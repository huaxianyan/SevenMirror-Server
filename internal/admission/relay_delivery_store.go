package admission

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/relay"
)

const (
	maxQueuedDeliveriesPerRecipient    = 4_096
	maxQueuedDeliveryBytesPerRecipient = 64 * 1024 * 1024
)

func (s *Store) IsRecipientAuthorized(
	ctx context.Context,
	peer relay.PeerIdentity,
) (bool, error) {
	return s.IsDeviceAuthorized(ctx, admissionWorkspaceID(peer), admissionDeviceID(peer))
}

func (s *Store) AppendDelivery(
	ctx context.Context,
	recipient relay.PeerIdentity,
	envelope []byte,
	expiresAt time.Time,
	now time.Time,
) (uint64, error) {
	if len(envelope) == 0 || expiresAt.IsZero() || now.IsZero() || !expiresAt.After(now) {
		return 0, errors.New("delivery envelope and valid expiry are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin relay delivery append: %w", err)
	}
	defer tx.Rollback()
	if err := ensureDeliveryState(ctx, tx, recipient); err != nil {
		return 0, err
	}
	if err := compactExpiredDeliveries(ctx, tx, recipient, now.UnixMilli()); err != nil {
		return 0, err
	}
	var nextID int64
	if err := tx.QueryRowContext(ctx, `SELECT next_delivery_id FROM relay_delivery_state
		WHERE workspace_id = ? AND recipient_device_id = ?`,
		recipient.WorkspaceID[:], recipient.DeviceID[:]).Scan(&nextID); err != nil ||
		nextID < 1 || nextID == math.MaxInt64 {
		return 0, errors.New("relay delivery sequence is unavailable")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO relay_deliveries
		(workspace_id, recipient_device_id, delivery_id, envelope, expires_at_ms, created_at_ms)
		VALUES (?, ?, ?, ?, ?, ?)`, recipient.WorkspaceID[:], recipient.DeviceID[:], nextID,
		envelope, expiresAt.UnixMilli(), now.UnixMilli()); err != nil {
		return 0, fmt.Errorf("store relay delivery: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE relay_delivery_state SET next_delivery_id = ?
		WHERE workspace_id = ? AND recipient_device_id = ?`, nextID+1,
		recipient.WorkspaceID[:], recipient.DeviceID[:]); err != nil {
		return 0, fmt.Errorf("advance relay delivery sequence: %w", err)
	}
	if err := enforceDeliveryCapacity(ctx, tx, recipient); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit relay delivery: %w", err)
	}
	return uint64(nextID), nil
}

func (s *Store) ResumeDeliveries(
	ctx context.Context,
	recipient relay.PeerIdentity,
	cursor uint64,
	now time.Time,
	limit int,
) (relay.DeliveryBatch, error) {
	if cursor > math.MaxInt64 || now.IsZero() || limit < 1 || limit > 256 {
		return relay.DeliveryBatch{}, errors.New("invalid relay delivery resume")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("begin relay delivery resume: %w", err)
	}
	defer tx.Rollback()
	if err := ensureDeliveryState(ctx, tx, recipient); err != nil {
		return relay.DeliveryBatch{}, err
	}
	if err := compactExpiredDeliveries(ctx, tx, recipient, now.UnixMilli()); err != nil {
		return relay.DeliveryBatch{}, err
	}
	var nextID, acknowledged, unavailable int64
	if err := tx.QueryRowContext(ctx, `SELECT next_delivery_id, acknowledged_delivery_id,
		unavailable_through_id FROM relay_delivery_state
		WHERE workspace_id = ? AND recipient_device_id = ?`,
		recipient.WorkspaceID[:], recipient.DeviceID[:]).Scan(
		&nextID, &acknowledged, &unavailable); err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("read relay delivery state: %w", err)
	}
	highWater := nextID - 1
	if int64(cursor) > highWater {
		return relay.DeliveryBatch{}, relay.ErrDeliveryCursorAhead
	}
	floor := acknowledged
	if unavailable > floor {
		floor = unavailable
	}
	if int64(cursor) < floor {
		if err := tx.Commit(); err != nil {
			return relay.DeliveryBatch{}, fmt.Errorf("commit relay delivery compaction: %w", err)
		}
		return relay.DeliveryBatch{HighWater: uint64(highWater), ResetRequired: true}, nil
	}
	if int64(cursor) > acknowledged {
		if err := acknowledgeThrough(ctx, tx, recipient, int64(cursor)); err != nil {
			return relay.DeliveryBatch{}, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT delivery_id, envelope FROM relay_deliveries
		WHERE workspace_id = ? AND recipient_device_id = ? AND delivery_id > ?
		ORDER BY delivery_id LIMIT ?`, recipient.WorkspaceID[:], recipient.DeviceID[:],
		int64(cursor), limit)
	if err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("read relay deliveries: %w", err)
	}
	batch := relay.DeliveryBatch{HighWater: uint64(highWater)}
	for rows.Next() {
		var id int64
		var envelope []byte
		if err := rows.Scan(&id, &envelope); err != nil {
			rows.Close()
			return relay.DeliveryBatch{}, fmt.Errorf("scan relay delivery: %w", err)
		}
		batch.Deliveries = append(batch.Deliveries, relay.StoredDelivery{
			ID: uint64(id), Envelope: append([]byte(nil), envelope...),
		})
	}
	if err := rows.Close(); err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("close relay deliveries: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("commit relay delivery resume: %w", err)
	}
	return batch, nil
}

func (s *Store) ReadDeliveries(
	ctx context.Context,
	recipient relay.PeerIdentity,
	after uint64,
	now time.Time,
	limit int,
) (relay.DeliveryBatch, error) {
	if after > math.MaxInt64 || now.IsZero() || limit < 1 || limit > 256 {
		return relay.DeliveryBatch{}, errors.New("invalid relay delivery read")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("begin relay delivery read: %w", err)
	}
	defer tx.Rollback()
	if err := compactExpiredDeliveries(ctx, tx, recipient, now.UnixMilli()); err != nil {
		return relay.DeliveryBatch{}, err
	}
	var nextID, unavailable int64
	if err := tx.QueryRowContext(ctx, `SELECT next_delivery_id, unavailable_through_id
		FROM relay_delivery_state WHERE workspace_id = ? AND recipient_device_id = ?`,
		recipient.WorkspaceID[:], recipient.DeviceID[:]).Scan(&nextID, &unavailable); err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("read relay delivery high-water: %w", err)
	}
	batch := relay.DeliveryBatch{HighWater: uint64(nextID - 1)}
	if int64(after) < unavailable {
		batch.ResetRequired = true
		if err := tx.Commit(); err != nil {
			return relay.DeliveryBatch{}, fmt.Errorf("commit relay delivery compaction: %w", err)
		}
		return batch, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT delivery_id, envelope FROM relay_deliveries
		WHERE workspace_id = ? AND recipient_device_id = ? AND delivery_id > ?
		ORDER BY delivery_id LIMIT ?`, recipient.WorkspaceID[:], recipient.DeviceID[:],
		int64(after), limit)
	if err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("read relay deliveries: %w", err)
	}
	for rows.Next() {
		var id int64
		var envelope []byte
		if err := rows.Scan(&id, &envelope); err != nil {
			rows.Close()
			return relay.DeliveryBatch{}, fmt.Errorf("scan relay delivery: %w", err)
		}
		batch.Deliveries = append(batch.Deliveries, relay.StoredDelivery{
			ID: uint64(id), Envelope: append([]byte(nil), envelope...),
		})
	}
	if err := rows.Close(); err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("close relay deliveries: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return relay.DeliveryBatch{}, fmt.Errorf("commit relay delivery read: %w", err)
	}
	return batch, nil
}

func (s *Store) AcknowledgeDelivery(
	ctx context.Context,
	recipient relay.PeerIdentity,
	cursor uint64,
) error {
	if cursor == 0 || cursor > math.MaxInt64 {
		return errors.New("delivery acknowledgement must be in 1..2^63-1")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin relay delivery acknowledgement: %w", err)
	}
	defer tx.Rollback()
	if err := ensureDeliveryState(ctx, tx, recipient); err != nil {
		return err
	}
	var nextID, acknowledged int64
	if err := tx.QueryRowContext(ctx, `SELECT next_delivery_id, acknowledged_delivery_id
		FROM relay_delivery_state WHERE workspace_id = ? AND recipient_device_id = ?`,
		recipient.WorkspaceID[:], recipient.DeviceID[:]).Scan(&nextID, &acknowledged); err != nil {
		return fmt.Errorf("read relay delivery acknowledgement state: %w", err)
	}
	if int64(cursor) >= nextID {
		return relay.ErrDeliveryCursorAhead
	}
	if int64(cursor) > acknowledged {
		if err := acknowledgeThrough(ctx, tx, recipient, int64(cursor)); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit relay delivery acknowledgement: %w", err)
	}
	return nil
}

func ensureDeliveryState(ctx context.Context, tx *sql.Tx, recipient relay.PeerIdentity) error {
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO relay_delivery_state
		(workspace_id, recipient_device_id, next_delivery_id, acknowledged_delivery_id,
		 unavailable_through_id) VALUES (?, ?, 1, 0, 0)`,
		recipient.WorkspaceID[:], recipient.DeviceID[:])
	if err != nil {
		return fmt.Errorf("initialize relay delivery state: %w", err)
	}
	if rows, err := result.RowsAffected(); err != nil || rows > 1 {
		return errors.New("initialize relay delivery state failed")
	}
	return nil
}

func compactExpiredDeliveries(
	ctx context.Context,
	tx *sql.Tx,
	recipient relay.PeerIdentity,
	nowUnixMs int64,
) error {
	var expiredThrough sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(delivery_id) FROM relay_deliveries
		WHERE workspace_id = ? AND recipient_device_id = ? AND expires_at_ms <= ?`,
		recipient.WorkspaceID[:], recipient.DeviceID[:], nowUnixMs).Scan(&expiredThrough); err != nil {
		return fmt.Errorf("find expired relay deliveries: %w", err)
	}
	if !expiredThrough.Valid {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM relay_deliveries WHERE workspace_id = ?
		AND recipient_device_id = ? AND expires_at_ms <= ?`, recipient.WorkspaceID[:],
		recipient.DeviceID[:], nowUnixMs); err != nil {
		return fmt.Errorf("delete expired relay deliveries: %w", err)
	}
	return markUnavailableThrough(ctx, tx, recipient, expiredThrough.Int64)
}

func enforceDeliveryCapacity(
	ctx context.Context,
	tx *sql.Tx,
	recipient relay.PeerIdentity,
) error {
	for {
		var count, bytes int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(length(envelope)), 0)
			FROM relay_deliveries WHERE workspace_id = ? AND recipient_device_id = ?`,
			recipient.WorkspaceID[:], recipient.DeviceID[:]).Scan(&count, &bytes); err != nil {
			return fmt.Errorf("measure relay delivery capacity: %w", err)
		}
		if count <= maxQueuedDeliveriesPerRecipient &&
			bytes <= maxQueuedDeliveryBytesPerRecipient {
			return nil
		}
		var oldest int64
		if err := tx.QueryRowContext(ctx, `SELECT delivery_id FROM relay_deliveries
			WHERE workspace_id = ? AND recipient_device_id = ? ORDER BY delivery_id LIMIT 1`,
			recipient.WorkspaceID[:], recipient.DeviceID[:]).Scan(&oldest); err != nil {
			return fmt.Errorf("select relay delivery for eviction: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM relay_deliveries WHERE workspace_id = ?
			AND recipient_device_id = ? AND delivery_id = ?`, recipient.WorkspaceID[:],
			recipient.DeviceID[:], oldest); err != nil {
			return fmt.Errorf("evict relay delivery: %w", err)
		}
		if err := markUnavailableThrough(ctx, tx, recipient, oldest); err != nil {
			return err
		}
	}
}

func markUnavailableThrough(
	ctx context.Context,
	tx *sql.Tx,
	recipient relay.PeerIdentity,
	cursor int64,
) error {
	_, err := tx.ExecContext(ctx, `UPDATE relay_delivery_state
		SET unavailable_through_id = MAX(unavailable_through_id, ?)
		WHERE workspace_id = ? AND recipient_device_id = ?`, cursor,
		recipient.WorkspaceID[:], recipient.DeviceID[:])
	if err != nil {
		return fmt.Errorf("record unavailable relay delivery history: %w", err)
	}
	return nil
}

func acknowledgeThrough(
	ctx context.Context,
	tx *sql.Tx,
	recipient relay.PeerIdentity,
	cursor int64,
) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM relay_deliveries WHERE workspace_id = ?
		AND recipient_device_id = ? AND delivery_id <= ?`, recipient.WorkspaceID[:],
		recipient.DeviceID[:], cursor); err != nil {
		return fmt.Errorf("delete acknowledged relay deliveries: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE relay_delivery_state
		SET acknowledged_delivery_id = MAX(acknowledged_delivery_id, ?)
		WHERE workspace_id = ? AND recipient_device_id = ?`, cursor,
		recipient.WorkspaceID[:], recipient.DeviceID[:]); err != nil {
		return fmt.Errorf("advance relay delivery acknowledgement: %w", err)
	}
	return nil
}

func admissionWorkspaceID(peer relay.PeerIdentity) WorkspaceID {
	var result WorkspaceID
	copy(result[:], peer.WorkspaceID[:])
	return result
}

func admissionDeviceID(peer relay.PeerIdentity) DeviceID {
	var result DeviceID
	copy(result[:], peer.DeviceID[:])
	return result
}
