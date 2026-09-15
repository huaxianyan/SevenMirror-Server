package relay

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/protocol/envelopeframe"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/routingheader"
)

// Bound storage and activity work independently of the existing socket write timeout.
const sessionOperationTimeout = 5 * time.Second

// A replacement waits for the retired instance to release its slot within this
// budget. The wait is bounded on purpose: a session that cannot drain must not
// deny a reconnecting device indefinitely, and it must not be reported as
// retired when its admitted work is still running.
const defaultSessionHandoverTimeout = 5 * time.Second

// A replacement can lose the slot race to a concurrent replacement once. Losing
// it twice means the caller retries rather than looping inside one admission.
const maxHandoverAttempts = 2

var (
	ErrAlreadyConnected   = errors.New("device already connected")
	ErrStaleCredential    = errors.New("connected session uses a newer credential version")
	ErrHandoverTimeout    = errors.New("connected session did not release its slot in time")
	ErrSessionSuperseded  = errors.New("connection instance was replaced by a newer connection")
	ErrRecipientOffline   = errors.New("recipient is offline")
	ErrRecipientBusy      = errors.New("recipient delivery queue is full")
	ErrSenderMismatch     = errors.New("authenticated sender does not match routing header")
	ErrSessionOffline     = errors.New("connection instance is no longer active")
	ErrDeviceDisconnected = errors.New("device authorization was revoked")
)

// A session retires exactly once. Authorization revocation and replacement must
// stay distinguishable: the first is a policy close that clients must act on as
// a membership change, the second is an ordinary close that clients treat as a
// superseded connection.
type sessionRetirement uint8

const (
	retirementRevoked sessionRetirement = iota + 1
	retirementSuperseded
)

type WorkspaceID [16]byte
type DeviceID [16]byte

type PeerIdentity struct {
	WorkspaceID WorkspaceID
	DeviceID    DeviceID
}

// Hub routes online-only ciphertext in memory and durable ciphertext through
// one recipient-specific DeliveryStore. It never receives decryption keys.
type deviceSession struct {
	operations sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc

	credentialVersion int64
	immediate         chan []byte
	durableWake       chan struct{}
	disconnected      chan struct{}
	// Closed instead of disconnected when a newer authenticated connection
	// replaces this instance. A replacement is not a membership change, so it
	// must not reach the client as an authorization-revoked close.
	superseded chan struct{}
	// Closed once this instance has removed its own slot entry. A waiting
	// replacement observes this instead of blocking on the operation lock, so
	// an admission never needs an unbounded wait.
	released    chan struct{}
	retireOnce  sync.Once
	releaseOnce sync.Once
}

func newDeviceSession(credentialVersion int64, queueSize int) *deviceSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &deviceSession{
		ctx:               ctx,
		cancel:            cancel,
		credentialVersion: credentialVersion,
		immediate:         make(chan []byte, queueSize),
		durableWake:       make(chan struct{}, 1),
		disconnected:      make(chan struct{}),
		superseded:        make(chan struct{}),
		released:          make(chan struct{}),
	}
}

// retire signals and cancels this instance exactly once. It returns whether this
// call initiated the retirement.
func (s *deviceSession) retire(reason sessionRetirement) bool {
	initiated := false
	s.retireOnce.Do(func() {
		initiated = true
		if reason == retirementSuperseded {
			close(s.superseded)
		} else {
			close(s.disconnected)
		}
		s.cancel()
	})
	return initiated
}

func (s *deviceSession) markReleased() {
	s.releaseOnce.Do(func() { close(s.released) })
}

type ConnectedSession struct {
	Peer              PeerIdentity
	CredentialVersion int64
	// Retaining this instance prevents an old observation from targeting a reconnect.
	session *deviceSession
}

type Hub struct {
	mu         sync.RWMutex
	devices    map[PeerIdentity]*deviceSession
	deliveries DeliveryStore
	authorizer RecipientAuthorizer
	// Overridable for tests; production uses defaultSessionHandoverTimeout.
	handoverTimeout time.Duration
}

func NewHub(deliveries DeliveryStore, authorizer RecipientAuthorizer) (*Hub, error) {
	if deliveries == nil || authorizer == nil {
		return nil, errors.New("delivery store and recipient authorizer are required")
	}
	return &Hub{
		devices:         make(map[PeerIdentity]*deviceSession),
		deliveries:      deliveries,
		authorizer:      authorizer,
		handoverTimeout: defaultSessionHandoverTimeout,
	}, nil
}

// Register reserves bounded live signals for an already authenticated device.
//
// An occupied slot is not rejected outright: the caller has already proven
// possession of the device credential, and a device that reconnects after a
// network change must not stay locked out until the relay happens to notice the
// stale socket. The replacement retires the older instance first and only takes
// the slot after that instance has released it.
//
// Two boundaries keep this safe:
//   - A smaller credential version can never displace a newer one, so a stale
//     authenticated attempt cannot roll a rotated credential backwards.
//   - The wait for the retired instance is bounded. If the old instance cannot
//     drain its admitted work in time the slot stays reserved and the caller
//     gets ErrHandoverTimeout instead of a slot that is not really free.
func (h *Hub) Register(
	identity PeerIdentity,
	credentialVersion int64,
	queueSize int,
) (ConnectedSession, func(), error) {
	if credentialVersion < 1 {
		return ConnectedSession{}, nil, errors.New("credential version must be positive")
	}
	if queueSize < 1 {
		return ConnectedSession{}, nil, errors.New("queue size must be positive")
	}
	for attempt := 0; attempt < maxHandoverAttempts; attempt++ {
		h.mu.Lock()
		existing, exists := h.devices[identity]
		if !exists {
			session := newDeviceSession(credentialVersion, queueSize)
			h.devices[identity] = session
			observed := ConnectedSession{
				Peer:              identity,
				CredentialVersion: credentialVersion,
				session:           session,
			}
			h.mu.Unlock()
			return observed, func() { h.Disconnect(observed) }, nil
		}
		if credentialVersion < existing.credentialVersion {
			h.mu.Unlock()
			return ConnectedSession{}, nil, ErrStaleCredential
		}
		existing.retire(retirementSuperseded)
		h.mu.Unlock()

		if !h.awaitRelease(existing) {
			return ConnectedSession{}, nil, ErrHandoverTimeout
		}
	}
	return ConnectedSession{}, nil, ErrAlreadyConnected
}

// awaitRelease waits outside the Hub lock for a retired instance to drop its own
// slot entry. Waiting on the release signal rather than the operation lock keeps
// the admission bounded even when a retired session is stuck inside storage.
func (h *Hub) awaitRelease(session *deviceSession) bool {
	timer := time.NewTimer(h.handoverTimeout)
	defer timer.Stop()
	select {
	case <-session.released:
		return true
	case <-timer.C:
		return false
	}
}

func (h *Hub) IsConnected(identity PeerIdentity) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, exists := h.devices[identity]
	return exists
}

func (h *Hub) ConnectedSessions() []ConnectedSession {
	h.mu.RLock()
	defer h.mu.RUnlock()
	sessions := make([]ConnectedSession, 0, len(h.devices))
	for peer, session := range h.devices {
		sessions = append(sessions, ConnectedSession{
			Peer:              peer,
			CredentialVersion: session.credentialVersion,
			session:           session,
		})
	}
	return sessions
}

// Disconnect cancels and drains only the observed instance before releasing its
// slot. It returns whether this call initiated retirement. Never wait for database
// work with the Hub lock held: other devices must remain independently usable.
//
// This path stays unbounded on purpose. A slot is only released after the
// instance's admitted work has actually returned, so a storage implementation
// that ignores cancellation keeps the slot reserved instead of pretending the
// session ended safely. Bounded waiting belongs to Register, not here.
func (h *Hub) Disconnect(observed ConnectedSession) bool {
	h.mu.Lock()
	session, exists := h.devices[observed.Peer]
	if !exists || session != observed.session {
		h.mu.Unlock()
		return false
	}
	initiated := session.retire(retirementRevoked)
	h.mu.Unlock()

	session.operations.Lock()
	defer session.operations.Unlock()
	h.mu.Lock()
	if h.devices[observed.Peer] == session {
		delete(h.devices, observed.Peer)
	}
	h.mu.Unlock()
	session.markReleased()
	return initiated
}

// The read lock spans the actual operation, not just the identity check. A new
// session cannot occupy this slot until all admitted old work has returned.
func (h *Hub) beginOperation(ctx context.Context, observed ConnectedSession, timeout time.Duration) (context.Context, func(), error) {
	if observed.session == nil || observed.session.ctx.Err() != nil {
		return nil, nil, ErrSessionOffline
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	session := observed.session
	session.operations.RLock()
	h.mu.RLock()
	active := h.devices[observed.Peer] == session && session.ctx.Err() == nil
	h.mu.RUnlock()
	if !active {
		session.operations.RUnlock()
		return nil, nil, ErrSessionOffline
	}
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	stop := context.AfterFunc(session.ctx, cancel)
	return operationContext, func() {
		stop()
		cancel()
		session.operations.RUnlock()
	}, nil
}

// RouteOnline delivers an unchanged ciphertext only to a currently connected recipient.
func (h *Hub) RouteOnline(ctx context.Context, authenticatedSender ConnectedSession, encodedFrame []byte) error {
	recipient, _, err := validateRoutedEnvelope(authenticatedSender.Peer, encodedFrame)
	if err != nil {
		return err
	}
	_, finish, err := h.beginOperation(ctx, authenticatedSender, sessionOperationTimeout)
	if err != nil {
		return err
	}
	defer finish()
	h.mu.RLock()
	defer h.mu.RUnlock()
	session, exists := h.devices[recipient]
	if !exists || session.ctx.Err() != nil {
		return ErrRecipientOffline
	}
	copyForRecipient := append([]byte(nil), encodedFrame...)
	select {
	case session.immediate <- copyForRecipient:
		return nil
	default:
		return ErrRecipientBusy
	}
}

// RouteDurable commits one exact ciphertext before waking a live recipient.
func (h *Hub) RouteDurable(
	ctx context.Context,
	authenticatedSender ConnectedSession,
	encodedFrame []byte,
	now time.Time,
) error {
	recipient, header, err := validateRoutedEnvelope(authenticatedSender.Peer, encodedFrame)
	if err != nil {
		return err
	}
	ctx, finish, err := h.beginOperation(ctx, authenticatedSender, sessionOperationTimeout)
	if err != nil {
		return err
	}
	defer finish()
	authorized, err := h.authorizer.IsRecipientAuthorized(ctx, recipient)
	if err != nil {
		return err
	}
	if !authorized {
		return ErrRecipientUnauthorized
	}
	expiresAt := time.UnixMilli(int64(header.ExpiresAtUnixMs))
	if !expiresAt.After(now) {
		return errors.New("durable encrypted envelope is already expired")
	}
	if _, err := h.deliveries.AppendDelivery(ctx, recipient, encodedFrame, expiresAt, now); err != nil {
		return err
	}
	h.mu.RLock()
	session := h.devices[recipient]
	if session != nil && session.ctx.Err() == nil {
		select {
		case session.durableWake <- struct{}{}:
		default:
		}
	}
	h.mu.RUnlock()
	return nil
}

func (h *Hub) ResumeDeliveries(
	ctx context.Context,
	recipient ConnectedSession,
	cursor uint64,
	now time.Time,
) (DeliveryBatch, error) {
	ctx, finish, err := h.beginOperation(ctx, recipient, sessionOperationTimeout)
	if err != nil {
		return DeliveryBatch{}, err
	}
	defer finish()
	return h.deliveries.ResumeDeliveries(ctx, recipient.Peer, cursor, now, deliveryBatchSize)
}

func (h *Hub) ReadDeliveries(
	ctx context.Context,
	recipient ConnectedSession,
	after uint64,
	now time.Time,
) (DeliveryBatch, error) {
	ctx, finish, err := h.beginOperation(ctx, recipient, sessionOperationTimeout)
	if err != nil {
		return DeliveryBatch{}, err
	}
	defer finish()
	return h.deliveries.ReadDeliveries(ctx, recipient.Peer, after, now, deliveryBatchSize)
}

func (h *Hub) AcknowledgeDelivery(
	ctx context.Context,
	recipient ConnectedSession,
	cursor uint64,
) error {
	ctx, finish, err := h.beginOperation(ctx, recipient, sessionOperationTimeout)
	if err != nil {
		return err
	}
	defer finish()
	return h.deliveries.AcknowledgeDelivery(ctx, recipient.Peer, cursor)
}

func validateRoutedEnvelope(
	authenticatedSender PeerIdentity,
	encodedFrame []byte,
) (PeerIdentity, routingheader.Header, error) {
	frame, err := envelopeframe.Decode(encodedFrame)
	if err != nil {
		return PeerIdentity{}, routingheader.Header{}, err
	}
	if !bytes.Equal(frame.RoutingHeader[8:24], authenticatedSender.WorkspaceID[:]) ||
		!bytes.Equal(frame.RoutingHeader[24:40], authenticatedSender.DeviceID[:]) {
		return PeerIdentity{}, routingheader.Header{}, ErrSenderMismatch
	}
	header, err := routingheader.Decode(frame.RoutingHeader[:])
	if err != nil {
		return PeerIdentity{}, routingheader.Header{}, err
	}
	var recipient PeerIdentity
	copy(recipient.WorkspaceID[:], header.WorkspaceID[:])
	copy(recipient.DeviceID[:], header.RecipientDeviceID[:])
	return recipient, header, nil
}
