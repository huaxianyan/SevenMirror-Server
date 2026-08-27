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

var (
	ErrAlreadyConnected   = errors.New("device already connected")
	ErrRecipientOffline   = errors.New("recipient is offline")
	ErrRecipientBusy      = errors.New("recipient delivery queue is full")
	ErrSenderMismatch     = errors.New("authenticated sender does not match routing header")
	ErrSenderOffline      = errors.New("authenticated sender is no longer connected")
	ErrDeviceDisconnected = errors.New("device authorization was revoked")
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
	credentialVersion int64
	immediate         chan []byte
	durableWake       chan struct{}
	disconnected      chan struct{}
}

type ConnectedSession struct {
	Peer              PeerIdentity
	CredentialVersion int64
}

type Hub struct {
	mu         sync.RWMutex
	devices    map[PeerIdentity]*deviceSession
	deliveries DeliveryStore
	authorizer RecipientAuthorizer
}

func NewHub(deliveries DeliveryStore, authorizer RecipientAuthorizer) (*Hub, error) {
	if deliveries == nil || authorizer == nil {
		return nil, errors.New("delivery store and recipient authorizer are required")
	}
	return &Hub{
		devices:    make(map[PeerIdentity]*deviceSession),
		deliveries: deliveries,
		authorizer: authorizer,
	}, nil
}

// Register reserves bounded live signals for an already authenticated device.
func (h *Hub) Register(
	identity PeerIdentity,
	credentialVersion int64,
	queueSize int,
) (<-chan []byte, <-chan struct{}, <-chan struct{}, func(), error) {
	if credentialVersion < 1 {
		return nil, nil, nil, nil, errors.New("credential version must be positive")
	}
	if queueSize < 1 {
		return nil, nil, nil, nil, errors.New("queue size must be positive")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.devices[identity]; exists {
		return nil, nil, nil, nil, ErrAlreadyConnected
	}
	session := &deviceSession{
		credentialVersion: credentialVersion,
		immediate:         make(chan []byte, queueSize),
		durableWake:       make(chan struct{}, 1),
		disconnected:      make(chan struct{}),
	}
	h.devices[identity] = session
	var once sync.Once
	unregister := func() {
		once.Do(func() {
			h.mu.Lock()
			if h.devices[identity] == session {
				delete(h.devices, identity)
			}
			h.mu.Unlock()
		})
	}
	return session.immediate, session.durableWake, session.disconnected, unregister, nil
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
		})
	}
	return sessions
}

// Disconnect atomically removes an active device from routing and signals its
// transport session. It is idempotent for offline or already-disconnected peers.
func (h *Hub) Disconnect(identity PeerIdentity) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	session, exists := h.devices[identity]
	if !exists {
		return false
	}
	delete(h.devices, identity)
	close(session.disconnected)
	return true
}

// RouteOnline delivers an unchanged ciphertext only to a currently connected recipient.
func (h *Hub) RouteOnline(authenticatedSender PeerIdentity, encodedFrame []byte) error {
	recipient, _, err := validateRoutedEnvelope(authenticatedSender, encodedFrame)
	if err != nil {
		return err
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if _, senderConnected := h.devices[authenticatedSender]; !senderConnected {
		return ErrSenderOffline
	}
	session, exists := h.devices[recipient]
	if !exists {
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
	authenticatedSender PeerIdentity,
	encodedFrame []byte,
	now time.Time,
) error {
	recipient, header, err := validateRoutedEnvelope(authenticatedSender, encodedFrame)
	if err != nil {
		return err
	}
	h.mu.RLock()
	_, senderConnected := h.devices[authenticatedSender]
	h.mu.RUnlock()
	if !senderConnected {
		return ErrSenderOffline
	}
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
	if session != nil {
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
	recipient PeerIdentity,
	cursor uint64,
	now time.Time,
) (DeliveryBatch, error) {
	return h.deliveries.ResumeDeliveries(ctx, recipient, cursor, now, deliveryBatchSize)
}

func (h *Hub) ReadDeliveries(
	ctx context.Context,
	recipient PeerIdentity,
	after uint64,
	now time.Time,
) (DeliveryBatch, error) {
	return h.deliveries.ReadDeliveries(ctx, recipient, after, now, deliveryBatchSize)
}

func (h *Hub) AcknowledgeDelivery(
	ctx context.Context,
	recipient PeerIdentity,
	cursor uint64,
) error {
	return h.deliveries.AcknowledgeDelivery(ctx, recipient, cursor)
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
