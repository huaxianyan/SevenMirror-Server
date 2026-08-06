package relay

import (
	"bytes"
	"errors"
	"sync"

	"github.com/huaxianyan/SyncNotifications-Server/protocol/envelopeframe"
)

var (
	ErrAlreadyConnected = errors.New("device already connected")
	ErrRecipientOffline = errors.New("recipient is offline")
	ErrRecipientBusy    = errors.New("recipient delivery queue is full")
	ErrSenderMismatch   = errors.New("authenticated sender does not match routing header")
)

type WorkspaceID [16]byte
type DeviceID [16]byte

type PeerIdentity struct {
	WorkspaceID WorkspaceID
	DeviceID    DeviceID
}

// Hub is an in-memory ciphertext router. It never receives decryption keys and
// validates only the fixed clear framing required to route one recipient copy.
type Hub struct {
	mu      sync.RWMutex
	devices map[PeerIdentity]chan []byte
}

func NewHub() *Hub {
	return &Hub{devices: make(map[PeerIdentity]chan []byte)}
}

// Register reserves one bounded queue for an already authenticated device.
func (h *Hub) Register(identity PeerIdentity, queueSize int) (<-chan []byte, func(), error) {
	if queueSize < 1 {
		return nil, nil, errors.New("queue size must be positive")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.devices[identity]; exists {
		return nil, nil, ErrAlreadyConnected
	}
	queue := make(chan []byte, queueSize)
	h.devices[identity] = queue
	var once sync.Once
	unregister := func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.devices, identity)
			h.mu.Unlock()
		})
	}
	return queue, unregister, nil
}

func (h *Hub) IsConnected(identity PeerIdentity) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, exists := h.devices[identity]
	return exists
}

// Route validates an envelope and delivers an unchanged ciphertext copy. The
// authenticated sender identity comes from the future transport-auth layer,
// never from an untrusted query parameter or payload field.
func (h *Hub) Route(authenticatedSender PeerIdentity, encodedFrame []byte) error {
	frame, err := envelopeframe.Decode(encodedFrame)
	if err != nil {
		return err
	}
	if !bytes.Equal(frame.RoutingHeader[8:24], authenticatedSender.WorkspaceID[:]) ||
		!bytes.Equal(frame.RoutingHeader[24:40], authenticatedSender.DeviceID[:]) {
		return ErrSenderMismatch
	}
	var recipient PeerIdentity
	copy(recipient.WorkspaceID[:], frame.RoutingHeader[8:24])
	copy(recipient.DeviceID[:], frame.RoutingHeader[40:56])

	h.mu.RLock()
	queue, exists := h.devices[recipient]
	if !exists {
		h.mu.RUnlock()
		return ErrRecipientOffline
	}
	copyForRecipient := append([]byte(nil), encodedFrame...)
	select {
	case queue <- copyForRecipient:
		h.mu.RUnlock()
		return nil
	default:
		h.mu.RUnlock()
		return ErrRecipientBusy
	}
}
