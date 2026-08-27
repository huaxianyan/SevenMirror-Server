package relay

import (
	"context"
	"errors"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/relaydelivery"
)

const (
	writeTimeout = 10 * time.Second
	pingInterval = 30 * time.Second
	pongTimeout  = 75 * time.Second
)

var (
	authenticationSuccessAck = [4]byte{'S', 'N', 'O', '1'}
	heartbeatRequest         = [4]byte{'S', 'N', 'H', '1'}
	heartbeatResponse        = [4]byte{'S', 'N', 'H', '2'}
)

// ServeAuthenticatedConnection connects an identity already established by the
// transport-auth layer to online and durable ciphertext delivery.
func ServeAuthenticatedConnection(
	ctx context.Context,
	connection *websocket.Conn,
	authenticatedPeer PeerIdentity,
	credentialVersion int64,
	hub *Hub,
) error {
	sessionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	connection.SetReadLimit(int64(relaydelivery.MaxClientMessageSize))
	if err := connection.SetReadDeadline(time.Now().Add(pongTimeout)); err != nil {
		return err
	}
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(pongTimeout))
	})
	immediate, durableWake, disconnected, unregister, err := hub.Register(
		authenticatedPeer, credentialVersion, 16)
	if err != nil {
		return err
	}
	defer unregister()
	if err := connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	// SNO1 remains the first server data message.
	if err := connection.WriteMessage(websocket.BinaryMessage, authenticationSuccessAck[:]); err != nil {
		return err
	}

	writerErrors := make(chan error, 1)
	heartbeats := make(chan struct{}, 1)
	resumeRequests := make(chan uint64, 1)
	reportWriterError := func(err error) {
		select {
		case writerErrors <- err:
		default:
		}
		_ = connection.Close()
	}
	go func() {
		pingTicker := time.NewTicker(pingInterval)
		defer pingTicker.Stop()
		cursorInitialized := false
		var sentCursor uint64

		writeBinary := func(encoded []byte) error {
			if err := connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return err
			}
			return connection.WriteMessage(websocket.BinaryMessage, encoded)
		}
		drainBatch := func(batch DeliveryBatch) (bool, error) {
			for {
				if batch.ResetRequired {
					reset, err := relaydelivery.EncodeResetRequired(batch.HighWater)
					if err != nil {
						return false, err
					}
					return true, writeBinary(reset)
				}
				for _, delivery := range batch.Deliveries {
					encoded, err := relaydelivery.EncodeDelivery(delivery.ID, delivery.Envelope)
					if err != nil {
						return false, err
					}
					if err := writeBinary(encoded); err != nil {
						return false, err
					}
					sentCursor = delivery.ID
				}
				if sentCursor >= batch.HighWater {
					caughtUp, err := relaydelivery.EncodeCaughtUp(batch.HighWater)
					if err != nil {
						return false, err
					}
					return false, writeBinary(caughtUp)
				}
				next, err := hub.ReadDeliveries(
					sessionContext, authenticatedPeer, sentCursor, time.Now())
				if err != nil {
					return false, err
				}
				if len(next.Deliveries) == 0 && next.HighWater > sentCursor &&
					!next.ResetRequired {
					return false, errors.New("relay delivery history contains an unreported gap")
				}
				batch = next
			}
		}

		for {
			select {
			case <-sessionContext.Done():
				reportWriterError(sessionContext.Err())
				return
			case <-disconnected:
				_ = connection.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "authorization revoked"),
					time.Now().Add(writeTimeout),
				)
				reportWriterError(ErrDeviceDisconnected)
				return
			case <-pingTicker.C:
				if err := connection.WriteControl(websocket.PingMessage, nil,
					time.Now().Add(writeTimeout)); err != nil {
					reportWriterError(err)
					return
				}
			case <-heartbeats:
				if err := writeBinary(heartbeatResponse[:]); err != nil {
					reportWriterError(err)
					return
				}
			case frame := <-immediate:
				if err := writeBinary(frame); err != nil {
					reportWriterError(err)
					return
				}
			case cursor := <-resumeRequests:
				batch, err := hub.ResumeDeliveries(
					sessionContext, authenticatedPeer, cursor, time.Now())
				if err != nil {
					reportWriterError(err)
					return
				}
				cursorInitialized = true
				sentCursor = cursor
				resetSent, err := drainBatch(batch)
				if err != nil {
					reportWriterError(err)
					return
				}
				if resetSent {
					cursorInitialized = false
				}
			case <-durableWake:
				if !cursorInitialized {
					continue
				}
				batch, err := hub.ReadDeliveries(
					sessionContext, authenticatedPeer, sentCursor, time.Now())
				if err != nil {
					reportWriterError(err)
					return
				}
				resetSent, err := drainBatch(batch)
				if err != nil {
					reportWriterError(err)
					return
				}
				if resetSent {
					cursorInitialized = false
				}
			}
		}
	}()

	for {
		select {
		case err := <-writerErrors:
			return err
		default:
		}
		message, isHeartbeat, err := readBoundedClientMessage(connection)
		if err != nil {
			return err
		}
		if isHeartbeat {
			select {
			case heartbeats <- struct{}{}:
			case <-sessionContext.Done():
				return sessionContext.Err()
			}
			continue
		}
		switch message.Kind {
		case relaydelivery.ClientEnvelopeOnline:
			if err := hub.RouteOnline(authenticatedPeer, message.Envelope); err != nil {
				return err
			}
		case relaydelivery.ClientEnvelopeDurable:
			if err := hub.RouteDurable(
				sessionContext, authenticatedPeer, message.Envelope, time.Now()); err != nil {
				return err
			}
		case relaydelivery.ClientResume:
			select {
			case resumeRequests <- message.Cursor:
			case <-sessionContext.Done():
				return sessionContext.Err()
			}
		case relaydelivery.ClientAcknowledge:
			if err := hub.AcknowledgeDelivery(
				sessionContext, authenticatedPeer, message.Cursor); err != nil {
				return err
			}
		default:
			return errors.New("unsupported relay delivery message")
		}
	}
}

func readBoundedClientMessage(
	connection *websocket.Conn,
) (relaydelivery.ClientMessage, bool, error) {
	messageType, encoded, err := connection.ReadMessage()
	if err != nil {
		return relaydelivery.ClientMessage{}, false, err
	}
	if messageType != websocket.BinaryMessage {
		return relaydelivery.ClientMessage{}, false, errors.New("relay accepts binary messages only")
	}
	if len(encoded) == len(heartbeatRequest) && string(encoded) == string(heartbeatRequest[:]) {
		return relaydelivery.ClientMessage{}, true, nil
	}
	message, err := relaydelivery.DecodeClientMessage(encoded)
	return message, false, err
}
