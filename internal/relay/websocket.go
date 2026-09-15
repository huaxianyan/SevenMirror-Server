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
	activityRecorders ...ConnectionActivityRecorder,
) (result error) {
	if len(activityRecorders) > 1 {
		return errors.New("at most one connection activity recorder is allowed")
	}
	var activityRecorder ConnectionActivityRecorder
	if len(activityRecorders) == 1 {
		activityRecorder = activityRecorders[0]
	}
	sessionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	connection.SetReadLimit(int64(relaydelivery.MaxClientMessageSize))
	if err := connection.SetReadDeadline(time.Now().Add(pongTimeout)); err != nil {
		return err
	}
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(pongTimeout))
	})
	session, unregister, err := hub.Register(
		authenticatedPeer, credentialVersion, 16)
	if err != nil {
		return err
	}
	// Deferred calls run last-in-first-out, so this runs before unregister closes
	// this instance's own revocation signal. That ordering is what lets a
	// retirement be reported instead of the socket or context error retiring the
	// instance produced, while an ordinary client disconnect keeps its own error.
	defer unregister()
	defer func() { result = sessionEndCause(session, result) }()
	writeMessage := func(kind int, encoded []byte) error {
		operationContext, finish, err := hub.beginOperation(sessionContext, session, writeTimeout)
		if err != nil {
			return err
		}
		stop := context.AfterFunc(operationContext, func() { _ = connection.Close() })
		defer func() { stop(); finish() }()
		deadline, _ := operationContext.Deadline()
		if kind == websocket.PingMessage {
			return connection.WriteControl(kind, encoded, deadline)
		}
		if err := connection.SetWriteDeadline(deadline); err != nil {
			return err
		}
		return connection.WriteMessage(kind, encoded)
	}
	// SNO1 remains the first server data message.
	if err := writeMessage(websocket.BinaryMessage, authenticationSuccessAck[:]); err != nil {
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
		cancel()
		_ = connection.Close()
	}
	go func() {
		pingTicker := time.NewTicker(pingInterval)
		defer pingTicker.Stop()
		cursorInitialized := false
		var sentCursor uint64

		drainBatch := func(batch DeliveryBatch) (bool, error) {
			for {
				if batch.ResetRequired {
					reset, err := relaydelivery.EncodeResetRequired(batch.HighWater)
					if err != nil {
						return false, err
					}
					return true, writeMessage(websocket.BinaryMessage, reset)
				}
				for _, delivery := range batch.Deliveries {
					encoded, err := relaydelivery.EncodeDelivery(delivery.ID, delivery.Envelope)
					if err != nil {
						return false, err
					}
					if err := writeMessage(websocket.BinaryMessage, encoded); err != nil {
						return false, err
					}
					sentCursor = delivery.ID
				}
				if sentCursor >= batch.HighWater {
					caughtUp, err := relaydelivery.EncodeCaughtUp(batch.HighWater)
					if err != nil {
						return false, err
					}
					return false, writeMessage(websocket.BinaryMessage, caughtUp)
				}
				next, err := hub.ReadDeliveries(
					sessionContext, session, sentCursor, time.Now())
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
			case <-session.session.disconnected:
				_ = connection.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "authorization revoked"),
					time.Now().Add(writeTimeout),
				)
				reportWriterError(ErrDeviceDisconnected)
				return
			case <-session.session.superseded:
				// An ordinary close, not a policy close: the client must read this
				// as "this connection was replaced", not as a membership change.
				// The deadline is deliberately short. The replacement is already
				// waiting on this instance to release its slot, and that wait is
				// bounded; a courtesy close frame must not spend the whole budget.
				_ = connection.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "superseded connection"),
					time.Now().Add(time.Second),
				)
				reportWriterError(ErrSessionSuperseded)
				return
			case <-pingTicker.C:
				if err := writeMessage(websocket.PingMessage, nil); err != nil {
					reportWriterError(err)
					return
				}
			case <-heartbeats:
				if err := writeMessage(websocket.BinaryMessage, heartbeatResponse[:]); err != nil {
					reportWriterError(err)
					return
				}
			case frame := <-session.session.immediate:
				if err := writeMessage(websocket.BinaryMessage, frame); err != nil {
					reportWriterError(err)
					return
				}
			case cursor := <-resumeRequests:
				batch, err := hub.ResumeDeliveries(
					sessionContext, session, cursor, time.Now())
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
			case <-session.session.durableWake:
				if !cursorInitialized {
					continue
				}
				batch, err := hub.ReadDeliveries(
					sessionContext, session, sentCursor, time.Now())
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
		if activityRecorder != nil {
			activityContext, finish, err := hub.beginOperation(sessionContext, session, sessionOperationTimeout)
			if err != nil {
				return err
			}
			_ = activityRecorder.RecordConnectionActivity(
				activityContext, authenticatedPeer, time.Now())
			finish()
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
			if err := hub.RouteOnline(sessionContext, session, message.Envelope); err != nil {
				return err
			}
		case relaydelivery.ClientEnvelopeDurable:
			if err := hub.RouteDurable(
				sessionContext, session, message.Envelope, time.Now()); err != nil {
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
				sessionContext, session, message.Cursor); err != nil {
				return err
			}
		default:
			return errors.New("unsupported relay delivery message")
		}
	}
}

// A retired instance reports the retirement itself rather than the socket error
// that retiring it produced, so operator logs keep the cause instead of the
// symptom. These signals are only observable before this connection's own
// cleanup runs, so an ordinary client disconnect still reports its own error and
// is not misreported as a revocation.
func sessionEndCause(session ConnectedSession, err error) error {
	if session.session == nil {
		return err
	}
	select {
	case <-session.session.superseded:
		return ErrSessionSuperseded
	default:
	}
	select {
	case <-session.session.disconnected:
		return ErrDeviceDisconnected
	default:
	}
	return err
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
