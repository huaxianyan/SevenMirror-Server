package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huaxianyan/SyncNotifications-Server/protocol/envelopeframe"
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
// transport-auth layer to the ciphertext hub. It must not be exposed before
// registration/authentication is implemented.
func ServeAuthenticatedConnection(
	ctx context.Context,
	connection *websocket.Conn,
	authenticatedPeer PeerIdentity,
	hub *Hub,
) error {
	sessionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	connection.SetReadLimit(int64(envelopeframe.MaxFrameSize))
	if err := connection.SetReadDeadline(time.Now().Add(pongTimeout)); err != nil {
		return err
	}
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(pongTimeout))
	})
	deliveries, unregister, err := hub.Register(authenticatedPeer, 16)
	if err != nil {
		return err
	}
	defer unregister()
	if err := connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	// This synchronous write occurs after Hub registration and before the sole
	// writer goroutine starts, so SNO1 is always the first server data message.
	if err := connection.WriteMessage(websocket.BinaryMessage, authenticationSuccessAck[:]); err != nil {
		return err
	}

	writerErrors := make(chan error, 1)
	heartbeats := make(chan struct{}, 1)
	reportWriterError := func(err error) {
		writerErrors <- err
		_ = connection.Close() // unblock NextReader before the writer exits
	}
	go func() {
		pingTicker := time.NewTicker(pingInterval)
		defer pingTicker.Stop()
		for {
			select {
			case <-sessionContext.Done():
				reportWriterError(sessionContext.Err())
				return
			case <-pingTicker.C:
				if err := connection.WriteControl(
					websocket.PingMessage,
					nil,
					time.Now().Add(writeTimeout),
				); err != nil {
					reportWriterError(err)
					return
				}
			case <-heartbeats:
				if err := connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
					reportWriterError(err)
					return
				}
				if err := connection.WriteMessage(websocket.BinaryMessage, heartbeatResponse[:]); err != nil {
					reportWriterError(err)
					return
				}
			case frame := <-deliveries:
				if err := connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
					reportWriterError(err)
					return
				}
				if err := connection.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					reportWriterError(err)
					return
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
		frame, isHeartbeat, err := readBoundedEnvelopeOrHeartbeat(connection)
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
		if err := hub.Route(authenticatedPeer, frame); err != nil {
			return err
		}
	}
}

func readBoundedEnvelopeOrHeartbeat(connection *websocket.Conn) ([]byte, bool, error) {
	messageType, reader, err := connection.NextReader()
	if err != nil {
		return nil, false, err
	}
	if messageType != websocket.BinaryMessage {
		return nil, false, errors.New("relay accepts binary messages only")
	}
	limited := io.LimitReader(reader, int64(envelopeframe.MaxFrameSize)+1)
	frame, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, fmt.Errorf("read encrypted envelope: %w", err)
	}
	if len(frame) == len(heartbeatRequest) && string(frame) == string(heartbeatRequest[:]) {
		return nil, true, nil
	}
	if len(frame) > envelopeframe.MaxFrameSize {
		return nil, false, errors.New("encrypted envelope exceeds maximum frame size")
	}
	if _, err := envelopeframe.Decode(frame); err != nil {
		return nil, false, err
	}
	return frame, false, nil
}
