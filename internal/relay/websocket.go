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

	writerErrors := make(chan error, 1)
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
		frame, err := readBoundedEnvelope(connection)
		if err != nil {
			return err
		}
		if err := hub.Route(authenticatedPeer, frame); err != nil {
			return err
		}
	}
}

func readBoundedEnvelope(connection *websocket.Conn) ([]byte, error) {
	messageType, reader, err := connection.NextReader()
	if err != nil {
		return nil, err
	}
	if messageType != websocket.BinaryMessage {
		return nil, errors.New("relay accepts binary messages only")
	}
	limited := io.LimitReader(reader, int64(envelopeframe.MaxFrameSize)+1)
	frame, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read encrypted envelope: %w", err)
	}
	if len(frame) > envelopeframe.MaxFrameSize {
		return nil, errors.New("encrypted envelope exceeds maximum frame size")
	}
	if _, err := envelopeframe.Decode(frame); err != nil {
		return nil, err
	}
	return frame, nil
}
