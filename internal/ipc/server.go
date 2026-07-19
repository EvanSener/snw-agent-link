package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

type Server struct {
	handler Handler
	limit   int64

	mu       sync.Mutex
	listener net.Listener
}

func NewServer(handler Handler, maxRequestBytes int64) *Server {
	if maxRequestBytes <= 0 {
		maxRequestBytes = 1 << 20
	}
	return &Server{handler: handler, limit: maxRequestBytes}
}

func (server *Server) Serve(ctx context.Context, endpoint string) error {
	if server.handler == nil {
		return errors.New("IPC handler is required")
	}
	listener, err := listen(endpoint)
	if err != nil {
		return err
	}
	server.mu.Lock()
	server.listener = listener
	server.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()

	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept IPC connection: %w", acceptErr)
		}
		go server.serveConnection(ctx, connection)
	}
}

func (server *Server) Close() error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener == nil {
		return nil
	}
	err := server.listener.Close()
	server.listener = nil
	return err
}

func (server *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	decoder := json.NewDecoder(io.LimitReader(connection, server.limit))
	encoder := json.NewEncoder(connection)

	var request Request
	if err := decoder.Decode(&request); err != nil {
		_ = encoder.Encode(errorResponse(request.RequestID, ErrInvalidRequest))
		return
	}
	if request.Version != ProtocolVersion || request.RequestID == "" || request.Method == "" {
		_ = encoder.Encode(errorResponse(request.RequestID, ErrInvalidRequest))
		return
	}

	result, err := server.handler.HandleIPC(ctx, request)
	if err != nil {
		_ = encoder.Encode(errorResponse(request.RequestID, err))
		return
	}
	payload, err := json.Marshal(result)
	if err != nil {
		_ = encoder.Encode(errorResponse(request.RequestID, err))
		return
	}
	_ = encoder.Encode(Response{Version: ProtocolVersion, RequestID: request.RequestID, Result: payload})
}

func errorResponse(requestID string, err error) Response {
	return Response{
		Version:   ProtocolVersion,
		RequestID: requestID,
		Error: &ResponseError{
			Code:    errorCode(err),
			Message: err.Error(),
		},
	}
}
