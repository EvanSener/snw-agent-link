package ipc

import (
	"context"
	"encoding/json"
	"errors"
)

const ProtocolVersion = "1.0"

var (
	ErrInvalidRequest = errors.New("invalid IPC request")
	ErrMethodNotFound = errors.New("IPC method not found")
)

type Request struct {
	Version   string          `json:"version"`
	RequestID string          `json:"requestId"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Version   string          `json:"version"`
	RequestID string          `json:"requestId"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *ResponseError  `json:"error,omitempty"`
}

type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Handler interface {
	HandleIPC(context.Context, Request) (any, error)
}

type HandlerFunc func(context.Context, Request) (any, error)

func (function HandlerFunc) HandleIPC(ctx context.Context, request Request) (any, error) {
	return function(ctx, request)
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, ErrMethodNotFound):
		return "method_not_found"
	default:
		return "internal_error"
	}
}
