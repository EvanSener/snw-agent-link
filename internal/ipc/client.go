package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type Client struct {
	endpoint string
}

func NewClient(endpoint string) *Client {
	return &Client{endpoint: endpoint}
}

func (client *Client) Call(ctx context.Context, method string, params any, result any) error {
	if method == "" {
		return fmt.Errorf("%w: method is required", ErrInvalidRequest)
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal IPC params: %w", err)
	}
	connection, err := dial(ctx, client.endpoint)
	if err != nil {
		return err
	}
	defer connection.Close()

	requestID := uuid.NewString()
	request := Request{Version: ProtocolVersion, RequestID: requestID, Method: method, Params: payload}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return fmt.Errorf("send IPC request: %w", err)
	}
	var response Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		return fmt.Errorf("read IPC response: %w", err)
	}
	if response.Version != ProtocolVersion || response.RequestID != requestID {
		return fmt.Errorf("%w: response correlation mismatch", ErrInvalidRequest)
	}
	if response.Error != nil {
		return &RemoteError{Code: response.Error.Code, Message: response.Error.Message}
	}
	if result == nil || len(response.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(response.Result, result); err != nil {
		return fmt.Errorf("decode IPC result: %w", err)
	}
	return nil
}

type RemoteError struct {
	Code    string
	Message string
}

func (err *RemoteError) Error() string {
	return err.Code + ": " + err.Message
}

func IsRemoteError(err error, code string) bool {
	var remote *RemoteError
	return errors.As(err, &remote) && remote.Code == code
}
