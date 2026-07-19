//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

func listen(endpoint string) (net.Listener, error) {
	if !strings.HasPrefix(endpoint, `\\.\pipe\`) {
		return nil, fmt.Errorf("Windows IPC endpoint must be a named pipe")
	}
	listener, err := winio.ListenPipe(endpoint, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
		MessageMode:        true,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("listen on IPC named pipe: %w", err)
	}
	return listener, nil
}

func dial(ctx context.Context, endpoint string) (net.Conn, error) {
	connection, err := winio.DialPipeContext(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("connect to IPC named pipe: %w", err)
	}
	return connection, nil
}
