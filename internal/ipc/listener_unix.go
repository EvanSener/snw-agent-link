//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func listen(endpoint string) (net.Listener, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("IPC endpoint is required")
	}
	if err := os.MkdirAll(filepath.Dir(endpoint), 0o700); err != nil {
		return nil, fmt.Errorf("create IPC directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(endpoint), 0o700); err != nil {
		return nil, fmt.Errorf("secure IPC directory: %w", err)
	}
	if err := removeStaleSocket(endpoint); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		return nil, fmt.Errorf("listen on IPC socket: %w", err)
	}
	if err := os.Chmod(endpoint, 0o600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("secure IPC socket: %w", err)
	}
	return &cleanupListener{Listener: listener, endpoint: endpoint}, nil
}

func dial(ctx context.Context, endpoint string) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", endpoint)
	if err != nil {
		return nil, fmt.Errorf("connect to IPC socket: %w", err)
	}
	return connection, nil
}

func removeStaleSocket(endpoint string) error {
	info, err := os.Lstat(endpoint)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect IPC socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("IPC endpoint exists and is not a socket")
	}
	if err := os.Remove(endpoint); err != nil {
		return fmt.Errorf("remove stale IPC socket: %w", err)
	}
	return nil
}

type cleanupListener struct {
	net.Listener
	endpoint string
}

func (listener *cleanupListener) Close() error {
	err := listener.Listener.Close()
	removeErr := os.Remove(listener.endpoint)
	if removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
		return removeErr
	}
	return err
}
