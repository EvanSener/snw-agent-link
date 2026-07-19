//go:build !windows

package ipc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientServerRoundTrip(t *testing.T) {
	endpoint := filepath.Join(shortTempDir(t), "runtime", "link.sock")
	server := NewServer(HandlerFunc(func(_ context.Context, request Request) (any, error) {
		if request.Method != "echo" {
			return nil, ErrMethodNotFound
		}
		return map[string]string{"value": "ok"}, nil
	}), 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, endpoint) }()
	waitForSocket(t, endpoint, serveDone)

	var result map[string]string
	if err := NewClient(endpoint).Call(context.Background(), "echo", map[string]string{"value": "x"}, &result); err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if result["value"] != "ok" {
		t.Fatalf("result = %#v", result)
	}

	info, err := os.Stat(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o", info.Mode().Perm())
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestRemoteError(t *testing.T) {
	endpoint := filepath.Join(shortTempDir(t), "link.sock")
	server := NewServer(HandlerFunc(func(context.Context, Request) (any, error) {
		return nil, ErrMethodNotFound
	}), 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, endpoint) }()
	waitForSocket(t, endpoint, serveDone)

	err := NewClient(endpoint).Call(context.Background(), "missing", nil, nil)
	if !IsRemoteError(err, "method_not_found") {
		t.Fatalf("Call() error = %v", err)
	}
}

func TestRejectsNonSocketEndpoint(t *testing.T) {
	endpoint := filepath.Join(shortTempDir(t), "link.sock")
	if err := os.WriteFile(endpoint, []byte("do not delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := listen(endpoint)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("listen() error = %v", err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "snw-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("RemoveAll(%q) error = %v", dir, err)
		}
	})
	return dir
}

func waitForSocket(t *testing.T, endpoint string, serveDone <-chan error) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-serveDone:
			t.Fatalf("Serve() exited before socket creation: %v", err)
		default:
		}
		if info, err := os.Stat(endpoint); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("IPC socket was not created")
}
