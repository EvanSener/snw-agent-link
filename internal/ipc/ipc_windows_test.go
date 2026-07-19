//go:build windows

package ipc

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestClientServerRoundTripOverWindowsNamedPipe(t *testing.T) {
	endpoint := fmt.Sprintf(`\\.\pipe\snw-agent-link-ipc-%d-%d`, os.Getpid(), time.Now().UnixNano())
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

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	var result map[string]string
	for {
		err := NewClient(endpoint).Call(callCtx, "echo", map[string]string{"value": "x"}, &result)
		if err == nil {
			break
		}
		select {
		case serveErr := <-serveDone:
			t.Fatalf("Serve() exited before client connected: %v", serveErr)
		case <-callCtx.Done():
			t.Fatalf("Call() did not connect to named pipe: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if result["value"] != "ok" {
		t.Fatalf("result = %#v", result)
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
