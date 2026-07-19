//go:build windows

package tailscale

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func TestLocalAPIClientWhoIsOverWindowsNamedPipe(t *testing.T) {
	pipePath := fmt.Sprintf(`\\.\pipe\snw-agent-link-localapi-%d-%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(pipePath, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;WD)",
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/localapi/v0/whois" || request.URL.Query().Get("addr") != "100.64.0.9" {
			t.Fatalf("unexpected Local API request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		_, _ = response.Write([]byte(`{"Node":{"ID":42,"StableID":"node-stable"}}`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	identity, err := NewLocalAPISocketClient(pipePath).WhoIs(context.Background(), "100.64.0.9")
	if err != nil {
		t.Fatalf("whois over Windows named pipe: %v", err)
	}
	if identity.NodeID != "42" || identity.StableNodeID != "node-stable" {
		t.Fatalf("unexpected node identity: %+v", identity)
	}
}
