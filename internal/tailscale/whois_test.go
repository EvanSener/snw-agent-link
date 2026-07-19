package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
)

func TestLocalAPIClientWhoIsParsesMinimumIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/localapi/v0/whois" {
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
		if request.URL.Query().Get("addr") != "100.64.0.9:7443" {
			t.Fatalf("unexpected addr query %s", request.URL.RawQuery)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{
			"Node":{"ID":42,"StableID":"node-stable","Name":"agent-host.tailnet.ts.net.","Addresses":["100.64.0.9/32"]},
			"UserProfile":{"ID":7,"LoginName":"agent@example.com"}
		}`))
	}))
	defer server.Close()

	client := NewLocalAPIClient(server.URL, server.Client())
	identity, err := client.WhoIs(context.Background(), "100.64.0.9:7443")
	if err != nil {
		t.Fatalf("whois: %v", err)
	}
	if identity.NodeID != "42" || identity.StableNodeID != "node-stable" || identity.NodeName != "agent-host.tailnet.ts.net." {
		t.Fatalf("unexpected node identity: %+v", identity)
	}
	if identity.UserID != "7" || identity.LoginName != "agent@example.com" {
		t.Fatalf("unexpected user identity: %+v", identity)
	}
}

func TestLocalAPISocketClientWhoIs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are unavailable on Windows")
	}
	socketPath := "/tmp/snw-agent-link-tailscaled-test.sock"
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/localapi/v0/whois" || request.URL.Query().Get("addr") != "100.64.0.9" {
			t.Fatalf("unexpected Local API request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		if request.Host != "local-tailscaled.sock" {
			t.Fatalf("unexpected Local API host: %s", request.Host)
		}
		_, _ = response.Write([]byte(`{"Node":{"ID":42,"StableID":"node-stable"}}`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	identity, err := NewLocalAPISocketClient(socketPath).WhoIs(context.Background(), "100.64.0.9")
	if err != nil {
		t.Fatalf("whois over Unix socket: %v", err)
	}
	if identity.NodeID != "42" || identity.StableNodeID != "node-stable" {
		t.Fatalf("unexpected node identity: %+v", identity)
	}
}

func TestVerifyPeerFailsClosedOnNodeMismatch(t *testing.T) {
	provider := stubWhoIsProvider{identity: NodeIdentity{StableNodeID: "node-a", LoginName: "a@example.com"}}
	err := VerifyPeer(context.Background(), provider, "100.64.0.9:7443", PeerExpectation{
		StableNodeID: "node-b",
		LoginName:    "a@example.com",
	})
	if !errors.Is(err, ErrPeerIdentityMismatch) {
		t.Fatalf("expected peer mismatch, got %v", err)
	}
}

func TestVerifyPeerPropagatesWhoIsFailure(t *testing.T) {
	want := errors.New("localapi unavailable")
	err := VerifyPeer(context.Background(), stubWhoIsProvider{err: want}, "100.64.0.9:7443", PeerExpectation{})
	if !errors.Is(err, want) {
		t.Fatalf("expected provider failure, got %v", err)
	}
}

func TestNodeIdentityHasAddress(t *testing.T) {
	identity := NodeIdentity{Addresses: []string{"100.64.0.9/32", "fd7a:115c:a1e0::/48"}}
	for _, address := range []string{"100.64.0.9:7443", "[fd7a:115c:a1e0::9]:7443"} {
		if !identity.HasAddress(address) {
			t.Fatalf("expected address %q to belong to node", address)
		}
	}
	if identity.HasAddress("100.64.0.10:7443") {
		t.Fatal("unexpected unrelated address match")
	}
}

func TestIdentifierStringAcceptsTailscaleStringAndNumericIDs(t *testing.T) {
	if got := identifierString(json.RawMessage(`"n123"`)); got != "n123" {
		t.Fatalf("unexpected string identifier: %q", got)
	}
	if got := identifierString(json.RawMessage(`42`)); got != "42" {
		t.Fatalf("unexpected numeric identifier: %q", got)
	}
}

type stubWhoIsProvider struct {
	identity NodeIdentity
	err      error
}

func (s stubWhoIsProvider) WhoIs(context.Context, string) (NodeIdentity, error) {
	return s.identity, s.err
}
