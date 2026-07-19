package gateway

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/registration"
	"github.com/EvanSener/snw-agent-link/internal/store"
	"github.com/EvanSener/snw-agent-link/internal/tailscale"
	"github.com/EvanSener/snw-agent-link/internal/transport"
)

func TestNewRouterWithWhoIsRequiresProvider(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "agent-link.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := NewRouterWithWhoIs(database, registration.NewService(database), nil); err == nil {
		t.Fatal("expected production router to require a WhoIs provider")
	}
}

func TestStrictRouterRejectsContactWithoutRemoteNodeID(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "agent-link.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registrations := registration.NewService(database)
	remote, err := identity.Generate("agent-remote")
	if err != nil {
		t.Fatal(err)
	}
	registerGatewayTestAgent(t, registrations, "agent-local", "Agent Local")
	if err := database.UpsertContact(context.Background(), model.Contact{
		LocalAgentID:           "agent-local",
		RemoteAgentID:          remote.AgentID(),
		RemoteAgentFingerprint: identity.Fingerprint(remote.PublicKey()),
		State:                  model.ContactStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouterWithWhoIs(database, registrations, staticWhoIsProvider{
		identity: tailscale.NodeIdentity{StableNodeID: "node-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://100.64.0.1:7443/agents/agent-local/a2a/jsonrpc", nil)
	request.Header.Set("X-SNW-Agent-ID", remote.AgentID())
	request.Header.Set("X-SNW-Agent-Public-Key", base64.RawURLEncoding.EncodeToString(remote.PublicKey()))
	if router.authorized(request, "agent-local") {
		t.Fatal("strict router authorized a contact without RemoteNodeID")
	}
}

func TestStrictRouterRequiresStableNodeIDAndSourceAddress(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "agent-link.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registrations := registration.NewService(database)
	remote, err := identity.Generate("agent-remote")
	if err != nil {
		t.Fatal(err)
	}
	registerGatewayTestAgent(t, registrations, "agent-local", "Agent Local")
	if err := database.UpsertContact(context.Background(), model.Contact{
		LocalAgentID: "agent-local", RemoteAgentID: remote.AgentID(), RemoteNodeID: "stable-node",
		RemoteAgentFingerprint: identity.Fingerprint(remote.PublicKey()), State: model.ContactStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouterWithWhoIs(database, registrations, staticWhoIsProvider{identity: tailscale.NodeIdentity{
		NodeID: "legacy-node", StableNodeID: "stable-node", Addresses: []string{"100.64.0.9/32"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://100.64.0.1:7443/agents/agent-local/a2a/jsonrpc", strings.NewReader(`{}`))
	request.RemoteAddr = "100.64.0.9:41000"
	request.Header.Set("X-SNW-Agent-ID", remote.AgentID())
	if err := transport.SignRequest(request, remote, "agent-local"); err != nil {
		t.Fatal(err)
	}
	request.RemoteAddr = "100.64.0.10:41000"
	if router.authorized(request, "agent-local") {
		t.Fatal("strict router accepted a source address not owned by the WhoIs node")
	}
	matching := httptest.NewRequest(http.MethodPost, "https://100.64.0.1:7443/agents/agent-local/a2a/jsonrpc", strings.NewReader(`{}`))
	matching.RemoteAddr = "100.64.0.9:41001"
	if err := transport.SignRequest(matching, remote, "agent-local"); err != nil {
		t.Fatal(err)
	}
	if !router.authorized(matching, "agent-local") {
		t.Fatal("strict router rejected matching StableNodeID/source address")
	}
}

type staticWhoIsProvider struct {
	identity tailscale.NodeIdentity
	err      error
}

func (provider staticWhoIsProvider) WhoIs(context.Context, string) (tailscale.NodeIdentity, error) {
	return provider.identity, provider.err
}
