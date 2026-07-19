package delivery

import (
	"context"
	"errors"
	"testing"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
)

type staticContactProvider struct {
	contact model.Contact
}

func (provider staticContactProvider) GetContact(context.Context, string, string) (model.Contact, error) {
	return provider.contact, nil
}

type staticIdentityProvider struct {
	identity *identity.Identity
}

func (provider staticIdentityProvider) GetIdentity(context.Context, string) (*identity.Identity, error) {
	return provider.identity, nil
}

func TestDynamicA2ATransportRejectsActiveContactWithoutNodeIdentity(t *testing.T) {
	signer, err := identity.Generate("agent-source")
	if err != nil {
		t.Fatal(err)
	}
	transportClient, err := NewDynamicA2ATransport(staticContactProvider{contact: model.Contact{
		LocalAgentID: "agent-source", RemoteAgentID: "agent-target", State: model.ContactStateActive,
		RemoteEndpoint: "http://100.64.0.2:7443/agents/agent-target/a2a/rest",
	}}, staticIdentityProvider{identity: signer})
	if err != nil {
		t.Fatal(err)
	}
	transportClient.SetRequireRemoteNodeID(true)
	_, err = transportClient.Deliver(context.Background(), model.OutboxMessage{SourceAgentID: "agent-source", TargetAgentID: "agent-target"})
	if err == nil || err.Error() != "target contact Tailscale node identity is unavailable" {
		t.Fatalf("expected missing node identity rejection, got %v", err)
	}
}

func TestDynamicA2ATransportFailsClosedWhenReadinessCheckFails(t *testing.T) {
	signer, err := identity.Generate("agent-source")
	if err != nil {
		t.Fatal(err)
	}
	transportClient, err := NewDynamicA2ATransport(staticContactProvider{}, staticIdentityProvider{identity: signer})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("localapi unavailable")
	transportClient.SetReadinessCheck(func(context.Context) error { return want })
	_, err = transportClient.Deliver(context.Background(), model.OutboxMessage{SourceAgentID: "agent-source", TargetAgentID: "agent-target"})
	if !errors.Is(err, want) {
		t.Fatalf("expected readiness failure, got %v", err)
	}
}

var _ ContactProvider = staticContactProvider{}
var _ IdentityProvider = staticIdentityProvider{}
