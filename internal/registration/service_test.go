package registration

import (
	"context"
	"errors"
	"testing"

	"github.com/EvanSener/snw-agent-link/internal/store"
)

func TestRegisterSupportsMultipleIndependentAgents(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	service := NewService(database)
	ctx := context.Background()

	agentA, tokenA, err := service.Register(ctx, Input{
		AgentID:           "agent-a",
		DisplayName:       "Agent A",
		LocalEndpoint:     "http://127.0.0.1:7781/a2a",
		AgentCardJSON:     []byte(`{"name":"Agent A"}`),
		IdentityPublicKey: []byte("public-key-a"),
	})
	if err != nil {
		t.Fatalf("register agent A: %v", err)
	}
	agentB, tokenB, err := service.Register(ctx, Input{
		AgentID:           "agent-b",
		DisplayName:       "Agent B",
		LocalEndpoint:     "http://127.0.0.1:7782/a2a",
		AgentCardJSON:     []byte(`{"name":"Agent B"}`),
		IdentityPublicKey: []byte("public-key-b"),
	})
	if err != nil {
		t.Fatalf("register agent B: %v", err)
	}

	if tokenA == "" || tokenB == "" || tokenA == tokenB {
		t.Fatalf("registration tokens must be non-empty and independent: %q %q", tokenA, tokenB)
	}
	if agentA.AgentID != "agent-a" || agentB.AgentID != "agent-b" {
		t.Fatalf("unexpected registrations: %+v %+v", agentA, agentB)
	}
	registrations, err := database.ListAgentRegistrations(ctx)
	if err != nil {
		t.Fatalf("list registrations: %v", err)
	}
	if len(registrations) != 2 {
		t.Fatalf("expected two registrations, got %d", len(registrations))
	}
}

func TestRegistrationTokenCannotAuthenticateAnotherAgent(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	service := NewService(database)
	ctx := context.Background()

	_, tokenA, err := service.Register(ctx, Input{
		AgentID:           "agent-a",
		DisplayName:       "Agent A",
		LocalEndpoint:     "http://127.0.0.1:7781/a2a",
		AgentCardJSON:     []byte(`{"name":"Agent A"}`),
		IdentityPublicKey: []byte("public-key-a"),
	})
	if err != nil {
		t.Fatalf("register agent A: %v", err)
	}
	_, tokenB, err := service.Register(ctx, Input{
		AgentID:           "agent-b",
		DisplayName:       "Agent B",
		LocalEndpoint:     "http://127.0.0.1:7782/a2a",
		AgentCardJSON:     []byte(`{"name":"Agent B"}`),
		IdentityPublicKey: []byte("public-key-b"),
	})
	if err != nil {
		t.Fatalf("register agent B: %v", err)
	}

	if _, err := service.Authenticate(ctx, "agent-a", tokenA); err != nil {
		t.Fatalf("authenticate agent A: %v", err)
	}
	if _, err := service.Authenticate(ctx, "agent-b", tokenB); err != nil {
		t.Fatalf("authenticate agent B: %v", err)
	}
	if _, err := service.Authenticate(ctx, "agent-b", tokenA); !errors.Is(err, ErrInvalidRegistrationToken) {
		t.Fatalf("expected cross-agent token rejection, got %v", err)
	}
	if _, err := service.Authenticate(ctx, "agent-a", "wrong-token"); !errors.Is(err, ErrInvalidRegistrationToken) {
		t.Fatalf("expected invalid token rejection, got %v", err)
	}
}

func TestRegisterRejectsNonLoopbackEndpoint(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	_, _, err = NewService(database).Register(context.Background(), Input{
		AgentID: "agent-public", DisplayName: "Agent Public", LocalEndpoint: "http://203.0.113.10:7781/a2a",
		AgentCardJSON: []byte(`{"name":"Agent Public"}`), IdentityPublicKey: []byte("public-key"),
	})
	if err == nil {
		t.Fatal("expected public endpoint rejection")
	}
}
