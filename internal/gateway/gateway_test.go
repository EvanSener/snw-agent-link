package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/registration"
	"github.com/EvanSener/snw-agent-link/internal/store"
	"github.com/EvanSener/snw-agent-link/internal/transport"
	"github.com/a2aproject/a2a-go/v2/a2a"
)

func TestA2AForwardsSignedRequestToLoopbackAgent(t *testing.T) {
	remoteIdentity, err := identity.Generate("agent-remote")
	if err != nil {
		t.Fatal(err)
	}
	localHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/a2a/message:send" {
			t.Fatalf("unexpected forwarded path: %s", request.URL.Path)
		}
		if request.Header.Get("X-SNW-Linkd-Ingress") == "" {
			t.Fatal("expected linkd ingress capability")
		}
		if request.Header.Get("X-SNW-Agent-ID") != remoteIdentity.AgentID() {
			t.Fatalf("expected forwarded source Agent ID %q, got %q", remoteIdentity.AgentID(), request.Header.Get("X-SNW-Agent-ID"))
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(a2a.StreamResponse{Event: a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("forwarded"))})
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	localServer := &http.Server{Handler: localHandler}
	go func() { _ = localServer.Serve(listener) }()
	defer localServer.Close()
	handler, registrations, database := newGatewayTestHandlerWithStore(t)
	card, _ := json.Marshal(map[string]any{"name": "Agent Local"})
	if _, _, err := registrations.Register(context.Background(), registration.Input{
		AgentID: "agent-local", DisplayName: "Agent Local", LocalEndpoint: "http://" + listener.Addr().String() + "/a2a",
		AgentCardJSON: card, IdentityPublicKey: []byte("local-key"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertContact(context.Background(), model.Contact{
		LocalAgentID: "agent-local", RemoteAgentID: remoteIdentity.AgentID(),
		RemoteAgentFingerprint: identity.Fingerprint(remoteIdentity.PublicKey()), State: model.ContactStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"message":{"messageId":"message-1","role":"user","parts":[{"kind":"text","text":"hello"}]}}`)
	request := httptest.NewRequest(http.MethodPost, "https://100.64.0.1:7443/agents/agent-local/a2a/rest/message:send", bytes.NewReader(body))
	if err := transport.SignRequest(request, remoteIdentity, "agent-local"); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected forwarded response, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "forwarded") {
		t.Fatalf("unexpected forwarded response: %s", response.Body.String())
	}
	inbox, err := database.ListInboxMessages(context.Background(), "agent-local", "", true, 10)
	if err != nil {
		t.Fatalf("list persisted inbound mailbox: %v", err)
	}
	if len(inbox) != 1 || inbox[0].MessageID != "message-1" || inbox[0].ContextID != "message-1" || inbox[0].SourceAgentID != remoteIdentity.AgentID() {
		t.Fatalf("unexpected persisted inbound mailbox: %+v", inbox)
	}
}

func TestHealthReturnsReadyJSON(t *testing.T) {
	handler, _ := newGatewayTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://100.64.0.1:7443/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("expected JSON response, got %q", contentType)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("unexpected health response: %+v", body)
	}
}

func TestUnknownAgentCardReturnsNotFound(t *testing.T) {
	handler, _ := newGatewayTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://100.64.0.1:7443/agents/missing/agent-card.json", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", response.Code)
	}
}

func TestRegisteredAgentCardReturnsPublicInterface(t *testing.T) {
	handler, registrations := newGatewayTestHandler(t)
	registerGatewayTestAgent(t, registrations, "agent-local", "Agent Local")
	request := httptest.NewRequest(http.MethodGet, "https://100.64.0.1:7443/agents/agent-local/agent-card.json", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Name                string `json:"name"`
		SupportedInterfaces []struct {
			URL string `json:"url"`
		} `json:"supportedInterfaces"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode agent card: %v", err)
	}
	if body.Name != "Agent Local" {
		t.Fatalf("unexpected agent card name: %q", body.Name)
	}
	if len(body.SupportedInterfaces) != 1 || body.SupportedInterfaces[0].URL != "https://100.64.0.1:7443/agents/agent-local/a2a/rest" {
		t.Fatalf("unexpected supported interfaces: %+v", body.SupportedInterfaces)
	}
}

func TestRouterSignsAgentCardResponseWhenConfigured(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "agent-link.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registrations := registration.NewService(database)
	signer, err := identity.Generate("agent-local")
	if err != nil {
		t.Fatal(err)
	}
	registerGatewayTestAgent(t, registrations, signer.AgentID(), "Agent Local")
	router, err := NewRouter(database, registrations, func(*http.Request) (transport.Signer, error) {
		return signer, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://100.64.0.1:7443/agents/agent-local/agent-card.json", nil)
	response := httptest.NewRecorder()
	router.Handler().ServeHTTP(response, request)
	result := response.Result()
	defer result.Body.Close()
	if err := transport.VerifyResponse(result, signer.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("verify signed agent card response: %v", err)
	}
}

func TestA2ARejectsMissingRemoteAgentIdentity(t *testing.T) {
	handler, registrations := newGatewayTestHandler(t)
	registerGatewayTestAgent(t, registrations, "agent-local", "Agent Local")
	request := httptest.NewRequest(http.MethodPost, "https://100.64.0.1:7443/agents/agent-local/a2a/jsonrpc", strings.NewReader(`{}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestA2ARejectsInactiveContact(t *testing.T) {
	handler, registrations, database := newGatewayTestHandlerWithStore(t)
	registerGatewayTestAgent(t, registrations, "agent-local", "Agent Local")
	if err := database.UpsertContact(context.Background(), model.Contact{
		LocalAgentID:           "agent-local",
		RemoteAgentID:          "agent-remote",
		RemoteHostFingerprint:  "host-remote",
		RemoteAgentFingerprint: "agent-remote-key",
		State:                  model.ContactStateAwaitingConfirmation,
	}); err != nil {
		t.Fatalf("upsert inactive contact: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://100.64.0.1:7443/agents/agent-local/a2a/jsonrpc", strings.NewReader(`{}`))
	request.Header.Set("X-SNW-Agent-ID", "agent-remote")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestA2ARejectsSpoofedAgentHeaderEvenForActiveContact(t *testing.T) {
	handler, registrations, database := newGatewayTestHandlerWithStore(t)
	registerGatewayTestAgent(t, registrations, "agent-local", "Agent Local")
	if err := database.UpsertContact(context.Background(), model.Contact{
		LocalAgentID: "agent-local", RemoteAgentID: "agent-remote", RemoteAgentFingerprint: "not-a-real-key", State: model.ContactStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://100.64.0.1:7443/agents/agent-local/a2a/jsonrpc", strings.NewReader(`{}`))
	request.Header.Set("X-SNW-Agent-ID", "agent-remote")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected spoofed identity rejection, got %d: %s", response.Code, response.Body.String())
	}
}

func newGatewayTestHandler(t *testing.T) (http.Handler, *registration.Service) {
	t.Helper()
	handler, registrations, _ := newGatewayTestHandlerWithStore(t)
	return handler, registrations
}

func newGatewayTestHandlerWithStore(t *testing.T) (http.Handler, *registration.Service, *store.Store) {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "agent-link.sqlite3"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	registrations := registration.NewService(database)
	router, err := NewRouter(database, registrations)
	if err != nil {
		t.Fatalf("create router: %v", err)
	}
	return router.Handler(), registrations, database
}

func registerGatewayTestAgent(t *testing.T, service *registration.Service, agentID, displayName string) {
	t.Helper()
	card, err := json.Marshal(map[string]any{"name": displayName})
	if err != nil {
		t.Fatalf("encode agent card: %v", err)
	}
	if _, _, err := service.Register(context.Background(), registration.Input{
		AgentID:           agentID,
		DisplayName:       displayName,
		LocalEndpoint:     "http://127.0.0.1:7781/a2a",
		AgentCardJSON:     card,
		IdentityPublicKey: []byte("identity-public-key"),
	}); err != nil {
		t.Fatalf("register agent: %v", err)
	}
}
