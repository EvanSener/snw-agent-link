package management

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"github.com/EvanSener/snw-agent-link/internal/attachment"
	"github.com/EvanSener/snw-agent-link/internal/capability"
	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/ipc"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/pairing"
	"github.com/EvanSener/snw-agent-link/internal/registration"
	"github.com/EvanSener/snw-agent-link/internal/store"
)

type memoryIdentities struct {
	values map[string]*identity.Identity
	caps   map[string]capability.Key
}

func (provider *memoryIdentities) GetIdentity(_ context.Context, agentID string) (*identity.Identity, error) {
	value, ok := provider.values[agentID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return value, nil
}
func (provider *memoryIdentities) PutIdentity(_ context.Context, value *identity.Identity) error {
	provider.values[value.AgentID()] = value
	return nil
}
func (provider *memoryIdentities) GetCapabilityKey(_ context.Context, agentID string) (capability.Key, error) {
	value, ok := provider.caps[agentID]
	if !ok {
		return capability.Key{}, store.ErrNotFound
	}
	return value, nil
}
func (provider *memoryIdentities) PutCapabilityKey(_ context.Context, agentID string, value capability.Key) error {
	provider.caps[agentID] = value
	return nil
}

type staticStatus struct{}

func (staticStatus) RuntimeStatus(context.Context) RuntimeStatus {
	return RuntimeStatus{Version: "test", TailscaleAddress: "100.64.0.1", TailscaleNodeID: "node-a", TailscaleStableNodeID: "stable-a", TailscaleLoggedIn: true, TailscaleLocalAPIReady: true, TailscaleWhoIsReady: true, HostFingerprint: "host-a", GatewayListening: true}
}

func TestBlobURIUsesTailnetGatewayAddress(t *testing.T) {
	grant := model.AttachmentGrant{OwnerAgentID: "agent-a", BlobID: "blob-1"}
	if got := blobURI("100.64.0.1", grant); got != "http://100.64.0.1:7443/agents/agent-a/blobs/blob-1" {
		t.Fatalf("unexpected blob URI: %q", got)
	}
	if got := blobURI("[fd7a:115c:a1e0::1]:7443", grant); got != "http://[fd7a:115c:a1e0::1]:7443/agents/agent-a/blobs/blob-1" {
		t.Fatalf("unexpected IPv6 blob URI: %q", got)
	}
}

func TestHandlerRegistersAndListsAgents(t *testing.T) {
	handler, database, identities := newTestHandler(t)
	result := call[AgentRegisterResult](t, handler, "agent.register", AgentRegisterParams{
		AgentID: "agent-a", DisplayName: "Agent A", LocalEndpoint: "http://127.0.0.1:7781/a2a", AgentCard: []byte(`{"name":"Agent A"}`),
	})
	if result.Registration.AgentID != "agent-a" || result.RegistrationToken == "" {
		t.Fatalf("unexpected registration: %#v", result)
	}
	if _, ok := identities.values["agent-a"]; !ok {
		t.Fatal("identity was not persisted")
	}
	registrations, err := database.ListAgentRegistrations(context.Background())
	if err != nil || len(registrations) != 1 {
		t.Fatalf("list registrations: %v %#v", err, registrations)
	}
}

func TestHandlerEnsuresExistingAgentWithoutReplacingIdentity(t *testing.T) {
	handler, database, identities := newTestHandler(t)
	params := AgentEnsureParams{AgentID: "agent-ensure", DisplayName: "Agent Ensure", LocalEndpoint: "http://127.0.0.1:7781/a2a", AgentCard: []byte(`{"name":"Agent Ensure"}`)}
	first := call[AgentEnsureResult](t, handler, "agent.ensure", params)
	if !first.Created || first.RegistrationToken == "" {
		t.Fatalf("unexpected first ensure result: %+v", first)
	}
	originalKey := append([]byte(nil), first.Registration.IdentityPublicKey...)
	params.RegistrationToken = first.RegistrationToken
	params.AgentCard = []byte("{\n  \"name\": \"Agent Ensure\"\n}")
	second := call[AgentEnsureResult](t, handler, "agent.ensure", params)
	if second.Created || second.RegistrationToken != first.RegistrationToken || !bytes.Equal(second.Registration.IdentityPublicKey, originalKey) {
		t.Fatalf("ensure replaced existing registration: first=%+v second=%+v", first, second)
	}
	if _, err := identities.GetIdentity(context.Background(), "agent-ensure"); err != nil {
		t.Fatalf("identity missing after ensure: %v", err)
	}
	registrations, err := database.ListAgentRegistrations(context.Background())
	if err != nil || len(registrations) != 1 {
		t.Fatalf("ensure created duplicate registrations: %v %+v", err, registrations)
	}
}

func TestHandlerEnsureRejectsExistingAgentWithoutTokenOrWithChangedEndpoint(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	params := AgentEnsureParams{AgentID: "agent-ensure", DisplayName: "Agent Ensure", LocalEndpoint: "http://127.0.0.1:7781/a2a", AgentCard: []byte(`{"name":"Agent Ensure"}`)}
	first := call[AgentEnsureResult](t, handler, "agent.ensure", params)
	if _, err := handler.HandleIPC(context.Background(), ipc.Request{Version: ipc.ProtocolVersion, RequestID: "missing-token", Method: "agent.ensure", Params: mustJSON(t, params)}); err == nil {
		t.Fatal("expected existing ensure without token to fail")
	}
	params.RegistrationToken = first.RegistrationToken
	params.LocalEndpoint = "http://127.0.0.1:7782/a2a"
	if _, err := handler.HandleIPC(context.Background(), ipc.Request{Version: ipc.ProtocolVersion, RequestID: "changed-endpoint", Method: "agent.ensure", Params: mustJSON(t, params)}); err == nil {
		t.Fatal("expected changed endpoint to fail")
	}
}

func TestHandlerQueuesMessageOnlyForAuthenticatedActiveAgent(t *testing.T) {
	handler, database, _ := newTestHandler(t)
	registered := call[AgentRegisterResult](t, handler, "agent.register", AgentRegisterParams{
		AgentID: "agent-a", DisplayName: "Agent A", LocalEndpoint: "http://127.0.0.1:7781/a2a", AgentCard: []byte(`{"name":"Agent A"}`),
	})
	if err := database.UpsertContact(context.Background(), model.Contact{LocalAgentID: "agent-a", RemoteAgentID: "agent-b", State: model.ContactStateActive}); err != nil {
		t.Fatal(err)
	}
	queued := call[model.OutboxMessage](t, handler, "message.send", MessageSendParams{
		SourceAgentID: "agent-a", TargetAgentID: "agent-b", RegistrationToken: registered.RegistrationToken,
		Payload: json.RawMessage(`{"message":{"messageId":"message-1","role":"user","parts":[]}}`),
	})
	if queued.State != model.OutboxStatePending || queued.MessageID == "" {
		t.Fatalf("unexpected queued message: %+v", queued)
	}
	if _, err := handler.HandleIPC(context.Background(), ipc.Request{Version: ipc.ProtocolVersion, RequestID: "bad", Method: "message.send", Params: json.RawMessage(`{"sourceAgentId":"agent-a","targetAgentId":"agent-b","registrationToken":"wrong","payload":{}}`)}); err == nil {
		t.Fatal("expected invalid registration token rejection")
	}
	cancelled := call[model.OutboxMessage](t, handler, "message.cancel", MessageCancelParams{SourceAgentID: "agent-a", RegistrationToken: registered.RegistrationToken, MessageID: queued.MessageID})
	if cancelled.State != model.OutboxStateCancelled {
		t.Fatalf("expected cancelled message, got %+v", cancelled)
	}
}

func TestHandlerCapabilityChallengeExchangeAndMessage(t *testing.T) {
	handler, database, identities := newTestHandler(t)
	registered := call[AgentRegisterResult](t, handler, "agent.register", AgentRegisterParams{
		AgentID: "agent-cap", DisplayName: "Capability Agent", LocalEndpoint: "http://127.0.0.1:7783/a2a", AgentCard: []byte(`{"name":"Capability Agent"}`),
	})
	if err := database.UpsertContact(context.Background(), model.Contact{LocalAgentID: "agent-cap", RemoteAgentID: "agent-target", State: model.ContactStateActive}); err != nil {
		t.Fatal(err)
	}
	challengeResult := call[CapabilityChallengeResult](t, handler, "agent.capability.challenge", CapabilityChallengeParams{
		AgentID: "agent-cap", RegistrationToken: registered.RegistrationToken, Methods: []string{"message.send"},
	})
	key, err := identities.GetCapabilityKey(context.Background(), "agent-cap")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := key.Sign(challengeResult.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	sessionResult := call[CapabilitySessionResult](t, handler, "agent.capability.exchange", CapabilityExchangeParams{
		AgentID: "agent-cap", Challenge: challengeResult.Challenge, Signature: signature,
	})
	queued := call[model.OutboxMessage](t, handler, "message.send", MessageSendParams{
		SourceAgentID: "agent-cap", TargetAgentID: "agent-target", CapabilitySession: sessionResult.Session.Token,
		Payload: json.RawMessage(`{"message":{"messageId":"cap-1","role":"user","parts":[]}}`),
	})
	if queued.State != model.OutboxStatePending {
		t.Fatalf("expected capability-authenticated message to queue: %+v", queued)
	}
}

func TestHandlerAttachmentUploadLifecycle(t *testing.T) {
	database, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	identities := &memoryIdentities{values: map[string]*identity.Identity{}, caps: map[string]capability.Key{}}
	attachments, err := attachment.NewService(t.TempDir(), 1<<20, 8)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(database, registration.NewService(database), pairing.NewService(database, nil), identities, staticStatus{}, attachments)
	registered := call[AgentRegisterResult](t, handler, "agent.register", AgentRegisterParams{AgentID: "agent-files", DisplayName: "Files", LocalEndpoint: "http://127.0.0.1:7784/a2a", AgentCard: []byte(`{"name":"Files"}`)})
	data := []byte("attachment data")
	digest := sha256.Sum256(data)
	init := call[AttachmentResult](t, handler, "attachment.init", AttachmentInitParams{AgentID: "agent-files", RegistrationToken: registered.RegistrationToken, Name: "note.txt", Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])})
	call[AttachmentResult](t, handler, "attachment.chunk", AttachmentChunkParams{AgentID: "agent-files", RegistrationToken: registered.RegistrationToken, BlobID: init.Attachment.BlobID, Offset: 0, Data: data[:8]})
	call[AttachmentResult](t, handler, "attachment.chunk", AttachmentChunkParams{AgentID: "agent-files", RegistrationToken: registered.RegistrationToken, BlobID: init.Attachment.BlobID, Offset: 8, Data: data[8:]})
	completed := call[AttachmentResult](t, handler, "attachment.complete", AttachmentBlobParams{AgentID: "agent-files", RegistrationToken: registered.RegistrationToken, BlobID: init.Attachment.BlobID})
	if completed.Attachment.State != attachment.StateCompleted || completed.Attachment.Received != int64(len(data)) {
		t.Fatalf("unexpected attachment completion: %+v", completed.Attachment)
	}
}

func TestHandlerAcceptsAgentCardObject(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	request := ipc.Request{
		Version:   ipc.ProtocolVersion,
		RequestID: "object-card",
		Method:    "agent.register",
		Params: json.RawMessage(`{
			"agentId":"agent-object-card",
			"displayName":"Agent Object Card",
			"localEndpoint":"http://127.0.0.1:7782/a2a",
			"agentCard":{"name":"Agent Object Card"}
		}`),
	}

	value, err := handler.HandleIPC(context.Background(), request)
	if err != nil {
		t.Fatalf("agent.register: %v", err)
	}
	result := value.(AgentRegisterResult)
	if string(result.Registration.AgentCardJSON) != `{"name":"Agent Object Card"}` {
		t.Fatalf("AgentCardJSON = %s", result.Registration.AgentCardJSON)
	}
}

func TestHandlerCompletesPairingAcrossExplicitMessages(t *testing.T) {
	handler, database, identities := newTestHandler(t)
	identityA, _ := identity.Generate("agent-a")
	identityB, _ := identity.Generate("agent-b")
	identities.values["agent-a"] = identityA
	identities.values["agent-b"] = identityB

	invite := call[pairing.PairingInvite](t, handler, "pair.invite", PairInviteParams{
		LocalAgentID: "agent-a", RemoteAgentID: "agent-b", LocalHostFingerprint: "host-a", TailscaleAddress: "100.64.0.1", TTL: time.Hour,
	})
	acceptance := call[pairing.PairingAcceptance](t, handler, "pair.accept", PairAcceptParams{LocalAgentID: "agent-b", LocalHostFingerprint: "host-b", Invite: invite})
	confirmation := call[pairing.PairingConfirmation](t, handler, "pair.approve", PairApproveParams{
		LocalAgentID: "agent-a", Acceptance: acceptance, ExpectedHostFingerprint: "host-b", ExpectedAgentFingerprint: identity.Fingerprint(identityB.PublicKey()),
	})
	receipt := call[pairing.PairingActivationReceipt](t, handler, "pair.confirm", PairConfirmParams{LocalAgentID: "agent-b", Confirmation: confirmation})
	call[struct{}](t, handler, "pair.activate", PairActivateParams{LocalAgentID: "agent-a", Receipt: receipt})

	for _, pair := range [][2]string{{"agent-a", "agent-b"}, {"agent-b", "agent-a"}} {
		contact, err := database.GetContact(context.Background(), pair[0], pair[1])
		if err != nil || !handler.pairing.CanCommunicate(contact) {
			t.Fatalf("contact %v is not active: %v %#v", pair, err, contact)
		}
	}
}

func TestHandlerPairingBindsTailscaleEndpoints(t *testing.T) {
	handler, database, identities := newTestHandler(t)
	identityA, _ := identity.Generate("agent-a-endpoint")
	identityB, _ := identity.Generate("agent-b-endpoint")
	identities.values[identityA.AgentID()] = identityA
	identities.values[identityB.AgentID()] = identityB
	invite := call[pairing.PairingInvite](t, handler, "pair.invite", PairInviteParams{
		LocalAgentID: identityA.AgentID(), RemoteAgentID: identityB.AgentID(), LocalHostFingerprint: "host-a", TailscaleAddress: "100.64.0.11", TTL: time.Hour,
	})
	acceptance := call[pairing.PairingAcceptance](t, handler, "pair.accept", PairAcceptParams{
		LocalAgentID: identityB.AgentID(), LocalHostFingerprint: "host-b", TailscaleAddress: "100.64.0.12", Invite: invite,
	})
	confirmation := call[pairing.PairingConfirmation](t, handler, "pair.approve", PairApproveParams{
		LocalAgentID: identityA.AgentID(), Acceptance: acceptance, ExpectedHostFingerprint: "host-b", ExpectedAgentFingerprint: identity.Fingerprint(identityB.PublicKey()),
	})
	receipt := call[pairing.PairingActivationReceipt](t, handler, "pair.confirm", PairConfirmParams{LocalAgentID: identityB.AgentID(), Confirmation: confirmation})
	call[struct{}](t, handler, "pair.activate", PairActivateParams{LocalAgentID: identityA.AgentID(), Receipt: receipt})
	contactA, err := database.GetContact(context.Background(), identityA.AgentID(), identityB.AgentID())
	if err != nil || contactA.RemoteEndpoint != "http://100.64.0.12:7443/agents/"+identityB.AgentID()+"/a2a/rest" {
		t.Fatalf("unexpected A endpoint: %v %+v", err, contactA)
	}
	contactB, err := database.GetContact(context.Background(), identityB.AgentID(), identityA.AgentID())
	if err != nil || contactB.RemoteEndpoint != "http://100.64.0.11:7443/agents/"+identityA.AgentID()+"/a2a/rest" {
		t.Fatalf("unexpected B endpoint: %v %+v", err, contactB)
	}
}

func newTestHandler(t *testing.T) (*Handler, *store.Store, *memoryIdentities) {
	t.Helper()
	database, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	identities := &memoryIdentities{values: map[string]*identity.Identity{}, caps: map[string]capability.Key{}}
	return NewHandler(database, registration.NewService(database), pairing.NewService(database, nil), identities, staticStatus{}), database, identities
}

func TestDoctorReportsTailscaleReadinessChecks(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	value, err := handler.HandleIPC(context.Background(), ipc.Request{Version: ipc.ProtocolVersion, RequestID: "doctor", Method: "doctor"})
	if err != nil {
		t.Fatal(err)
	}
	result, ok := value.(DoctorResult)
	if !ok {
		t.Fatalf("doctor returned %T", value)
	}
	if !result.OK {
		t.Fatalf("expected ready doctor result: %+v", result)
	}
	checks := map[string]bool{}
	for _, check := range result.Checks {
		checks[check.Name] = check.OK
	}
	for _, name := range []string{"tailscale_address", "tailscale_login", "tailscale_local_api", "tailscale_whois"} {
		if !checks[name] {
			t.Fatalf("missing or failed Tailscale doctor check %q: %+v", name, result.Checks)
		}
	}
}

func call[T any](t *testing.T, handler *Handler, method string, params any) T {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	value, err := handler.HandleIPC(context.Background(), ipc.Request{Version: ipc.ProtocolVersion, RequestID: "request", Method: method, Params: raw})
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	result, ok := value.(T)
	if !ok {
		t.Fatalf("%s returned %T", method, value)
	}
	return result
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
