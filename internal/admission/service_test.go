package admission

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/store"
)

func TestAuthorizeAcceptsActivePinnedSignedPeerOnce(t *testing.T) {
	service, database, remoteIdentity, now := newAdmissionTestService(t)
	envelope := signAt(t, remoteIdentity, now, "message", []byte("untrusted external payload"))
	input := Input{
		LocalAgentID:          "agent-local",
		RemoteHostFingerprint: "host-remote",
		RemotePublicKey:       remoteIdentity.PublicKey(),
		Envelope:              envelope,
	}

	if err := service.Authorize(context.Background(), input); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if err := service.Authorize(context.Background(), input); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected replay rejection, got %v", err)
	}

	entries, err := database.ListAuditEntries(context.Background(), "agent-local", "agent-remote", 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 2 || entries[0].Action != "admission.authorize" {
		t.Fatalf("unexpected audit entries: %+v", entries)
	}
}

func TestAuthorizeRejectsInactiveContactBeforeCommunication(t *testing.T) {
	service, database, remoteIdentity, now := newAdmissionTestService(t)
	contact, err := database.GetContact(context.Background(), "agent-local", "agent-remote")
	if err != nil {
		t.Fatalf("get contact: %v", err)
	}
	contact.State = model.ContactStateAwaitingConfirmation
	if err := database.UpsertContact(context.Background(), contact); err != nil {
		t.Fatalf("update contact: %v", err)
	}

	err = service.Authorize(context.Background(), Input{
		LocalAgentID:          "agent-local",
		RemoteHostFingerprint: "host-remote",
		RemotePublicKey:       remoteIdentity.PublicKey(),
		Envelope:              signAt(t, remoteIdentity, now, "message", nil),
	})
	if !errors.Is(err, ErrContactNotActive) {
		t.Fatalf("expected inactive contact rejection, got %v", err)
	}
}

func TestAuthorizeRejectsHostAndAgentIdentityChanges(t *testing.T) {
	service, _, remoteIdentity, now := newAdmissionTestService(t)
	envelope := signAt(t, remoteIdentity, now, "message", nil)

	err := service.Authorize(context.Background(), Input{
		LocalAgentID:          "agent-local",
		RemoteHostFingerprint: "changed-host",
		RemotePublicKey:       remoteIdentity.PublicKey(),
		Envelope:              envelope,
	})
	if !errors.Is(err, ErrHostFingerprintMismatch) {
		t.Fatalf("expected host mismatch, got %v", err)
	}

	changedIdentity, err := identity.Generate("agent-remote")
	if err != nil {
		t.Fatalf("generate changed identity: %v", err)
	}
	err = service.Authorize(context.Background(), Input{
		LocalAgentID:          "agent-local",
		RemoteHostFingerprint: "host-remote",
		RemotePublicKey:       changedIdentity.PublicKey(),
		Envelope:              envelope,
	})
	if !errors.Is(err, ErrAgentFingerprintMismatch) {
		t.Fatalf("expected agent mismatch, got %v", err)
	}
}

func TestAuthorizeRejectsStaleEnvelope(t *testing.T) {
	service, _, remoteIdentity, now := newAdmissionTestService(t)
	err := service.Authorize(context.Background(), Input{
		LocalAgentID:          "agent-local",
		RemoteHostFingerprint: "host-remote",
		RemotePublicKey:       remoteIdentity.PublicKey(),
		Envelope:              signAt(t, remoteIdentity, now.Add(-6*time.Minute), "message", nil),
	})
	if !errors.Is(err, ErrEnvelopeOutsideTimeWindow) {
		t.Fatalf("expected stale envelope rejection, got %v", err)
	}
}

func newAdmissionTestService(t *testing.T) (*Service, *store.Store, *identity.Identity, time.Time) {
	t.Helper()
	database, err := store.Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	remoteIdentity, err := identity.Generate("agent-remote")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	if err := database.UpsertContact(context.Background(), model.Contact{
		LocalAgentID:           "agent-local",
		RemoteAgentID:          "agent-remote",
		RemoteHostFingerprint:  "host-remote",
		RemoteAgentFingerprint: identity.Fingerprint(remoteIdentity.PublicKey()),
		State:                  model.ContactStateActive,
	}); err != nil {
		t.Fatalf("seed contact: %v", err)
	}
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	return NewService(database, func() time.Time { return now }, 5*time.Minute), database, remoteIdentity, now
}

func signAt(t *testing.T, signer *identity.Identity, issuedAt time.Time, kind string, payload []byte) model.SignedEnvelope {
	t.Helper()
	envelope, err := signer.Sign(signer.AgentID(), kind, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope.IssuedAt = issuedAt.UnixMilli()
	content := struct {
		AgentID         string `json:"agentId"`
		KeyFingerprint string `json:"keyFingerprint"`
		Kind            string `json:"kind"`
		Payload         []byte `json:"payload"`
		IssuedAt        int64  `json:"issuedAt"`
		Nonce           string `json:"nonce"`
	}{
		AgentID:         envelope.AgentID,
		KeyFingerprint: envelope.KeyFingerprint,
		Kind:            envelope.Kind,
		Payload:         envelope.Payload,
		IssuedAt:        envelope.IssuedAt,
		Nonce:           envelope.Nonce,
	}
	encoded, err := canonicalEnvelopeBytes(content)
	if err != nil {
		t.Fatalf("canonical envelope: %v", err)
	}
	envelope.Signature = ed25519.Sign(signer.PrivateKey(), encoded)
	return envelope
}
