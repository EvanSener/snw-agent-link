package pairing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/store"
)

func TestPairingActivatesOnlyAfterBothDaemonsConfirm(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
	serviceA := newTestService(t, now)
	serviceB := newTestService(t, now)
	agentA := mustIdentity(t, "agent-a")
	agentB := mustIdentity(t, "agent-b")

	invite, err := serviceA.CreateInvite(ctx, agentA, CreateInviteInput{
		RemoteAgentID:       agentB.AgentID(),
		LocalHostFingerprint: "host-a",
		LocalTailscaleAddress: "100.64.0.10",
		TTL:                 time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	assertContactState(t, ctx, serviceA, agentA.AgentID(), agentB.AgentID(), model.ContactStatePendingOutbound)

	imported, err := serviceB.ImportInvite(ctx, agentB, invite)
	if err != nil {
		t.Fatalf("import invite: %v", err)
	}
	if imported.RemoteAgentFingerprint != identity.Fingerprint(agentA.PublicKey()) {
		t.Fatalf("unexpected inviter fingerprint: %s", imported.RemoteAgentFingerprint)
	}
	assertContactState(t, ctx, serviceB, agentB.AgentID(), agentA.AgentID(), model.ContactStatePendingInbound)

	acceptance, err := serviceB.AcceptImportedInvite(ctx, agentB, "host-b")
	if err != nil {
		t.Fatalf("accept imported invite: %v", err)
	}
	assertContactState(t, ctx, serviceB, agentB.AgentID(), agentA.AgentID(), model.ContactStateAwaitingConfirmation)

	confirmation, err := serviceA.ApproveAcceptance(ctx, agentA, acceptance, ApproveAcceptanceInput{
		ExpectedHostFingerprint:  "host-b",
		ExpectedAgentFingerprint: identity.Fingerprint(agentB.PublicKey()),
	})
	if err != nil {
		t.Fatalf("approve acceptance: %v", err)
	}
	assertContactState(t, ctx, serviceA, agentA.AgentID(), agentB.AgentID(), model.ContactStateAwaitingConfirmation)

	receipt, err := serviceB.ApplyConfirmation(ctx, agentB, confirmation)
	if err != nil {
		t.Fatalf("apply confirmation: %v", err)
	}
	assertContactState(t, ctx, serviceB, agentB.AgentID(), agentA.AgentID(), model.ContactStateActive)
	assertContactState(t, ctx, serviceA, agentA.AgentID(), agentB.AgentID(), model.ContactStateAwaitingConfirmation)

	if _, err := serviceA.ApplyActivationReceipt(ctx, agentA, receipt); err != nil {
		t.Fatalf("apply activation receipt: %v", err)
	}
	assertContactState(t, ctx, serviceA, agentA.AgentID(), agentB.AgentID(), model.ContactStateActive)
}

func TestBlockedContactCannotCreateOrImportInvite(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	serviceA := newTestService(t, now)
	serviceB := newTestService(t, now)
	agentA := mustIdentity(t, "agent-a")
	agentB := mustIdentity(t, "agent-b")

	seedContact(t, ctx, serviceA, model.Contact{
		LocalAgentID: agentA.AgentID(), RemoteAgentID: agentB.AgentID(),
		RemoteHostFingerprint: "host-b", RemoteAgentFingerprint: identity.Fingerprint(agentB.PublicKey()),
		State: model.ContactStateBlocked,
	})
	if _, err := serviceA.CreateInvite(ctx, agentA, CreateInviteInput{
		RemoteAgentID: agentB.AgentID(), LocalHostFingerprint: "host-a",
		LocalTailscaleAddress: "100.64.0.10", TTL: time.Hour,
	}); !errors.Is(err, ErrContactBlocked) {
		t.Fatalf("expected blocked create rejection, got %v", err)
	}

	serviceC := newTestService(t, now)
	invite, err := serviceC.CreateInvite(ctx, agentA, CreateInviteInput{
		RemoteAgentID: agentB.AgentID(), LocalHostFingerprint: "host-a",
		LocalTailscaleAddress: "100.64.0.10", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite from unblocked store: %v", err)
	}
	seedContact(t, ctx, serviceB, model.Contact{
		LocalAgentID: agentB.AgentID(), RemoteAgentID: agentA.AgentID(),
		RemoteHostFingerprint: "host-a", RemoteAgentFingerprint: identity.Fingerprint(agentA.PublicKey()),
		State: model.ContactStateBlocked,
	})
	if _, err := serviceB.ImportInvite(ctx, agentB, invite); !errors.Is(err, ErrContactBlocked) {
		t.Fatalf("expected blocked import rejection, got %v", err)
	}
}

func TestInviteExpiresAndCannotBeReplayed(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	current := base
	serviceA := newTestServiceWithClock(t, func() time.Time { return current })
	serviceB := newTestServiceWithClock(t, func() time.Time { return current })
	agentA := mustIdentity(t, "agent-a")
	agentB := mustIdentity(t, "agent-b")

	invite, err := serviceA.CreateInvite(ctx, agentA, CreateInviteInput{
		RemoteAgentID: agentB.AgentID(), LocalHostFingerprint: "host-a",
		LocalTailscaleAddress: "100.64.0.10", TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := serviceB.ImportInvite(ctx, agentB, invite); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if _, err := serviceB.ImportInvite(ctx, agentB, invite); !errors.Is(err, ErrInviteConsumed) {
		t.Fatalf("expected replay rejection, got %v", err)
	}

	serviceC := newTestServiceWithClock(t, func() time.Time { return current })
	current = base.Add(time.Minute)
	if _, err := serviceC.ImportInvite(ctx, agentB, invite); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("expected expiry at boundary, got %v", err)
	}
}

func TestPairingRejectsHostAndAgentIdentityChanges(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 11, 0, 0, 0, time.UTC)
	serviceA := newTestService(t, now)
	serviceB := newTestService(t, now)
	agentA := mustIdentity(t, "agent-a")
	agentB := mustIdentity(t, "agent-b")
	invite := mustCreateInvite(t, ctx, serviceA, agentA, agentB.AgentID())
	if _, err := serviceB.ImportInvite(ctx, agentB, invite); err != nil {
		t.Fatalf("import invite: %v", err)
	}
	acceptance, err := serviceB.AcceptImportedInvite(ctx, agentB, "host-b")
	if err != nil {
		t.Fatalf("accept imported invite: %v", err)
	}

	tamperedHost := acceptance
	tamperedHost.Payload.AcceptingHostFingerprint = "host-attacker"
	tamperedHost.Envelope = mustSignPayload(t, agentB, KindPairingAcceptance, tamperedHost.Payload)
	approval := ApproveAcceptanceInput{
		ExpectedHostFingerprint:  "host-b",
		ExpectedAgentFingerprint: identity.Fingerprint(agentB.PublicKey()),
	}
	if _, err := serviceA.ApproveAcceptance(ctx, agentA, tamperedHost, approval); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("expected host identity rejection, got %v", err)
	}

	otherB := mustIdentity(t, agentB.AgentID())
	tamperedAgent := acceptance
	tamperedAgent.Payload.AcceptingAgentPublicKey = otherB.PublicKey()
	tamperedAgent.Envelope = mustSignPayload(t, otherB, KindPairingAcceptance, tamperedAgent.Payload)
	if _, err := serviceA.ApproveAcceptance(ctx, agentA, tamperedAgent, approval); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("expected agent identity rejection, got %v", err)
	}
}

func TestSignedRevocationImmediatelyDisablesPeer(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	serviceA := newTestService(t, now)
	serviceB := newTestService(t, now)
	agentA := mustIdentity(t, "agent-a")
	agentB := mustIdentity(t, "agent-b")
	activatePair(t, ctx, serviceA, serviceB, agentA, agentB)

	notice, contact, err := serviceA.RevokeWithNotice(ctx, agentA, agentB.AgentID(), "operator revoked")
	if err != nil {
		t.Fatalf("create revocation: %v", err)
	}
	if contact.State != model.ContactStateRevoked {
		t.Fatalf("local contact not revoked: %s", contact.State)
	}
	remote, err := serviceB.ApplyRevocation(ctx, agentB, notice)
	if err != nil {
		t.Fatalf("apply revocation: %v", err)
	}
	if remote.State != model.ContactStateRevoked || serviceB.CanCommunicate(remote) {
		t.Fatalf("remote contact remains communicable: %+v", remote)
	}
}

func activatePair(t *testing.T, ctx context.Context, serviceA, serviceB *Service, agentA, agentB *identity.Identity) {
	t.Helper()
	invite := mustCreateInvite(t, ctx, serviceA, agentA, agentB.AgentID())
	if _, err := serviceB.ImportInvite(ctx, agentB, invite); err != nil {
		t.Fatalf("import invite: %v", err)
	}
	acceptance, err := serviceB.AcceptImportedInvite(ctx, agentB, "host-b")
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}
	confirmation, err := serviceA.ApproveAcceptance(ctx, agentA, acceptance, ApproveAcceptanceInput{
		ExpectedHostFingerprint:  "host-b",
		ExpectedAgentFingerprint: identity.Fingerprint(agentB.PublicKey()),
	})
	if err != nil {
		t.Fatalf("approve acceptance: %v", err)
	}
	receipt, err := serviceB.ApplyConfirmation(ctx, agentB, confirmation)
	if err != nil {
		t.Fatalf("apply confirmation: %v", err)
	}
	if _, err := serviceA.ApplyActivationReceipt(ctx, agentA, receipt); err != nil {
		t.Fatalf("apply receipt: %v", err)
	}
}

func mustCreateInvite(t *testing.T, ctx context.Context, service *Service, local *identity.Identity, remoteAgentID string) PairingInvite {
	t.Helper()
	invite, err := service.CreateInvite(ctx, local, CreateInviteInput{
		RemoteAgentID: remoteAgentID, LocalHostFingerprint: "host-a",
		LocalTailscaleAddress: "100.64.0.10", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	return invite
}

func mustIdentity(t *testing.T, agentID string) *identity.Identity {
	t.Helper()
	value, err := identity.Generate(agentID)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return value
}

func mustSignPayload[T any](t *testing.T, signer *identity.Identity, kind string, payload T) model.SignedEnvelope {
	t.Helper()
	envelope, err := signPayload(signer, kind, payload)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	return envelope
}

func assertContactState(t *testing.T, ctx context.Context, service *Service, localAgentID, remoteAgentID string, expected model.ContactState) {
	t.Helper()
	contact, err := service.Store().GetContact(ctx, localAgentID, remoteAgentID)
	if err != nil {
		t.Fatalf("get contact: %v", err)
	}
	if contact.State != expected {
		t.Fatalf("expected %s, got %s", expected, contact.State)
	}
}

func seedContact(t *testing.T, ctx context.Context, service *Service, contact model.Contact) {
	t.Helper()
	if err := service.Store().UpsertContact(ctx, contact); err != nil {
		t.Fatalf("seed contact: %v", err)
	}
}

func newTestService(t *testing.T, now time.Time) *Service {
	t.Helper()
	return newTestServiceWithClock(t, func() time.Time { return now })
}

func newTestServiceWithClock(t *testing.T, clock Clock) *Service {
	t.Helper()
	db, err := store.Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewService(db, clock)
}
