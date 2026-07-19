package identity

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateDerivesStableAgentIDWhenUnset(t *testing.T) {
	identity, err := Generate("")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	want := StableAgentID(identity.PublicKey())
	if identity.AgentID() != want {
		t.Fatalf("agent id = %q, want %q", identity.AgentID(), want)
	}
	if len(identity.PublicKey()) != ed25519.PublicKeySize {
		t.Fatalf("unexpected public key length: %d", len(identity.PublicKey()))
	}
}

func TestSignedEnvelopeBindsAgentIdentity(t *testing.T) {
	agentA, err := Generate("agent-a")
	if err != nil {
		t.Fatalf("generate agent A: %v", err)
	}
	agentB, err := Generate("agent-b")
	if err != nil {
		t.Fatalf("generate agent B: %v", err)
	}

	envelope, err := agentB.Sign("agent-a", "message", []byte(`{"text":"hello"}`))
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}

	if err := VerifyEnvelope(envelope, agentA.PublicKey()); err == nil {
		t.Fatal("expected signature verification to reject same-host agent impersonation")
	}
}

func TestSignedEnvelopeRoundTrip(t *testing.T) {
	agent, err := Generate("agent-a")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	envelope, err := agent.Sign("agent-a", "message", []byte(`{"text":"hello"}`))
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}

	if err := VerifyEnvelope(envelope, agent.PublicKey()); err != nil {
		t.Fatalf("verify envelope: %v", err)
	}
	if envelope.KeyFingerprint != Fingerprint(agent.PublicKey()) {
		t.Fatalf("unexpected fingerprint %q", envelope.KeyFingerprint)
	}
}
