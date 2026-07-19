package capability

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestChallengeSignatureBindsAgentEndpointAndMethods(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	challenge := Challenge{BootID: "boot-a", Nonce: "nonce-a", AgentID: "agent-a", EndpointDigest: "digest-a", Methods: []string{"send", "wait"}, ExpiresAt: time.Unix(100, 0).UTC()}
	signature, err := key.Sign(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(key.Public(), challenge, signature); err != nil {
		t.Fatalf("verify signed challenge: %v", err)
	}
	challenge.Methods[0] = "cancel"
	if err := Verify(key.Public(), challenge, signature); err == nil {
		t.Fatal("expected modified methods to invalidate capability challenge")
	}
	if len(key.Private()) != ed25519.PrivateKeySize || len(key.Public()) != ed25519.PublicKeySize {
		t.Fatal("unexpected capability key sizes")
	}
}

func TestSessionRejectsExpiredOrWrongGeneration(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	session := IssueSession("agent-a", 4, []string{"send"}, now, 15*time.Minute)
	if err := session.Validate("agent-a", 4, "send", now.Add(time.Minute)); err != nil {
		t.Fatalf("validate session: %v", err)
	}
	if err := session.Validate("agent-a", 3, "send", now.Add(time.Minute)); err == nil {
		t.Fatal("expected generation mismatch")
	}
	if err := session.Validate("agent-a", 4, "wait", now.Add(time.Minute)); err == nil {
		t.Fatal("expected method mismatch")
	}
	if err := session.Validate("agent-a", 4, "send", now.Add(16*time.Minute)); err == nil {
		t.Fatal("expected expiry")
	}
}
