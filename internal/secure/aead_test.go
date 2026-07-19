package secure

import (
	"context"
	"testing"
)

func TestAEADRoundTrip(t *testing.T) {
	service := NewAEAD(StaticKeyProvider([]byte("0123456789abcdef0123456789abcdef")))
	ctx := context.Background()
	plaintext := []byte("pairing secret")
	associatedData := []byte("agent-a:outbox")

	ciphertext, err := service.Encrypt(ctx, plaintext, associatedData)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ciphertext) == string(plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	restored, err := service.Decrypt(ctx, ciphertext, associatedData)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(restored) != string(plaintext) {
		t.Fatalf("unexpected plaintext: %q", restored)
	}
}

func TestAEADRejectsWrongAssociatedData(t *testing.T) {
	service := NewAEAD(StaticKeyProvider([]byte("0123456789abcdef0123456789abcdef")))
	ciphertext, err := service.Encrypt(context.Background(), []byte("secret"), []byte("agent-a"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := service.Decrypt(context.Background(), ciphertext, []byte("agent-b")); err == nil {
		t.Fatal("decrypt with different associated data must fail")
	}
}

func TestStaticKeyProviderRequiresAES256Key(t *testing.T) {
	provider := StaticKeyProvider([]byte("too-short"))
	if _, err := provider.Key(context.Background()); err == nil {
		t.Fatal("short key must be rejected")
	}
	service := NewAEAD(provider)
	if _, err := service.Encrypt(context.Background(), []byte("secret"), nil); err == nil {
		t.Fatal("encrypt with short key must fail")
	}
	if _, err := service.Decrypt(context.Background(), []byte("ciphertext"), nil); err == nil {
		t.Fatal("decrypt with short key must fail")
	}
}
