package identitystore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvanSener/snw-agent-link/internal/capability"
	"github.com/EvanSener/snw-agent-link/internal/identity"
)

func TestFileStoreRoundTripUsesPrivatePermissions(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileStore(filepath.Join(root, "identities"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := identity.Generate("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutIdentity(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetIdentity(context.Background(), "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID() != want.AgentID() || string(got.PrivateKey()) != string(want.PrivateKey()) {
		t.Fatal("identity round trip mismatch")
	}
	info, err := os.Stat(filepath.Join(root, "identities"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("identity directory mode = %o", info.Mode().Perm())
	}
	info, err = os.Stat(filepath.Join(root, "identities", "agent-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity file mode = %o", info.Mode().Perm())
	}
}

func TestFileStoreMissingIdentity(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "identities"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetIdentity(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFileStoreCapabilityRoundTrip(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileStore(filepath.Join(root, "identities"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := capability.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutCapabilityKey(context.Background(), "agent-a", key); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetCapabilityKey(context.Background(), "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Private()) != string(key.Private()) {
		t.Fatal("capability key round trip mismatch")
	}
	info, err := os.Stat(filepath.Join(root, "identities", "agent-a.capability.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("capability file mode = %o", info.Mode().Perm())
	}
}
