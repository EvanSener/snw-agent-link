package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateOutboxKeyIsStableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.key")
	first, err := loadOrCreateOutboxKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateOutboxKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || len(first) != 32 {
		t.Fatal("outbox key is not stable")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("outbox key mode = %o", info.Mode().Perm())
	}
}
