package daemon

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"runtime"
)

func loadOrCreateOutboxKey(path string) ([]byte, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("outbox key must be a regular non-symlink file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			return nil, errors.New("outbox key permissions must be 0600")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect outbox key: %w", err)
	}
	if value, err := os.ReadFile(path); err == nil {
		if len(value) != 32 {
			return nil, errors.New("outbox key must contain 32 bytes")
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read outbox key: %w", err)
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("generate outbox key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateOutboxKey(path)
		}
		return nil, fmt.Errorf("create outbox key: %w", err)
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write outbox key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return value, nil
}
