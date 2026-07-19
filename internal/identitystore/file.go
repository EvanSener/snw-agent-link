package identitystore

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/EvanSener/snw-agent-link/internal/capability"
	"github.com/EvanSener/snw-agent-link/internal/identity"
)

var ErrNotFound = errors.New("identity not found")

type FileStore struct {
	root string
}

type record struct {
	AgentID    string `json:"agentId"`
	PrivateKey string `json:"privateKey"`
}

func NewFileStore(root string) (*FileStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("identity store directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create identity store directory: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("secure identity store directory: %w", err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) GetIdentity(ctx context.Context, agentID string) (*identity.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(agentID) == "" {
		return nil, errors.New("agent id is required")
	}
	data, err := os.ReadFile(s.path(agentID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read agent identity: %w", err)
	}
	var value record
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode agent identity: %w", err)
	}
	if value.AgentID != agentID || value.PrivateKey == "" {
		return nil, errors.New("invalid agent identity record")
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(value.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid agent identity private key")
	}
	result, err := identity.FromPrivateKey(agentID, ed25519.PrivateKey(privateKey))
	if err != nil {
		return nil, fmt.Errorf("restore agent identity: %w", err)
	}
	return result, nil
}

func (s *FileStore) PutIdentity(ctx context.Context, value *identity.Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if value == nil || strings.TrimSpace(value.AgentID()) == "" {
		return errors.New("agent identity is required")
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return fmt.Errorf("create identity store directory: %w", err)
	}
	payload, err := json.Marshal(record{
		AgentID:    value.AgentID(),
		PrivateKey: base64.RawURLEncoding.EncodeToString(value.PrivateKey()),
	})
	if err != nil {
		return fmt.Errorf("encode agent identity: %w", err)
	}
	temporary, err := os.CreateTemp(s.root, ".identity-*")
	if err != nil {
		return fmt.Errorf("create temporary identity: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary identity: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write agent identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync agent identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close agent identity: %w", err)
	}
	if err := os.Rename(temporaryName, s.path(value.AgentID())); err != nil {
		return fmt.Errorf("install agent identity: %w", err)
	}
	return os.Chmod(s.path(value.AgentID()), 0o600)
}

func (s *FileStore) GetCapabilityKey(ctx context.Context, agentID string) (capability.Key, error) {
	if err := ctx.Err(); err != nil {
		return capability.Key{}, err
	}
	data, err := os.ReadFile(s.capabilityPath(agentID))
	if errors.Is(err, os.ErrNotExist) {
		return capability.Key{}, ErrNotFound
	}
	if err != nil {
		return capability.Key{}, fmt.Errorf("read capability key: %w", err)
	}
	var value record
	if err := json.Unmarshal(data, &value); err != nil || value.AgentID != agentID || value.PrivateKey == "" {
		return capability.Key{}, errors.New("invalid capability key record")
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(value.PrivateKey)
	if err != nil {
		return capability.Key{}, errors.New("invalid capability private key")
	}
	return capability.FromPrivate(ed25519.PrivateKey(privateKey))
}

func (s *FileStore) PutCapabilityKey(ctx context.Context, agentID string, key capability.Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(agentID) == "" {
		return errors.New("agent id is required")
	}
	payload, err := json.Marshal(record{AgentID: agentID, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Private())})
	if err != nil {
		return fmt.Errorf("encode capability key: %w", err)
	}
	return s.writeSecret(s.capabilityPath(agentID), payload)
}

func (s *FileStore) writeSecret(path string, payload []byte) error {
	temporary, err := os.CreateTemp(s.root, ".secret-*")
	if err != nil {
		return fmt.Errorf("create temporary secret: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("install secret: %w", err)
	}
	return os.Chmod(path, 0o600)
}

func (s *FileStore) path(agentID string) string {
	return filepath.Join(s.root, filepath.Base(agentID)+".json")
}

func (s *FileStore) capabilityPath(agentID string) string {
	return filepath.Join(s.root, filepath.Base(agentID)+".capability.json")
}
