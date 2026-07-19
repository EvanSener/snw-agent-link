package capability

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidSignature = errors.New("invalid capability signature")
	ErrExpired          = errors.New("capability session expired")
	ErrGeneration       = errors.New("capability generation mismatch")
	ErrAgent            = errors.New("capability agent mismatch")
	ErrMethod           = errors.New("capability method is not allowed")
)

type Key struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func GenerateKey() (Key, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, fmt.Errorf("generate capability key: %w", err)
	}
	return Key{public: public, private: private}, nil
}

func FromPrivate(private ed25519.PrivateKey) (Key, error) {
	if len(private) != ed25519.PrivateKeySize {
		return Key{}, errors.New("invalid capability private key")
	}
	return Key{public: private.Public().(ed25519.PublicKey), private: append(ed25519.PrivateKey(nil), private...)}, nil
}

func (key Key) Public() ed25519.PublicKey   { return append(ed25519.PublicKey(nil), key.public...) }
func (key Key) Private() ed25519.PrivateKey { return append(ed25519.PrivateKey(nil), key.private...) }

type Challenge struct {
	BootID         string    `json:"bootId"`
	Nonce          string    `json:"nonce"`
	AgentID        string    `json:"agentId"`
	EndpointDigest string    `json:"endpointDigest"`
	Methods        []string  `json:"methods"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

func (key Key) Sign(challenge Challenge) ([]byte, error) {
	if len(key.private) != ed25519.PrivateKeySize {
		return nil, errors.New("capability private key is unavailable")
	}
	content, err := canonical(challenge)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key.private, content), nil
}

func Verify(public ed25519.PublicKey, challenge Challenge, signature []byte) error {
	if len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	content, err := canonical(challenge)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, content, signature) {
		return ErrInvalidSignature
	}
	return nil
}

type Session struct {
	Token      string    `json:"token"`
	AgentID    string    `json:"agentId"`
	Generation uint64    `json:"generation"`
	Methods    []string  `json:"methods"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

func IssueSession(agentID string, generation uint64, methods []string, now time.Time, lifetime time.Duration) Session {
	if lifetime <= 0 {
		lifetime = 15 * time.Minute
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("generate capability session token: %v", err))
	}
	return Session{Token: base64.RawURLEncoding.EncodeToString(bytes), AgentID: agentID, Generation: generation, Methods: append([]string(nil), methods...), ExpiresAt: now.Add(lifetime).UTC()}
}

func (session Session) Validate(agentID string, generation uint64, method string, now time.Time) error {
	if session.AgentID != agentID {
		return ErrAgent
	}
	if session.Generation != generation {
		return ErrGeneration
	}
	if !now.Before(session.ExpiresAt) {
		return ErrExpired
	}
	for _, allowed := range session.Methods {
		if allowed == method {
			return nil
		}
	}
	return ErrMethod
}

func canonical(value Challenge) ([]byte, error) {
	methods := append([]string(nil), value.Methods...)
	sort.Strings(methods)
	value.Methods = methods
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal capability challenge: %w", err)
	}
	return append([]byte("snw-agent-link-capability-v1\x00"), encoded...), nil
}

func PublicFingerprint(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(digest[:]), "=")
}
