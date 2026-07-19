package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/google/uuid"
)

var (
	ErrAgentIDMismatch  = errors.New("signed envelope agent id mismatch")
	ErrKeyMismatch      = errors.New("signed envelope key fingerprint mismatch")
	ErrInvalidSignature = errors.New("invalid signed envelope signature")
)

type Identity struct {
	agentID    string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func Generate(agentID string) (*Identity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	if agentID == "" {
		agentID = StableAgentID(publicKey)
	}
	return &Identity{agentID: agentID, publicKey: publicKey, privateKey: privateKey}, nil
}

func FromPrivateKey(agentID string, privateKey ed25519.PrivateKey) (*Identity, error) {
	if agentID == "" {
		return nil, errors.New("agent id is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &Identity{agentID: agentID, publicKey: publicKey, privateKey: privateKey}, nil
}

func (i *Identity) AgentID() string { return i.agentID }

func (i *Identity) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), i.publicKey...)
}

func (i *Identity) PrivateKey() ed25519.PrivateKey {
	return append(ed25519.PrivateKey(nil), i.privateKey...)
}

func (i *Identity) Sign(claimedAgentID, kind string, payload []byte) (model.SignedEnvelope, error) {
	envelope := model.SignedEnvelope{
		AgentID:        claimedAgentID,
		KeyFingerprint: Fingerprint(i.publicKey),
		Kind:           kind,
		Payload:        append([]byte(nil), payload...),
		IssuedAt:       time.Now().UTC().UnixMilli(),
		Nonce:          uuid.NewString(),
	}
	content, err := signingBytes(envelope)
	if err != nil {
		return model.SignedEnvelope{}, err
	}
	envelope.Signature = ed25519.Sign(i.privateKey, content)
	return envelope, nil
}

func VerifyEnvelope(envelope model.SignedEnvelope, expectedPublicKey ed25519.PublicKey) error {
	if envelope.KeyFingerprint != Fingerprint(expectedPublicKey) {
		return ErrKeyMismatch
	}
	content, err := signingBytes(envelope)
	if err != nil {
		return err
	}
	if !ed25519.Verify(expectedPublicKey, content, envelope.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func VerifyEnvelopeForAgent(envelope model.SignedEnvelope, expectedAgentID string, expectedPublicKey ed25519.PublicKey) error {
	if envelope.AgentID != expectedAgentID {
		return ErrAgentIDMismatch
	}
	return VerifyEnvelope(envelope, expectedPublicKey)
}

func Fingerprint(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func StableAgentID(publicKey ed25519.PublicKey) string {
	domainSeparated := append([]byte("snw-agent-id-v1\x00"), publicKey...)
	digest := sha256.Sum256(domainSeparated)
	return "snw-agent:v1:" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
}

func signingBytes(envelope model.SignedEnvelope) ([]byte, error) {
	unsigned := struct {
		AgentID        string `json:"agentId"`
		KeyFingerprint string `json:"keyFingerprint"`
		Kind           string `json:"kind"`
		Payload        []byte `json:"payload"`
		IssuedAt       int64  `json:"issuedAt"`
		Nonce          string `json:"nonce"`
	}{
		AgentID:        envelope.AgentID,
		KeyFingerprint: envelope.KeyFingerprint,
		Kind:           envelope.Kind,
		Payload:        envelope.Payload,
		IssuedAt:       envelope.IssuedAt,
		Nonce:          envelope.Nonce,
	}
	content, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("marshal signed envelope: %w", err)
	}
	return content, nil
}
