package admission

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/store"
	"github.com/google/uuid"
)

var (
	ErrContactNotActive          = errors.New("contact is not active")
	ErrHostFingerprintMismatch   = errors.New("remote host fingerprint mismatch")
	ErrAgentFingerprintMismatch  = errors.New("remote agent fingerprint mismatch")
	ErrEnvelopeOutsideTimeWindow = errors.New("signed envelope is outside the accepted time window")
	ErrReplayDetected            = errors.New("signed envelope replay detected")
)

type Input struct {
	LocalAgentID          string
	RemoteHostFingerprint string
	RemotePublicKey       ed25519.PublicKey
	Envelope              model.SignedEnvelope
}

type Service struct {
	database    *store.Store
	clock       func() time.Time
	allowedSkew time.Duration
}

func NewService(database *store.Store, clock func() time.Time, allowedSkew time.Duration) *Service {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if allowedSkew <= 0 {
		allowedSkew = 5 * time.Minute
	}
	return &Service{database: database, clock: clock, allowedSkew: allowedSkew}
}

func (s *Service) Authorize(ctx context.Context, input Input) (resultErr error) {
	remoteAgentID := input.Envelope.AgentID
	requestID := input.Envelope.Nonce
	defer func() {
		outcome := "allowed"
		if resultErr != nil {
			outcome = "denied"
		}
		auditErr := s.database.AppendAuditEntry(ctx, model.AuditEntry{
			ID:            uuid.NewString(),
			ActorAgentID:  input.LocalAgentID,
			RemoteAgentID: remoteAgentID,
			Action:        "admission.authorize",
			Outcome:       outcome,
			RequestID:     requestID,
			CreatedAt:     s.clock(),
		})
		if resultErr == nil && auditErr != nil {
			resultErr = fmt.Errorf("record admission audit: %w", auditErr)
		}
	}()

	contact, err := s.database.GetContact(ctx, input.LocalAgentID, remoteAgentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrContactNotActive
		}
		return fmt.Errorf("load contact: %w", err)
	}
	if contact.State != model.ContactStateActive {
		return ErrContactNotActive
	}
	if input.RemoteHostFingerprint != "" && contact.RemoteHostFingerprint != "" && contact.RemoteHostFingerprint != input.RemoteHostFingerprint {
		return ErrHostFingerprintMismatch
	}
	if contact.RemoteAgentFingerprint != identity.Fingerprint(input.RemotePublicKey) {
		return ErrAgentFingerprintMismatch
	}
	if err := identity.VerifyEnvelopeForAgent(input.Envelope, contact.RemoteAgentID, input.RemotePublicKey); err != nil {
		return fmt.Errorf("verify signed envelope: %w", err)
	}
	now := s.clock().UTC()
	issuedAt := time.UnixMilli(input.Envelope.IssuedAt).UTC()
	if issuedAt.Before(now.Add(-s.allowedSkew)) || issuedAt.After(now.Add(s.allowedSkew)) {
		return ErrEnvelopeOutsideTimeWindow
	}
	claimed, err := s.database.ClaimReplayNonce(
		ctx,
		input.LocalAgentID,
		remoteAgentID,
		input.Envelope.Nonce,
		issuedAt.Add(s.allowedSkew),
		now,
	)
	if err != nil {
		return fmt.Errorf("claim replay nonce: %w", err)
	}
	if !claimed {
		return ErrReplayDetected
	}
	return nil
}

func canonicalEnvelopeBytes(value any) ([]byte, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal signed envelope: %w", err)
	}
	return content, nil
}
