package pairing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/store"
	"github.com/google/uuid"
)

const (
	KindPairingInvite            = "pairing.invite"
	KindPairingAcceptance        = "pairing.acceptance"
	KindPairingConfirmation      = "pairing.confirmation"
	KindPairingActivationReceipt = "pairing.activation_receipt"
	KindRevocationNotice         = "contact.revocation"

	pairingRoleInviter = "inviter"
	pairingRoleInvitee = "invitee"
)

var (
	ErrInviteConsumed    = errors.New("pairing invite already consumed")
	ErrInviteExpired     = errors.New("pairing invite expired")
	ErrInvalidSecret     = errors.New("invalid pairing invite secret")
	ErrIdentityMismatch  = errors.New("pairing identity mismatch")
	ErrInvalidTransition = errors.New("invalid contact state transition")
	ErrContactBlocked    = errors.New("contact is blocked")
	ErrInvalidEnvelope   = errors.New("invalid pairing envelope")
)

type Clock func() time.Time

type Service struct {
	store *store.Store
	now   Clock
}

type CreateInviteInput struct {
	RemoteAgentID         string
	LocalHostFingerprint  string
	LocalTailscaleAddress string
	LocalNodeID           string
	TTL                   time.Duration
}

type ApproveAcceptanceInput struct {
	ExpectedHostFingerprint  string
	ExpectedAgentFingerprint string
}

type PairingInvitePayload struct {
	InviteID                 string    `json:"inviteId"`
	InvitingAgentID          string    `json:"invitingAgentId"`
	InvitingAgentPublicKey   []byte    `json:"invitingAgentPublicKey"`
	InvitingHostFingerprint  string    `json:"invitingHostFingerprint"`
	InvitingTailscaleAddress string    `json:"invitingTailscaleAddress"`
	InvitingNodeID           string    `json:"invitingNodeId,omitempty"`
	TargetAgentID            string    `json:"targetAgentId"`
	Secret                   string    `json:"secret"`
	ExpiresAt                time.Time `json:"expiresAt"`
}

type PairingInvite struct {
	Payload  PairingInvitePayload `json:"payload"`
	Envelope model.SignedEnvelope `json:"envelope"`
}

type PairingAcceptancePayload struct {
	InviteID                  string `json:"inviteId"`
	InviteDigest              string `json:"inviteDigest"`
	InvitingAgentID           string `json:"invitingAgentId"`
	AcceptingAgentID          string `json:"acceptingAgentId"`
	AcceptingAgentPublicKey   []byte `json:"acceptingAgentPublicKey"`
	AcceptingHostFingerprint  string `json:"acceptingHostFingerprint"`
	AcceptingTailscaleAddress string `json:"acceptingTailscaleAddress,omitempty"`
	AcceptingNodeID           string `json:"acceptingNodeId,omitempty"`
	SecretProof               string `json:"secretProof"`
}

type PairingAcceptance struct {
	Payload  PairingAcceptancePayload `json:"payload"`
	Envelope model.SignedEnvelope     `json:"envelope"`
}

type PairingConfirmationPayload struct {
	InviteID                 string `json:"inviteId"`
	InviteDigest             string `json:"inviteDigest"`
	AcceptanceDigest         string `json:"acceptanceDigest"`
	InvitingAgentID          string `json:"invitingAgentId"`
	InvitingAgentPublicKey   []byte `json:"invitingAgentPublicKey"`
	InvitingHostFingerprint  string `json:"invitingHostFingerprint"`
	AcceptingAgentID         string `json:"acceptingAgentId"`
	AcceptingAgentPublicKey  []byte `json:"acceptingAgentPublicKey"`
	AcceptingHostFingerprint string `json:"acceptingHostFingerprint"`
}

type PairingConfirmation struct {
	Payload  PairingConfirmationPayload `json:"payload"`
	Envelope model.SignedEnvelope       `json:"envelope"`
}

type PairingActivationReceiptPayload struct {
	InviteID                 string `json:"inviteId"`
	ConfirmationDigest       string `json:"confirmationDigest"`
	InvitingAgentID          string `json:"invitingAgentId"`
	AcceptingAgentID         string `json:"acceptingAgentId"`
	AcceptingAgentPublicKey  []byte `json:"acceptingAgentPublicKey"`
	AcceptingHostFingerprint string `json:"acceptingHostFingerprint"`
}

type PairingActivationReceipt struct {
	Payload  PairingActivationReceiptPayload `json:"payload"`
	Envelope model.SignedEnvelope            `json:"envelope"`
}

type RevocationNoticePayload struct {
	RevokingAgentID         string    `json:"revokingAgentId"`
	RevokingAgentPublicKey  []byte    `json:"revokingAgentPublicKey"`
	RevokingHostFingerprint string    `json:"revokingHostFingerprint"`
	TargetAgentID           string    `json:"targetAgentId"`
	Reason                  string    `json:"reason,omitempty"`
	RevokedAt               time.Time `json:"revokedAt"`
}

type RevocationNotice struct {
	Payload  RevocationNoticePayload `json:"payload"`
	Envelope model.SignedEnvelope    `json:"envelope"`
}

func NewService(database *store.Store, clock Clock) *Service {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Service{store: database, now: clock}
}

func (s *Service) Store() *store.Store { return s.store }

func (s *Service) CreateInvite(ctx context.Context, localIdentity *identity.Identity, input CreateInviteInput) (PairingInvite, error) {
	if localIdentity == nil || input.RemoteAgentID == "" || input.LocalTailscaleAddress == "" {
		return PairingInvite{}, errors.New("pairing invite identity and Tailscale address are required")
	}
	if input.RemoteAgentID == localIdentity.AgentID() {
		return PairingInvite{}, errors.New("cannot pair an agent with itself")
	}
	if input.TTL <= 0 {
		return PairingInvite{}, errors.New("pairing invite ttl must be positive")
	}
	if err := s.rejectBlockedContact(ctx, localIdentity.AgentID(), input.RemoteAgentID); err != nil {
		return PairingInvite{}, err
	}

	secret, err := randomSecret(32)
	if err != nil {
		return PairingInvite{}, err
	}
	now := s.now().UTC()
	payload := PairingInvitePayload{
		InviteID:                 uuid.NewString(),
		InvitingAgentID:          localIdentity.AgentID(),
		InvitingAgentPublicKey:   localIdentity.PublicKey(),
		InvitingHostFingerprint:  input.LocalHostFingerprint,
		InvitingTailscaleAddress: input.LocalTailscaleAddress,
		InvitingNodeID:           strings.TrimSpace(input.LocalNodeID),
		TargetAgentID:            input.RemoteAgentID,
		Secret:                   secret,
		ExpiresAt:                now.Add(input.TTL),
	}
	envelope, err := signPayload(localIdentity, KindPairingInvite, payload)
	if err != nil {
		return PairingInvite{}, err
	}
	invite := PairingInvite{Payload: payload, Envelope: envelope}
	inviteDigest, err := digestEnvelope(envelope)
	if err != nil {
		return PairingInvite{}, err
	}
	request := model.PairingRequest{
		ID:            payload.InviteID,
		LocalAgentID:  payload.InvitingAgentID,
		RemoteAgentID: payload.TargetAgentID,
		SecretHash:    hashSecret(payload.Secret),
		ExpiresAt:     payload.ExpiresAt,
		CreatedAt:     now,
	}
	if err := s.store.CreatePairingRequest(ctx, request); err != nil {
		return PairingInvite{}, err
	}
	if err := s.store.UpsertPairingSession(ctx, model.PairingSession{
		InviteID:             payload.InviteID,
		LocalAgentID:         payload.InvitingAgentID,
		RemoteAgentID:        payload.TargetAgentID,
		Role:                 pairingRoleInviter,
		LocalHostFingerprint: payload.InvitingHostFingerprint,
		InviteDigest:         inviteDigest,
		ExpiresAt:            payload.ExpiresAt,
		CreatedAt:            now,
	}); err != nil {
		return PairingInvite{}, err
	}
	if err := s.store.UpsertContact(ctx, model.Contact{
		LocalAgentID:  payload.InvitingAgentID,
		RemoteAgentID: payload.TargetAgentID,
		State:         model.ContactStatePendingOutbound,
	}); err != nil {
		return PairingInvite{}, err
	}
	return invite, nil
}

func (s *Service) ImportInvite(ctx context.Context, localIdentity *identity.Identity, invite PairingInvite) (model.Contact, error) {
	if localIdentity == nil {
		return model.Contact{}, errors.New("local identity is required")
	}
	if _, err := s.store.GetPairingRequestForAgent(ctx, invite.Payload.InviteID, localIdentity.AgentID()); err == nil {
		return model.Contact{}, ErrInviteConsumed
	} else if !errors.Is(err, store.ErrNotFound) {
		return model.Contact{}, err
	}
	if invite.Payload.TargetAgentID != localIdentity.AgentID() || invite.Payload.InvitingAgentID == "" {
		return model.Contact{}, ErrIdentityMismatch
	}
	if err := s.rejectBlockedContact(ctx, localIdentity.AgentID(), invite.Payload.InvitingAgentID); err != nil {
		return model.Contact{}, err
	}
	if !s.now().UTC().Before(invite.Payload.ExpiresAt) {
		return model.Contact{}, ErrInviteExpired
	}
	inviterPublicKey, err := publicKey(invite.Payload.InvitingAgentPublicKey)
	if err != nil {
		return model.Contact{}, ErrIdentityMismatch
	}
	if err := verifyPayload(invite.Envelope, KindPairingInvite, invite.Payload, invite.Payload.InvitingAgentID, inviterPublicKey); err != nil {
		return model.Contact{}, err
	}
	inviteDigest, err := digestEnvelope(invite.Envelope)
	if err != nil {
		return model.Contact{}, err
	}
	now := s.now().UTC()
	request := model.PairingRequest{
		ID:                     invite.Payload.InviteID,
		LocalAgentID:           localIdentity.AgentID(),
		RemoteAgentID:          invite.Payload.InvitingAgentID,
		RemoteHostFingerprint:  invite.Payload.InvitingHostFingerprint,
		RemoteAgentFingerprint: identity.Fingerprint(inviterPublicKey),
		SecretHash:             hashSecret(invite.Payload.Secret),
		ExpiresAt:              invite.Payload.ExpiresAt,
		CreatedAt:              now,
	}
	if err := s.store.CreatePairingRequest(ctx, request); err != nil {
		if _, lookupErr := s.store.GetPairingRequestForAgent(ctx, request.ID, request.LocalAgentID); lookupErr == nil {
			return model.Contact{}, ErrInviteConsumed
		}
		return model.Contact{}, err
	}
	if err := s.store.UpsertPairingSession(ctx, model.PairingSession{
		InviteID:              request.ID,
		LocalAgentID:          request.LocalAgentID,
		RemoteAgentID:         request.RemoteAgentID,
		Role:                  pairingRoleInvitee,
		RemoteHostFingerprint: request.RemoteHostFingerprint,
		RemoteAgentPublicKey:  inviterPublicKey,
		InviteDigest:          inviteDigest,
		ExpiresAt:             request.ExpiresAt,
		CreatedAt:             now,
	}); err != nil {
		return model.Contact{}, err
	}
	contact := model.Contact{
		LocalAgentID:           request.LocalAgentID,
		RemoteAgentID:          request.RemoteAgentID,
		RemoteEndpoint:         endpointForAgent(invite.Payload.InvitingTailscaleAddress, request.RemoteAgentID),
		RemoteBinding:          strings.TrimSpace(invite.Payload.InvitingTailscaleAddress),
		RemoteNodeID:           strings.TrimSpace(invite.Payload.InvitingNodeID),
		RemoteHostFingerprint:  request.RemoteHostFingerprint,
		RemoteAgentFingerprint: request.RemoteAgentFingerprint,
		State:                  model.ContactStatePendingInbound,
	}
	if err := s.store.UpsertContact(ctx, contact); err != nil {
		return model.Contact{}, err
	}
	return s.store.GetContact(ctx, contact.LocalAgentID, contact.RemoteAgentID)
}

func (s *Service) AcceptImportedInvite(ctx context.Context, localIdentity *identity.Identity, localHostFingerprint string) (PairingAcceptance, error) {
	return s.acceptImportedInvite(ctx, localIdentity, "", localHostFingerprint, "", "")
}

func (s *Service) AcceptImportedInviteByID(ctx context.Context, localIdentity *identity.Identity, inviteID, localHostFingerprint string) (PairingAcceptance, error) {
	return s.acceptImportedInvite(ctx, localIdentity, inviteID, localHostFingerprint, "", "")
}

func (s *Service) AcceptImportedInviteByIDAndAddress(ctx context.Context, localIdentity *identity.Identity, inviteID, localHostFingerprint, tailscaleAddress string) (PairingAcceptance, error) {
	return s.acceptImportedInvite(ctx, localIdentity, inviteID, localHostFingerprint, tailscaleAddress, "")
}

func (s *Service) AcceptImportedInviteAndAddress(ctx context.Context, localIdentity *identity.Identity, localHostFingerprint, tailscaleAddress string) (PairingAcceptance, error) {
	return s.acceptImportedInvite(ctx, localIdentity, "", localHostFingerprint, tailscaleAddress, "")
}

func (s *Service) AcceptImportedInviteByIDAndAddressAndNode(ctx context.Context, localIdentity *identity.Identity, inviteID, localHostFingerprint, tailscaleAddress, nodeID string) (PairingAcceptance, error) {
	return s.acceptImportedInvite(ctx, localIdentity, inviteID, localHostFingerprint, tailscaleAddress, nodeID)
}

func (s *Service) AcceptImportedInviteAndAddressAndNode(ctx context.Context, localIdentity *identity.Identity, localHostFingerprint, tailscaleAddress, nodeID string) (PairingAcceptance, error) {
	return s.acceptImportedInvite(ctx, localIdentity, "", localHostFingerprint, tailscaleAddress, nodeID)
}

func (s *Service) acceptImportedInvite(ctx context.Context, localIdentity *identity.Identity, inviteID, localHostFingerprint, tailscaleAddress, nodeID string) (PairingAcceptance, error) {
	if localIdentity == nil {
		return PairingAcceptance{}, errors.New("local identity is required")
	}
	contacts, err := s.store.ListContacts(ctx, localIdentity.AgentID())
	if err != nil {
		return PairingAcceptance{}, err
	}
	var contact model.Contact
	if inviteID != "" {
		session, sessionErr := s.store.GetPairingSession(ctx, inviteID, localIdentity.AgentID())
		if sessionErr != nil {
			return PairingAcceptance{}, sessionErr
		}
		contact, err = s.store.GetContact(ctx, localIdentity.AgentID(), session.RemoteAgentID)
		if err != nil {
			return PairingAcceptance{}, err
		}
		if contact.State != model.ContactStatePendingInbound {
			return PairingAcceptance{}, fmt.Errorf("%w: invite is not pending", ErrInvalidTransition)
		}
	} else {
		pendingCount := 0
		for _, candidate := range contacts {
			if candidate.State == model.ContactStatePendingInbound {
				pendingCount++
				contact = candidate
			}
		}
		if pendingCount > 1 {
			return PairingAcceptance{}, fmt.Errorf("%w: invite id is required when multiple invites are pending", ErrInvalidTransition)
		}
	}
	if contact.LocalAgentID == "" {
		return PairingAcceptance{}, fmt.Errorf("%w: no pending inbound invite", ErrInvalidTransition)
	}
	session, err := s.store.FindPairingSession(ctx, localIdentity.AgentID(), contact.RemoteAgentID)
	if err != nil {
		return PairingAcceptance{}, err
	}
	now := s.now().UTC()
	request, consumed, err := s.store.ValidateAndConsumePairingRequestForAgent(ctx, session.InviteID, localIdentity.AgentID(), now, func(request model.PairingRequest) error {
		if !now.Before(request.ExpiresAt) {
			return ErrInviteExpired
		}
		return nil
	})
	if err != nil {
		return PairingAcceptance{}, err
	}
	if !consumed {
		return PairingAcceptance{}, ErrInviteConsumed
	}
	payload := PairingAcceptancePayload{
		InviteID:                  request.ID,
		InviteDigest:              session.InviteDigest,
		InvitingAgentID:           request.RemoteAgentID,
		AcceptingAgentID:          localIdentity.AgentID(),
		AcceptingAgentPublicKey:   localIdentity.PublicKey(),
		AcceptingHostFingerprint:  localHostFingerprint,
		AcceptingTailscaleAddress: strings.TrimSpace(tailscaleAddress),
		AcceptingNodeID:           strings.TrimSpace(nodeID),
		SecretProof:               acceptanceSecretProof(request.SecretHash, session.InviteDigest, localIdentity.AgentID(), localHostFingerprint, identity.Fingerprint(localIdentity.PublicKey())),
	}
	envelope, err := signPayload(localIdentity, KindPairingAcceptance, payload)
	if err != nil {
		return PairingAcceptance{}, err
	}
	acceptanceDigest, err := digestEnvelope(envelope)
	if err != nil {
		return PairingAcceptance{}, err
	}
	session.LocalHostFingerprint = localHostFingerprint
	session.AcceptanceDigest = acceptanceDigest
	if err := s.store.UpsertPairingSession(ctx, session); err != nil {
		return PairingAcceptance{}, err
	}
	contact.State = model.ContactStateAwaitingConfirmation
	if err := s.store.UpsertContact(ctx, contact); err != nil {
		return PairingAcceptance{}, err
	}
	return PairingAcceptance{Payload: payload, Envelope: envelope}, nil
}

func (s *Service) ApproveAcceptance(ctx context.Context, localIdentity *identity.Identity, acceptance PairingAcceptance, approval ApproveAcceptanceInput) (PairingConfirmation, error) {
	if localIdentity == nil || approval.ExpectedAgentFingerprint == "" {
		return PairingConfirmation{}, errors.New("local identity and expected remote agent fingerprint are required")
	}
	acceptingPublicKey, err := publicKey(acceptance.Payload.AcceptingAgentPublicKey)
	if err != nil {
		return PairingConfirmation{}, ErrIdentityMismatch
	}
	if (approval.ExpectedHostFingerprint != "" && acceptance.Payload.AcceptingHostFingerprint != approval.ExpectedHostFingerprint) || identity.Fingerprint(acceptingPublicKey) != approval.ExpectedAgentFingerprint {
		return PairingConfirmation{}, ErrIdentityMismatch
	}
	if err := verifyPayload(acceptance.Envelope, KindPairingAcceptance, acceptance.Payload, acceptance.Payload.AcceptingAgentID, acceptingPublicKey); err != nil {
		return PairingConfirmation{}, err
	}
	request, err := s.store.GetPairingRequestForAgent(ctx, acceptance.Payload.InviteID, localIdentity.AgentID())
	if err != nil {
		return PairingConfirmation{}, err
	}
	session, err := s.store.GetPairingSession(ctx, acceptance.Payload.InviteID, localIdentity.AgentID())
	if err != nil {
		return PairingConfirmation{}, err
	}
	if session.Role != pairingRoleInviter || request.LocalAgentID != localIdentity.AgentID() || request.RemoteAgentID != acceptance.Payload.AcceptingAgentID || acceptance.Payload.InvitingAgentID != localIdentity.AgentID() || acceptance.Payload.InviteDigest != session.InviteDigest {
		return PairingConfirmation{}, ErrIdentityMismatch
	}
	expectedProof := acceptanceSecretProof(request.SecretHash, session.InviteDigest, acceptance.Payload.AcceptingAgentID, acceptance.Payload.AcceptingHostFingerprint, identity.Fingerprint(acceptingPublicKey))
	if subtle.ConstantTimeCompare([]byte(expectedProof), []byte(acceptance.Payload.SecretProof)) != 1 {
		return PairingConfirmation{}, ErrInvalidSecret
	}
	now := s.now().UTC()
	_, consumed, err := s.store.ValidateAndConsumePairingRequestForAgent(ctx, request.ID, localIdentity.AgentID(), now, func(value model.PairingRequest) error {
		if !now.Before(value.ExpiresAt) {
			return ErrInviteExpired
		}
		return nil
	})
	if err != nil {
		return PairingConfirmation{}, err
	}
	if !consumed {
		return PairingConfirmation{}, ErrInviteConsumed
	}
	acceptanceDigest, err := digestEnvelope(acceptance.Envelope)
	if err != nil {
		return PairingConfirmation{}, err
	}
	payload := PairingConfirmationPayload{
		InviteID:                 request.ID,
		InviteDigest:             session.InviteDigest,
		AcceptanceDigest:         acceptanceDigest,
		InvitingAgentID:          localIdentity.AgentID(),
		InvitingAgentPublicKey:   localIdentity.PublicKey(),
		InvitingHostFingerprint:  session.LocalHostFingerprint,
		AcceptingAgentID:         acceptance.Payload.AcceptingAgentID,
		AcceptingAgentPublicKey:  acceptingPublicKey,
		AcceptingHostFingerprint: acceptance.Payload.AcceptingHostFingerprint,
	}
	envelope, err := signPayload(localIdentity, KindPairingConfirmation, payload)
	if err != nil {
		return PairingConfirmation{}, err
	}
	confirmationDigest, err := digestEnvelope(envelope)
	if err != nil {
		return PairingConfirmation{}, err
	}
	session.RemoteHostFingerprint = payload.AcceptingHostFingerprint
	session.RemoteAgentPublicKey = acceptingPublicKey
	session.AcceptanceDigest = acceptanceDigest
	session.ConfirmationDigest = confirmationDigest
	if err := s.store.UpsertPairingSession(ctx, session); err != nil {
		return PairingConfirmation{}, err
	}
	if err := s.store.UpsertContact(ctx, model.Contact{
		LocalAgentID:           localIdentity.AgentID(),
		RemoteAgentID:          payload.AcceptingAgentID,
		RemoteEndpoint:         endpointForAgent(acceptance.Payload.AcceptingTailscaleAddress, payload.AcceptingAgentID),
		RemoteBinding:          strings.TrimSpace(acceptance.Payload.AcceptingTailscaleAddress),
		RemoteNodeID:           strings.TrimSpace(acceptance.Payload.AcceptingNodeID),
		RemoteHostFingerprint:  payload.AcceptingHostFingerprint,
		RemoteAgentFingerprint: identity.Fingerprint(acceptingPublicKey),
		State:                  model.ContactStateAwaitingConfirmation,
	}); err != nil {
		if errors.Is(err, store.ErrIdentityConflict) {
			return PairingConfirmation{}, ErrIdentityMismatch
		}
		return PairingConfirmation{}, err
	}
	return PairingConfirmation{Payload: payload, Envelope: envelope}, nil
}

func (s *Service) ApplyConfirmation(ctx context.Context, localIdentity *identity.Identity, confirmation PairingConfirmation) (PairingActivationReceipt, error) {
	if localIdentity == nil {
		return PairingActivationReceipt{}, errors.New("local identity is required")
	}
	session, err := s.store.GetPairingSession(ctx, confirmation.Payload.InviteID, localIdentity.AgentID())
	if err != nil {
		return PairingActivationReceipt{}, err
	}
	invitingPublicKey, err := publicKey(confirmation.Payload.InvitingAgentPublicKey)
	if err != nil || !bytes.Equal(invitingPublicKey, session.RemoteAgentPublicKey) {
		return PairingActivationReceipt{}, ErrIdentityMismatch
	}
	if err := verifyPayload(confirmation.Envelope, KindPairingConfirmation, confirmation.Payload, confirmation.Payload.InvitingAgentID, invitingPublicKey); err != nil {
		return PairingActivationReceipt{}, err
	}
	acceptingPublicKey, err := publicKey(confirmation.Payload.AcceptingAgentPublicKey)
	if err != nil {
		return PairingActivationReceipt{}, ErrIdentityMismatch
	}
	if session.Role != pairingRoleInvitee || confirmation.Payload.InvitingAgentID != session.RemoteAgentID || confirmation.Payload.AcceptingAgentID != localIdentity.AgentID() || !bytes.Equal(acceptingPublicKey, localIdentity.PublicKey()) || confirmation.Payload.InvitingHostFingerprint != session.RemoteHostFingerprint || confirmation.Payload.AcceptingHostFingerprint != session.LocalHostFingerprint || confirmation.Payload.InviteDigest != session.InviteDigest || confirmation.Payload.AcceptanceDigest != session.AcceptanceDigest {
		return PairingActivationReceipt{}, ErrIdentityMismatch
	}
	confirmationDigest, err := digestEnvelope(confirmation.Envelope)
	if err != nil {
		return PairingActivationReceipt{}, err
	}
	session.ConfirmationDigest = confirmationDigest
	if err := s.store.UpsertPairingSession(ctx, session); err != nil {
		return PairingActivationReceipt{}, err
	}
	contact, err := s.store.GetContact(ctx, localIdentity.AgentID(), session.RemoteAgentID)
	if err != nil {
		return PairingActivationReceipt{}, err
	}
	if contact.State != model.ContactStateAwaitingConfirmation {
		return PairingActivationReceipt{}, fmt.Errorf("%w: %s to active", ErrInvalidTransition, contact.State)
	}
	contact.State = model.ContactStateActive
	if err := s.store.UpsertContact(ctx, contact); err != nil {
		return PairingActivationReceipt{}, err
	}
	payload := PairingActivationReceiptPayload{
		InviteID:                 session.InviteID,
		ConfirmationDigest:       confirmationDigest,
		InvitingAgentID:          session.RemoteAgentID,
		AcceptingAgentID:         localIdentity.AgentID(),
		AcceptingAgentPublicKey:  localIdentity.PublicKey(),
		AcceptingHostFingerprint: session.LocalHostFingerprint,
	}
	envelope, err := signPayload(localIdentity, KindPairingActivationReceipt, payload)
	if err != nil {
		return PairingActivationReceipt{}, err
	}
	return PairingActivationReceipt{Payload: payload, Envelope: envelope}, nil
}

func (s *Service) ApplyActivationReceipt(ctx context.Context, localIdentity *identity.Identity, receipt PairingActivationReceipt) (model.Contact, error) {
	if localIdentity == nil {
		return model.Contact{}, errors.New("local identity is required")
	}
	session, err := s.store.GetPairingSession(ctx, receipt.Payload.InviteID, localIdentity.AgentID())
	if err != nil {
		return model.Contact{}, err
	}
	acceptingPublicKey, err := publicKey(receipt.Payload.AcceptingAgentPublicKey)
	if err != nil || !bytes.Equal(acceptingPublicKey, session.RemoteAgentPublicKey) {
		return model.Contact{}, ErrIdentityMismatch
	}
	if err := verifyPayload(receipt.Envelope, KindPairingActivationReceipt, receipt.Payload, receipt.Payload.AcceptingAgentID, acceptingPublicKey); err != nil {
		return model.Contact{}, err
	}
	if session.Role != pairingRoleInviter || receipt.Payload.InvitingAgentID != localIdentity.AgentID() || receipt.Payload.AcceptingAgentID != session.RemoteAgentID || receipt.Payload.AcceptingHostFingerprint != session.RemoteHostFingerprint || receipt.Payload.ConfirmationDigest != session.ConfirmationDigest {
		return model.Contact{}, ErrIdentityMismatch
	}
	contact, err := s.store.GetContact(ctx, localIdentity.AgentID(), session.RemoteAgentID)
	if err != nil {
		return model.Contact{}, err
	}
	if contact.State != model.ContactStateAwaitingConfirmation {
		return model.Contact{}, fmt.Errorf("%w: %s to active", ErrInvalidTransition, contact.State)
	}
	contact.State = model.ContactStateActive
	if err := s.store.UpsertContact(ctx, contact); err != nil {
		return model.Contact{}, err
	}
	return s.store.GetContact(ctx, contact.LocalAgentID, contact.RemoteAgentID)
}

func (s *Service) RevokeWithNotice(ctx context.Context, localIdentity *identity.Identity, remoteAgentID, reason string) (RevocationNotice, model.Contact, error) {
	if localIdentity == nil {
		return RevocationNotice{}, model.Contact{}, errors.New("local identity is required")
	}
	contact, err := s.Revoke(ctx, localIdentity.AgentID(), remoteAgentID)
	if err != nil {
		return RevocationNotice{}, model.Contact{}, err
	}
	session, err := s.store.FindPairingSession(ctx, localIdentity.AgentID(), remoteAgentID)
	if err != nil {
		return RevocationNotice{}, model.Contact{}, err
	}
	payload := RevocationNoticePayload{
		RevokingAgentID:         localIdentity.AgentID(),
		RevokingAgentPublicKey:  localIdentity.PublicKey(),
		RevokingHostFingerprint: session.LocalHostFingerprint,
		TargetAgentID:           remoteAgentID,
		Reason:                  reason,
		RevokedAt:               s.now().UTC(),
	}
	envelope, err := signPayload(localIdentity, KindRevocationNotice, payload)
	if err != nil {
		return RevocationNotice{}, model.Contact{}, err
	}
	return RevocationNotice{Payload: payload, Envelope: envelope}, contact, nil
}

func (s *Service) ApplyRevocation(ctx context.Context, localIdentity *identity.Identity, notice RevocationNotice) (model.Contact, error) {
	if localIdentity == nil || notice.Payload.TargetAgentID != localIdentity.AgentID() {
		return model.Contact{}, ErrIdentityMismatch
	}
	contact, err := s.store.GetContact(ctx, localIdentity.AgentID(), notice.Payload.RevokingAgentID)
	if err != nil {
		return model.Contact{}, err
	}
	revokingPublicKey, err := publicKey(notice.Payload.RevokingAgentPublicKey)
	if err != nil || notice.Payload.RevokingHostFingerprint != contact.RemoteHostFingerprint || identity.Fingerprint(revokingPublicKey) != contact.RemoteAgentFingerprint {
		return model.Contact{}, ErrIdentityMismatch
	}
	if err := verifyPayload(notice.Envelope, KindRevocationNotice, notice.Payload, notice.Payload.RevokingAgentID, revokingPublicKey); err != nil {
		return model.Contact{}, err
	}
	contact.State = model.ContactStateRevoked
	if err := s.store.UpsertContact(ctx, contact); err != nil {
		return model.Contact{}, err
	}
	if err := s.store.CancelOutboxForContact(ctx, contact.LocalAgentID, contact.RemoteAgentID); err != nil {
		return model.Contact{}, err
	}
	if _, err := s.store.RevokeAttachmentGrantsForContact(ctx, contact.LocalAgentID, contact.RemoteAgentID, s.now().UTC()); err != nil {
		return model.Contact{}, err
	}
	return s.store.GetContact(ctx, contact.LocalAgentID, contact.RemoteAgentID)
}

func (s *Service) Revoke(ctx context.Context, localAgentID, remoteAgentID string) (model.Contact, error) {
	contact, err := s.store.GetContact(ctx, localAgentID, remoteAgentID)
	if err != nil {
		return model.Contact{}, err
	}
	if contact.State == model.ContactStateBlocked {
		return model.Contact{}, fmt.Errorf("%w: blocked to revoked", ErrInvalidTransition)
	}
	contact.State = model.ContactStateRevoked
	if err := s.store.UpsertContact(ctx, contact); err != nil {
		return model.Contact{}, err
	}
	if err := s.store.CancelOutboxForContact(ctx, contact.LocalAgentID, contact.RemoteAgentID); err != nil {
		return model.Contact{}, err
	}
	if _, err := s.store.RevokeAttachmentGrantsForContact(ctx, contact.LocalAgentID, contact.RemoteAgentID, s.now().UTC()); err != nil {
		return model.Contact{}, err
	}
	return s.store.GetContact(ctx, localAgentID, remoteAgentID)
}

func (s *Service) Block(ctx context.Context, localAgentID, remoteAgentID string) (model.Contact, error) {
	contact, err := s.store.GetContact(ctx, localAgentID, remoteAgentID)
	if err != nil {
		return model.Contact{}, err
	}
	contact.State = model.ContactStateBlocked
	if err := s.store.UpsertContact(ctx, contact); err != nil {
		return model.Contact{}, err
	}
	if err := s.store.CancelOutboxForContact(ctx, contact.LocalAgentID, contact.RemoteAgentID); err != nil {
		return model.Contact{}, err
	}
	if _, err := s.store.RevokeAttachmentGrantsForContact(ctx, contact.LocalAgentID, contact.RemoteAgentID, s.now().UTC()); err != nil {
		return model.Contact{}, err
	}
	return s.store.GetContact(ctx, localAgentID, remoteAgentID)
}

func (s *Service) CanCommunicate(contact model.Contact) bool {
	return contact.State == model.ContactStateActive
}

func (s *Service) rejectBlockedContact(ctx context.Context, localAgentID, remoteAgentID string) error {
	contact, err := s.store.GetContact(ctx, localAgentID, remoteAgentID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if contact.State == model.ContactStateBlocked {
		return ErrContactBlocked
	}
	return nil
}

func signPayload[T any](signer *identity.Identity, kind string, payload T) (model.SignedEnvelope, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return model.SignedEnvelope{}, fmt.Errorf("marshal %s payload: %w", kind, err)
	}
	envelope, err := signer.Sign(signer.AgentID(), kind, encoded)
	if err != nil {
		return model.SignedEnvelope{}, fmt.Errorf("sign %s payload: %w", kind, err)
	}
	return envelope, nil
}

func verifyPayload[T any](envelope model.SignedEnvelope, expectedKind string, payload T, expectedAgentID string, expectedPublicKey ed25519.PublicKey) error {
	if envelope.Kind != expectedKind {
		return fmt.Errorf("%w: unexpected kind %q", ErrInvalidEnvelope, envelope.Kind)
	}
	if err := identity.VerifyEnvelopeForAgent(envelope, expectedAgentID, expectedPublicKey); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload for verification: %w", err)
	}
	if !bytes.Equal(encoded, envelope.Payload) {
		return fmt.Errorf("%w: payload mismatch", ErrInvalidEnvelope)
	}
	return nil
}

func digestEnvelope(envelope model.SignedEnvelope) (string, error) {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal envelope digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func acceptanceSecretProof(secretHash []byte, inviteDigest, acceptingAgentID, hostFingerprint, agentFingerprint string) string {
	mac := hmac.New(sha256.New, secretHash)
	_, _ = mac.Write([]byte(inviteDigest))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(acceptingAgentID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(hostFingerprint))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(agentFingerprint))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func publicKey(value []byte) (ed25519.PublicKey, error) {
	if len(value) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key")
	}
	return append(ed25519.PublicKey(nil), value...), nil
}

func randomSecret(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate pairing secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func hashSecret(secret string) []byte {
	digest := sha256.Sum256([]byte(secret))
	return digest[:]
}

func endpointForAgent(address, agentID string) string {
	host, port := splitTailnetAddress(address)
	if host == "" || agentID == "" {
		return ""
	}
	if port == "" {
		port = "7443"
	}
	return "http://" + net.JoinHostPort(host, port) + "/agents/" + url.PathEscape(agentID) + "/a2a/rest"
}

func splitTailnetAddress(address string) (string, string) {
	raw := strings.TrimSpace(address)
	if raw == "" {
		return "", ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "" {
		raw = parsed.Host
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if _, err := strconv.Atoi(port); err == nil {
			return strings.Trim(host, "[]"), port
		}
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = strings.Trim(raw, "[]")
	}
	if net.ParseIP(raw) == nil {
		return "", ""
	}
	return raw, ""
}
