package management

import (
	"context"
	"encoding/json"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/attachment"
	"github.com/EvanSener/snw-agent-link/internal/capability"
	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/pairing"
)

type IdentityProvider interface {
	GetIdentity(context.Context, string) (*identity.Identity, error)
	PutIdentity(context.Context, *identity.Identity) error
}

type CapabilityKeyProvider interface {
	GetCapabilityKey(context.Context, string) (capability.Key, error)
	PutCapabilityKey(context.Context, string, capability.Key) error
}

type RuntimeStatusProvider interface {
	RuntimeStatus(context.Context) RuntimeStatus
}

type RuntimeStatus struct {
	Version                string `json:"version"`
	TailscaleAddress       string `json:"tailscaleAddress,omitempty"`
	TailscaleNodeID        string `json:"tailscaleNodeId,omitempty"`
	TailscaleStableNodeID  string `json:"tailscaleStableNodeId,omitempty"`
	TailscaleLoggedIn      bool   `json:"tailscaleLoggedIn"`
	TailscaleLocalAPIReady bool   `json:"tailscaleLocalApiReady"`
	TailscaleWhoIsReady    bool   `json:"tailscaleWhoIsReady"`
	HostFingerprint        string `json:"hostFingerprint,omitempty"`
	GatewayListening       bool   `json:"gatewayListening"`
}

type AgentRegisterParams struct {
	AgentID       string          `json:"agentId"`
	DisplayName   string          `json:"displayName"`
	LocalEndpoint string          `json:"localEndpoint"`
	AgentCard     json.RawMessage `json:"agentCard"`
}

type AgentRegisterResult struct {
	Registration      model.AgentRegistration `json:"registration"`
	RegistrationToken string                  `json:"registrationToken"`
}

// AgentEnsureParams is used by unattended installers. A new agent is created
// when AgentID is absent from the local store; an existing agent must present
// its previously issued registration token and matching endpoint/card so the
// operation can safely be retried without replacing its identity.
type AgentEnsureParams struct {
	AgentID           string          `json:"agentId,omitempty"`
	DisplayName       string          `json:"displayName"`
	LocalEndpoint     string          `json:"localEndpoint"`
	AgentCard         json.RawMessage `json:"agentCard"`
	RegistrationToken string          `json:"registrationToken,omitempty"`
}

type AgentEnsureResult struct {
	Registration      model.AgentRegistration `json:"registration"`
	RegistrationToken string                  `json:"registrationToken"`
	Created           bool                    `json:"created"`
}

type CapabilityChallengeParams struct {
	AgentID           string   `json:"agentId"`
	RegistrationToken string   `json:"registrationToken"`
	EndpointDigest    string   `json:"endpointDigest,omitempty"`
	Methods           []string `json:"methods,omitempty"`
}

type CapabilityChallengeResult struct {
	Challenge capability.Challenge `json:"challenge"`
}

type CapabilityExchangeParams struct {
	AgentID   string               `json:"agentId"`
	Challenge capability.Challenge `json:"challenge"`
	Signature []byte               `json:"signature"`
}

type CapabilitySessionResult struct {
	Session capability.Session `json:"session"`
}

type CapabilityRotateParams struct {
	AgentID           string `json:"agentId"`
	RegistrationToken string `json:"registrationToken"`
}

type CapabilityRotateResult struct {
	AgentID    string `json:"agentId"`
	PublicKey  []byte `json:"publicKey"`
	Generation uint64 `json:"generation"`
}

type AttachmentInitParams struct {
	AgentID           string `json:"agentId"`
	RegistrationToken string `json:"registrationToken,omitempty"`
	CapabilitySession string `json:"capabilitySession,omitempty"`
	Name              string `json:"name"`
	MediaType         string `json:"mediaType,omitempty"`
	Size              int64  `json:"size"`
	SHA256            string `json:"sha256"`
}

type AttachmentChunkParams struct {
	AgentID           string `json:"agentId"`
	RegistrationToken string `json:"registrationToken,omitempty"`
	CapabilitySession string `json:"capabilitySession,omitempty"`
	BlobID            string `json:"blobId"`
	Offset            int64  `json:"offset"`
	Data              []byte `json:"data"`
}

type AttachmentBlobParams struct {
	AgentID           string `json:"agentId"`
	RegistrationToken string `json:"registrationToken,omitempty"`
	CapabilitySession string `json:"capabilitySession,omitempty"`
	BlobID            string `json:"blobId"`
}

type AttachmentResult struct {
	Attachment attachment.Metadata `json:"attachment"`
}

type AttachmentGrantParams struct {
	AgentID           string `json:"agentId"`
	RegistrationToken string `json:"registrationToken,omitempty"`
	CapabilitySession string `json:"capabilitySession,omitempty"`
	BlobID            string `json:"blobId"`
	TargetAgentID     string `json:"targetAgentId"`
	ContextID         string `json:"contextId"`
	TTLSeconds        int    `json:"ttlSeconds,omitempty"`
}

type AttachmentGrantResult struct {
	Grant model.AttachmentGrant `json:"grant"`
}

type MailboxListParams struct {
	AgentID           string `json:"agentId,omitempty"`
	SourceAgentID     string `json:"sourceAgentId,omitempty"`
	RegistrationToken string `json:"registrationToken,omitempty"`
	CapabilitySession string `json:"capabilitySession,omitempty"`
	UnreadOnly        bool   `json:"unreadOnly,omitempty"`
	ContextID         string `json:"contextId,omitempty"`
	Limit             int    `json:"limit,omitempty"`
}

type MailboxListResult struct {
	Items []model.InboxMessage `json:"items"`
}

type MailboxReadParams struct {
	AgentID           string `json:"agentId,omitempty"`
	SourceAgentID     string `json:"sourceAgentId,omitempty"`
	RegistrationToken string `json:"registrationToken,omitempty"`
	CapabilitySession string `json:"capabilitySession,omitempty"`
	MessageID         string `json:"messageId"`
}

type PairInviteParams struct {
	LocalAgentID         string        `json:"localAgentId"`
	RemoteAgentID        string        `json:"remoteAgentId"`
	LocalHostFingerprint string        `json:"localHostFingerprint"`
	TailscaleAddress     string        `json:"tailscaleAddress"`
	TailscaleNodeID      string        `json:"tailscaleNodeId,omitempty"`
	TTL                  time.Duration `json:"ttl"`
}

type PairAcceptParams struct {
	LocalAgentID         string                `json:"localAgentId"`
	InviteID             string                `json:"inviteId,omitempty"`
	LocalHostFingerprint string                `json:"localHostFingerprint"`
	TailscaleAddress     string                `json:"tailscaleAddress,omitempty"`
	TailscaleNodeID      string                `json:"tailscaleNodeId,omitempty"`
	Invite               pairing.PairingInvite `json:"invite"`
}

type PairApproveParams struct {
	LocalAgentID             string                    `json:"localAgentId"`
	Acceptance               pairing.PairingAcceptance `json:"acceptance"`
	ExpectedHostFingerprint  string                    `json:"expectedHostFingerprint"`
	ExpectedAgentFingerprint string                    `json:"expectedAgentFingerprint"`
}

type PairConfirmParams struct {
	LocalAgentID string                      `json:"localAgentId"`
	Confirmation pairing.PairingConfirmation `json:"confirmation"`
}

type PairActivateParams struct {
	LocalAgentID string                           `json:"localAgentId"`
	Receipt      pairing.PairingActivationReceipt `json:"receipt"`
}

type ContactParams struct {
	LocalAgentID  string `json:"localAgentId"`
	RemoteAgentID string `json:"remoteAgentId,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type ContactRevokeResult struct {
	Notice pairing.RevocationNotice `json:"notice"`
}

type MessageSendParams struct {
	SourceAgentID     string          `json:"sourceAgentId"`
	TargetAgentID     string          `json:"targetAgentId"`
	RegistrationToken string          `json:"registrationToken"`
	CapabilitySession string          `json:"capabilitySession,omitempty"`
	ContextID         string          `json:"contextId,omitempty"`
	MessageID         string          `json:"messageId,omitempty"`
	Payload           json.RawMessage `json:"payload"`
}

type MessageStatusParams struct {
	SourceAgentID     string `json:"sourceAgentId"`
	RegistrationToken string `json:"registrationToken"`
	CapabilitySession string `json:"capabilitySession,omitempty"`
	MessageID         string `json:"messageId"`
}

type MessageCancelParams struct {
	SourceAgentID     string `json:"sourceAgentId"`
	RegistrationToken string `json:"registrationToken"`
	CapabilitySession string `json:"capabilitySession,omitempty"`
	MessageID         string `json:"messageId"`
}

type ApplyRevocationParams struct {
	LocalAgentID string                   `json:"localAgentId"`
	Notice       pairing.RevocationNotice `json:"notice"`
}

type DoctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

type DoctorResult struct {
	OK     bool          `json:"ok"`
	Checks []DoctorCheck `json:"checks"`
}
