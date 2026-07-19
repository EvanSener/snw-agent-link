package model

import "time"

type ContactState string

const (
	ContactStateUnknown              ContactState = "unknown"
	ContactStatePendingOutbound      ContactState = "pending_outbound"
	ContactStatePendingInbound       ContactState = "pending_inbound"
	ContactStateAwaitingConfirmation ContactState = "awaiting_confirmation"
	ContactStateActive               ContactState = "active"
	ContactStateRevoked              ContactState = "revoked"
	ContactStateBlocked              ContactState = "blocked"
)

type AgentRegistration struct {
	AgentID               string    `json:"agentId"`
	DisplayName           string    `json:"displayName"`
	LocalEndpoint         string    `json:"localEndpoint"`
	AgentCardJSON         []byte    `json:"agentCard"`
	IdentityPublicKey     []byte    `json:"identityPublicKey"`
	CapabilityPublicKey   []byte    `json:"capabilityPublicKey,omitempty"`
	CapabilityGeneration  uint64    `json:"capabilityGeneration,omitempty"`
	RegistrationTokenHash []byte    `json:"-"`
	CreatedAt             time.Time `json:"createdAt"`
	UpdatedAt             time.Time `json:"updatedAt"`
}

type Contact struct {
	LocalAgentID           string       `json:"localAgentId"`
	RemoteAgentID          string       `json:"remoteAgentId"`
	RemoteNodeID           string       `json:"remoteNodeId,omitempty"`
	RemoteEndpoint         string       `json:"remoteEndpoint,omitempty"`
	RemoteBinding          string       `json:"remoteBinding,omitempty"`
	RemoteHostFingerprint  string       `json:"remoteHostFingerprint"`
	RemoteAgentFingerprint string       `json:"remoteAgentFingerprint"`
	State                  ContactState `json:"state"`
	CreatedAt              time.Time    `json:"createdAt"`
	UpdatedAt              time.Time    `json:"updatedAt"`
}

type PairingRequest struct {
	ID                     string     `json:"id"`
	LocalAgentID           string     `json:"localAgentId"`
	RemoteAgentID          string     `json:"remoteAgentId"`
	RemoteHostFingerprint  string     `json:"remoteHostFingerprint"`
	RemoteAgentFingerprint string     `json:"remoteAgentFingerprint"`
	SecretHash             []byte     `json:"-"`
	ExpiresAt              time.Time  `json:"expiresAt"`
	ConsumedAt             *time.Time `json:"consumedAt,omitempty"`
	CreatedAt              time.Time  `json:"createdAt"`
}

type PairingSession struct {
	InviteID              string    `json:"inviteId"`
	LocalAgentID          string    `json:"localAgentId"`
	RemoteAgentID         string    `json:"remoteAgentId"`
	Role                  string    `json:"role"`
	LocalHostFingerprint  string    `json:"localHostFingerprint"`
	RemoteHostFingerprint string    `json:"remoteHostFingerprint"`
	RemoteAgentPublicKey  []byte    `json:"remoteAgentPublicKey"`
	InviteDigest          string    `json:"inviteDigest"`
	AcceptanceDigest      string    `json:"acceptanceDigest,omitempty"`
	ConfirmationDigest    string    `json:"confirmationDigest,omitempty"`
	ExpiresAt             time.Time `json:"expiresAt"`
	CreatedAt             time.Time `json:"createdAt"`
	UpdatedAt             time.Time `json:"updatedAt"`
}

type SignedEnvelope struct {
	AgentID        string `json:"agentId"`
	KeyFingerprint string `json:"keyFingerprint"`
	Kind           string `json:"kind"`
	Payload        []byte `json:"payload"`
	IssuedAt       int64  `json:"issuedAt"`
	Nonce          string `json:"nonce"`
	Signature      []byte `json:"signature"`
}

type OutboxState string

const (
	OutboxStatePending   OutboxState = "pending"
	OutboxStateDelivered OutboxState = "delivered"
	OutboxStateCancelled OutboxState = "cancelled"
)

type OutboxMessage struct {
	MessageID      string      `json:"messageId"`
	IdempotencyKey string      `json:"idempotencyKey"`
	SourceAgentID  string      `json:"sourceAgentId"`
	TargetAgentID  string      `json:"targetAgentId"`
	ContextID      string      `json:"contextId"`
	Payload        []byte      `json:"payload"`
	State          OutboxState `json:"state"`
	AttemptCount   int         `json:"attemptCount"`
	NextAttemptAt  time.Time   `json:"nextAttemptAt"`
	CreatedAt      time.Time   `json:"createdAt"`
	UpdatedAt      time.Time   `json:"updatedAt"`
}

type DeduplicationRecord struct {
	SourceAgentID  string    `json:"sourceAgentId,omitempty"`
	TargetAgentID  string    `json:"targetAgentId"`
	AgentKeyEpoch  uint64    `json:"agentKeyEpoch,omitempty"`
	MessageID      string    `json:"messageId"`
	TaskID         string    `json:"taskId"`
	ResponseStatus int       `json:"responseStatus,omitempty"`
	ResponseType   string    `json:"responseType,omitempty"`
	ResponseBody   []byte    `json:"-"`
	CreatedAt      time.Time `json:"createdAt"`
}

type DeliveryReceipt struct {
	MessageID       string    `json:"messageId"`
	TargetAgentID   string    `json:"targetAgentId"`
	RemoteReceiptID string    `json:"remoteReceiptId"`
	DeliveredAt     time.Time `json:"deliveredAt"`
}

type AttachmentGrant struct {
	GrantID       string     `json:"grantId"`
	BlobID        string     `json:"blobId"`
	BlobURI       string     `json:"blobUri,omitempty"`
	OwnerAgentID  string     `json:"ownerAgentId"`
	TargetAgentID string     `json:"targetAgentId"`
	ContextID     string     `json:"contextId"`
	Digest        string     `json:"digest"`
	Size          int64      `json:"size"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

type InboxMessage struct {
	MessageID     string    `json:"messageId"`
	TargetAgentID string    `json:"targetAgentId"`
	SourceAgentID string    `json:"sourceAgentId"`
	ContextID     string    `json:"contextId"`
	Body          string    `json:"body"`
	State         string    `json:"state"`
	ReceivedAt    time.Time `json:"receivedAt"`
}

type TaskIndex struct {
	TaskID        string    `json:"taskId"`
	ContextID     string    `json:"contextId"`
	LocalAgentID  string    `json:"localAgentId"`
	RemoteAgentID string    `json:"remoteAgentId"`
	State         string    `json:"state"`
	Cursor        string    `json:"cursor,omitempty"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type AuditEntry struct {
	ID            string    `json:"id"`
	ActorAgentID  string    `json:"actorAgentId,omitempty"`
	RemoteAgentID string    `json:"remoteAgentId,omitempty"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	RequestID     string    `json:"requestId,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}
