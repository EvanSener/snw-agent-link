package delivery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/transport"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
)

type A2ATransport struct {
	endpoints  map[string]*url.URL
	identities map[string]*identity.Identity
	client     *http.Client
}

type ContactProvider interface {
	GetContact(context.Context, string, string) (model.Contact, error)
}

type IdentityProvider interface {
	GetIdentity(context.Context, string) (*identity.Identity, error)
}

type PairingSessionProvider interface {
	FindPairingSession(context.Context, string, string) (model.PairingSession, error)
}

type DynamicA2ATransport struct {
	contacts            ContactProvider
	identities          IdentityProvider
	client              *http.Client
	requireRemoteNodeID bool
	readinessCheck      func(context.Context) error
	tasks               interface {
		UpsertTaskIndex(context.Context, model.TaskIndex) error
	}
}

func NewDynamicA2ATransport(contacts ContactProvider, identities IdentityProvider) (*DynamicA2ATransport, error) {
	if contacts == nil || identities == nil {
		return nil, errors.New("dynamic A2A transport dependencies are required")
	}
	return &DynamicA2ATransport{contacts: contacts, identities: identities, client: &http.Client{}}, nil
}

func (transportClient *DynamicA2ATransport) SetTaskStore(tasks interface {
	UpsertTaskIndex(context.Context, model.TaskIndex) error
}) {
	transportClient.tasks = tasks
}

// SetRequireRemoteNodeID enables the production fail-closed policy. Offline
// unit-test transports may leave it disabled, while the daemon requires every
// active contact to retain the Stable Node ID learned during pairing.
func (transportClient *DynamicA2ATransport) SetRequireRemoteNodeID(required bool) {
	transportClient.requireRemoteNodeID = required
}

// SetReadinessCheck gates production delivery on the local Tailscale control
// plane. A failed Local API/WhoIs check is returned before any network request
// is attempted, preserving the Tailnet-only fail-closed contract.
func (transportClient *DynamicA2ATransport) SetReadinessCheck(check func(context.Context) error) {
	transportClient.readinessCheck = check
}

func NewA2ATransport(endpoints map[string]string, identities map[string]*identity.Identity) (*A2ATransport, error) {
	parsed := make(map[string]*url.URL, len(endpoints))
	for agentID, raw := range endpoints {
		endpoint, err := url.Parse(raw)
		if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
			return nil, fmt.Errorf("parse endpoint for %s: %w", agentID, err)
		}
		parsed[agentID] = endpoint
	}
	return &A2ATransport{endpoints: parsed, identities: identities, client: &http.Client{}}, nil
}

func (transportClient *A2ATransport) Deliver(ctx context.Context, message model.OutboxMessage) (string, error) {
	endpoint, ok := transportClient.endpoints[message.TargetAgentID]
	if !ok {
		return "", fmt.Errorf("target endpoint is not configured: %s", message.TargetAgentID)
	}
	signer := transportClient.identities[message.SourceAgentID]
	if signer == nil {
		return "", fmt.Errorf("source identity is not configured: %s", message.SourceAgentID)
	}
	return deliverA2A(ctx, message, endpoint, signer, transportClient.client)
}

func (transportClient *DynamicA2ATransport) Deliver(ctx context.Context, message model.OutboxMessage) (string, error) {
	if transportClient.readinessCheck != nil {
		if err := transportClient.readinessCheck(ctx); err != nil {
			return "", fmt.Errorf("tailscale readiness check failed: %w", err)
		}
	}
	contact, err := transportClient.contacts.GetContact(ctx, message.SourceAgentID, message.TargetAgentID)
	if err != nil {
		return "", fmt.Errorf("resolve target contact: %w", err)
	}
	if contact.State != model.ContactStateActive {
		return "", fmt.Errorf("target contact is not active: %s", contact.State)
	}
	if transportClient.requireRemoteNodeID && strings.TrimSpace(contact.RemoteNodeID) == "" {
		return "", errors.New("target contact Tailscale node identity is unavailable")
	}
	if contact.RemoteEndpoint == "" {
		return "", fmt.Errorf("target endpoint is not configured: %s", message.TargetAgentID)
	}
	signer, err := transportClient.identities.GetIdentity(ctx, message.SourceAgentID)
	if err != nil {
		return "", fmt.Errorf("resolve source identity: %w", err)
	}
	endpoint, err := url.Parse(contact.RemoteEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse target endpoint: %w", err)
	}
	var remotePublicKey ed25519.PublicKey
	if sessions, ok := transportClient.contacts.(PairingSessionProvider); ok {
		if session, sessionErr := sessions.FindPairingSession(ctx, message.SourceAgentID, message.TargetAgentID); sessionErr == nil && len(session.RemoteAgentPublicKey) == ed25519.PublicKeySize {
			remotePublicKey = append(ed25519.PublicKey(nil), session.RemoteAgentPublicKey...)
		}
	}
	result, err := deliverA2A(ctx, message, endpoint, signer, transportClient.client, remotePublicKey)
	if err == nil && transportClient.tasks != nil {
		_ = transportClient.tasks.UpsertTaskIndex(ctx, model.TaskIndex{TaskID: result, ContextID: message.ContextID, LocalAgentID: message.SourceAgentID, RemoteAgentID: message.TargetAgentID, State: "working", UpdatedAt: time.Now().UTC()})
	}
	return result, err
}

func deliverA2A(ctx context.Context, message model.OutboxMessage, endpoint *url.URL, signer *identity.Identity, baseClient *http.Client, remotePublicKeys ...ed25519.PublicKey) (string, error) {
	if endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return "", errors.New("invalid target endpoint")
	}
	request := new(a2a.SendMessageRequest)
	if err := json.Unmarshal(message.Payload, request); err != nil {
		return "", fmt.Errorf("decode outbox A2A request: %w", err)
	}
	client := *baseClient
	client.Transport = transport.SignedRoundTripper{Base: baseClient.Transport, Identity: signer, TargetAgent: message.TargetAgentID}
	if len(remotePublicKeys) > 0 && len(remotePublicKeys[0]) == ed25519.PublicKeySize {
		client.Transport = transport.VerifyingRoundTripper{Base: client.Transport, PublicKey: remotePublicKeys[0], ExpectedAgent: message.TargetAgentID, AllowedSkew: 5 * time.Minute}
	}
	clientTransport := a2aclient.NewRESTTransport(endpoint, &client)
	result, err := clientTransport.SendMessage(ctx, a2aclient.ServiceParams{}, request)
	if err != nil {
		return "", err
	}
	switch value := result.(type) {
	case *a2a.Task:
		return string(value.ID), nil
	case *a2a.Message:
		return value.ID, nil
	default:
		return "", errors.New("A2A response did not contain a task or message")
	}
}
