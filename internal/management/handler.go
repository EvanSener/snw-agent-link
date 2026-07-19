package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/attachment"
	"github.com/EvanSener/snw-agent-link/internal/capability"
	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/identitystore"
	"github.com/EvanSener/snw-agent-link/internal/ipc"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/pairing"
	"github.com/EvanSener/snw-agent-link/internal/registration"
	"github.com/EvanSener/snw-agent-link/internal/store"
	"github.com/google/uuid"
)

type Handler struct {
	store         *store.Store
	registrations *registration.Service
	pairing       *pairing.Service
	identities    IdentityProvider
	status        RuntimeStatusProvider
	capabilityMu  sync.Mutex
	bootID        string
	challenges    map[string]capability.Challenge
	sessions      map[string]capability.Session
	attachments   *attachment.Service
}

func NewHandler(database *store.Store, registrations *registration.Service, pairingService *pairing.Service, identities IdentityProvider, status RuntimeStatusProvider, attachmentServices ...*attachment.Service) *Handler {
	var attachmentService *attachment.Service
	if len(attachmentServices) > 0 {
		attachmentService = attachmentServices[0]
	}
	return &Handler{store: database, registrations: registrations, pairing: pairingService, identities: identities, status: status,
		bootID: uuid.NewString(), challenges: make(map[string]capability.Challenge), sessions: make(map[string]capability.Session), attachments: attachmentService}
}

func (handler *Handler) HandleIPC(ctx context.Context, request ipc.Request) (any, error) {
	if handler.store == nil || handler.registrations == nil || handler.pairing == nil || handler.identities == nil {
		return nil, errors.New("management handler dependencies are required")
	}
	switch request.Method {
	case "status":
		return handler.handleStatus(ctx)
	case "agent.register":
		return decodeAndCall(ctx, request.Params, handler.registerAgent)
	case "agent.ensure":
		return decodeAndCall(ctx, request.Params, handler.ensureAgent)
	case "agent.capability.challenge":
		return decodeAndCall(ctx, request.Params, handler.capabilityChallenge)
	case "agent.capability.exchange":
		return decodeAndCall(ctx, request.Params, handler.capabilityExchange)
	case "agent.capability.rotate", "agent.capability.recover":
		return decodeAndCall(ctx, request.Params, handler.rotateCapability)
	case "attachment.init":
		return decodeAndCall(ctx, request.Params, handler.initAttachment)
	case "attachment.chunk":
		return decodeAndCall(ctx, request.Params, handler.chunkAttachment)
	case "attachment.complete":
		return decodeAndCall(ctx, request.Params, handler.completeAttachment)
	case "attachment.grant":
		return decodeAndCall(ctx, request.Params, handler.grantAttachment)
	case "attachment.status":
		return decodeAndCall(ctx, request.Params, handler.statusAttachment)
	case "attachment.cancel":
		return decodeAndCall(ctx, request.Params, handler.cancelAttachment)
	case "mailbox.list":
		return decodeAndCall(ctx, request.Params, handler.listMailbox)
	case "mailbox.read":
		return decodeAndCall(ctx, request.Params, handler.readMailbox)
	case "agent.list":
		return handler.store.ListAgentRegistrations(ctx)
	case "pair.invite":
		return decodeAndCall(ctx, request.Params, handler.createInvite)
	case "pair.accept":
		return decodeAndCall(ctx, request.Params, handler.acceptInvite)
	case "pair.approve":
		return decodeAndCall(ctx, request.Params, handler.approveAcceptance)
	case "pair.confirm":
		return decodeAndCall(ctx, request.Params, handler.applyConfirmation)
	case "pair.activate":
		return decodeAndCall(ctx, request.Params, handler.applyActivation)
	case "contact.list":
		return decodeAndCall(ctx, request.Params, handler.listContacts)
	case "contact.revoke":
		return decodeAndCall(ctx, request.Params, handler.revokeContact)
	case "contact.revoke.apply":
		return decodeAndCall(ctx, request.Params, handler.applyRevocation)
	case "contact.block":
		return decodeAndCall(ctx, request.Params, handler.blockContact)
	case "message.send":
		return decodeAndCall(ctx, request.Params, handler.sendMessage)
	case "message.status":
		return decodeAndCall(ctx, request.Params, handler.messageStatus)
	case "message.cancel":
		return decodeAndCall(ctx, request.Params, handler.cancelMessage)
	case "doctor":
		return handler.doctor(ctx)
	default:
		return nil, ipc.ErrMethodNotFound
	}
}

func (handler *Handler) sendMessage(ctx context.Context, params MessageSendParams) (model.OutboxMessage, error) {
	if params.SourceAgentID == "" || params.TargetAgentID == "" || len(params.Payload) == 0 || (params.RegistrationToken == "" && params.CapabilitySession == "") {
		return model.OutboxMessage{}, fmt.Errorf("%w: sourceAgentId, targetAgentId, capability and payload are required", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, params.SourceAgentID, params.RegistrationToken, params.CapabilitySession, "message.send"); err != nil {
		return model.OutboxMessage{}, fmt.Errorf("%w: source agent capability is invalid", ipc.ErrInvalidRequest)
	}
	contact, err := handler.store.GetContact(ctx, params.SourceAgentID, params.TargetAgentID)
	if err != nil || contact.State != model.ContactStateActive {
		return model.OutboxMessage{}, fmt.Errorf("%w: target contact is not active", ipc.ErrInvalidRequest)
	}
	messageID := params.MessageID
	if messageID == "" {
		messageID = uuid.NewString()
	}
	contextID := params.ContextID
	if contextID == "" {
		contextID = uuid.NewString()
	}
	message := model.OutboxMessage{MessageID: messageID, IdempotencyKey: params.SourceAgentID + ":" + params.TargetAgentID + ":" + messageID,
		SourceAgentID: params.SourceAgentID, TargetAgentID: params.TargetAgentID, ContextID: contextID,
		Payload: append([]byte(nil), params.Payload...), State: model.OutboxStatePending, NextAttemptAt: time.Now().UTC()}
	if existing, lookupErr := handler.store.GetOutbox(ctx, messageID); lookupErr == nil {
		if existing.SourceAgentID != params.SourceAgentID || existing.TargetAgentID != params.TargetAgentID {
			return model.OutboxMessage{}, fmt.Errorf("%w: message id is already owned by another agent", ipc.ErrInvalidRequest)
		}
		return existing, nil
	}
	if err := handler.store.EnqueueOutbox(ctx, message); err != nil {
		return model.OutboxMessage{}, err
	}
	return handler.store.GetOutbox(ctx, messageID)
}

func (handler *Handler) messageStatus(ctx context.Context, params MessageStatusParams) (model.OutboxMessage, error) {
	if err := handler.authenticateMethod(ctx, params.SourceAgentID, params.RegistrationToken, params.CapabilitySession, "message.status"); err != nil {
		return model.OutboxMessage{}, fmt.Errorf("%w: source agent capability is invalid", ipc.ErrInvalidRequest)
	}
	message, err := handler.store.GetOutbox(ctx, params.MessageID)
	if errors.Is(err, store.ErrNotFound) {
		task, taskErr := handler.store.GetTaskIndex(ctx, params.MessageID)
		if taskErr != nil {
			return model.OutboxMessage{}, err
		}
		return model.OutboxMessage{MessageID: task.TaskID, ContextID: task.ContextID, SourceAgentID: task.LocalAgentID, TargetAgentID: task.RemoteAgentID, State: model.OutboxStateDelivered, UpdatedAt: task.UpdatedAt}, nil
	}
	if err != nil {
		return model.OutboxMessage{}, err
	}
	if message.SourceAgentID != params.SourceAgentID {
		return model.OutboxMessage{}, fmt.Errorf("%w: message does not belong to source agent", ipc.ErrInvalidRequest)
	}
	return message, nil
}

func (handler *Handler) cancelMessage(ctx context.Context, params MessageCancelParams) (model.OutboxMessage, error) {
	message, err := handler.messageStatus(ctx, MessageStatusParams{SourceAgentID: params.SourceAgentID, RegistrationToken: params.RegistrationToken, CapabilitySession: params.CapabilitySession, MessageID: params.MessageID})
	if err != nil {
		return model.OutboxMessage{}, err
	}
	if err := handler.store.CancelOutbox(ctx, message.MessageID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if task, taskErr := handler.store.GetTaskIndex(ctx, message.MessageID); taskErr == nil {
				task.State = "cancel_requested"
				if updateErr := handler.store.UpsertTaskIndex(ctx, task); updateErr != nil {
					return model.OutboxMessage{}, updateErr
				}
				return model.OutboxMessage{MessageID: task.TaskID, ContextID: task.ContextID, SourceAgentID: task.LocalAgentID, TargetAgentID: task.RemoteAgentID, State: model.OutboxStateCancelled, UpdatedAt: time.Now().UTC()}, nil
			}
		}
		if !errors.Is(err, store.ErrInvalidState) {
			return model.OutboxMessage{}, err
		}
		if task, taskErr := handler.store.GetTaskIndex(ctx, message.MessageID); taskErr == nil {
			task.State = "cancel_requested"
			if updateErr := handler.store.UpsertTaskIndex(ctx, task); updateErr != nil {
				return model.OutboxMessage{}, updateErr
			}
			return model.OutboxMessage{MessageID: task.TaskID, ContextID: task.ContextID, SourceAgentID: task.LocalAgentID, TargetAgentID: task.RemoteAgentID, State: model.OutboxStateCancelled, UpdatedAt: task.UpdatedAt}, nil
		}
		return model.OutboxMessage{}, err
	}
	return handler.store.GetOutbox(ctx, message.MessageID)
}

func (handler *Handler) handleStatus(ctx context.Context) (RuntimeStatus, error) {
	status := RuntimeStatus{Version: "dev"}
	if handler.status != nil {
		status = handler.status.RuntimeStatus(ctx)
	}
	return status, nil
}

func (handler *Handler) registerAgent(ctx context.Context, params AgentRegisterParams) (AgentRegisterResult, error) {
	agentIdentity, err := identity.Generate(params.AgentID)
	if err != nil {
		return AgentRegisterResult{}, err
	}
	capabilityKey, err := capability.GenerateKey()
	if err != nil {
		return AgentRegisterResult{}, err
	}
	registrationValue, token, err := handler.registrations.Register(ctx, registration.Input{
		AgentID: agentIdentity.AgentID(), DisplayName: params.DisplayName, LocalEndpoint: params.LocalEndpoint,
		AgentCardJSON: params.AgentCard, IdentityPublicKey: agentIdentity.PublicKey(), CapabilityPublicKey: capabilityKey.Public(), CapabilityGeneration: 1,
	})
	if err != nil {
		return AgentRegisterResult{}, err
	}
	if err := handler.identities.PutIdentity(ctx, agentIdentity); err != nil {
		return AgentRegisterResult{}, fmt.Errorf("persist agent identity: %w", err)
	}
	if provider, ok := handler.identities.(CapabilityKeyProvider); ok {
		if err := provider.PutCapabilityKey(ctx, agentIdentity.AgentID(), capabilityKey); err != nil {
			return AgentRegisterResult{}, fmt.Errorf("persist capability key: %w", err)
		}
	}
	return AgentRegisterResult{Registration: registrationValue, RegistrationToken: token}, nil
}

func (handler *Handler) ensureAgent(ctx context.Context, params AgentEnsureParams) (AgentEnsureResult, error) {
	if strings.TrimSpace(params.DisplayName) == "" || strings.TrimSpace(params.LocalEndpoint) == "" || len(params.AgentCard) == 0 {
		return AgentEnsureResult{}, fmt.Errorf("%w: displayName, localEndpoint and agentCard are required", ipc.ErrInvalidRequest)
	}
	if strings.TrimSpace(params.AgentID) == "" && strings.TrimSpace(params.RegistrationToken) != "" {
		return AgentEnsureResult{}, fmt.Errorf("%w: agentId is required when registrationToken is provided", ipc.ErrInvalidRequest)
	}

	if strings.TrimSpace(params.AgentID) != "" {
		existing, err := handler.store.GetAgentRegistration(ctx, params.AgentID)
		if err == nil {
			if existing.DisplayName != params.DisplayName || existing.LocalEndpoint != params.LocalEndpoint || !sameJSON(existing.AgentCardJSON, params.AgentCard) {
				return AgentEnsureResult{}, fmt.Errorf("%w: existing agent registration does not match requested endpoint or card", ipc.ErrInvalidRequest)
			}
			storedIdentity, err := handler.identities.GetIdentity(ctx, existing.AgentID)
			if err != nil {
				return AgentEnsureResult{}, fmt.Errorf("%w: existing agent identity is unavailable", ipc.ErrInvalidRequest)
			}
			if !bytes.Equal(storedIdentity.PublicKey(), existing.IdentityPublicKey) {
				return AgentEnsureResult{}, fmt.Errorf("%w: existing agent identity does not match registration", ipc.ErrInvalidRequest)
			}
			if provider, ok := handler.identities.(CapabilityKeyProvider); ok && len(existing.CapabilityPublicKey) > 0 {
				storedCapability, capabilityErr := provider.GetCapabilityKey(ctx, existing.AgentID)
				if capabilityErr != nil || !bytes.Equal(storedCapability.Public(), existing.CapabilityPublicKey) {
					return AgentEnsureResult{}, fmt.Errorf("%w: existing agent capability does not match registration", ipc.ErrInvalidRequest)
				}
			}
			if strings.TrimSpace(params.RegistrationToken) == "" {
				return AgentEnsureResult{}, fmt.Errorf("%w: registrationToken is required to reuse an existing agent", ipc.ErrInvalidRequest)
			}
			if _, err := handler.registrations.Authenticate(ctx, existing.AgentID, params.RegistrationToken); err != nil {
				return AgentEnsureResult{}, fmt.Errorf("%w: registrationToken is invalid", ipc.ErrInvalidRequest)
			}
			return AgentEnsureResult{Registration: existing, RegistrationToken: params.RegistrationToken, Created: false}, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return AgentEnsureResult{}, err
		}
		if _, identityErr := handler.identities.GetIdentity(ctx, params.AgentID); identityErr == nil {
			return AgentEnsureResult{}, fmt.Errorf("%w: agent identity exists but registration is missing; refusing to replace identity", ipc.ErrInvalidRequest)
		} else if !errors.Is(identityErr, identitystore.ErrNotFound) && !errors.Is(identityErr, store.ErrNotFound) {
			return AgentEnsureResult{}, fmt.Errorf("%w: inspect existing agent identity: %v", ipc.ErrInvalidRequest, identityErr)
		}
		if strings.TrimSpace(params.RegistrationToken) != "" {
			return AgentEnsureResult{}, fmt.Errorf("%w: registrationToken refers to an unknown agent", ipc.ErrInvalidRequest)
		}
	}

	created, err := handler.registerAgent(ctx, AgentRegisterParams{
		AgentID:       params.AgentID,
		DisplayName:   params.DisplayName,
		LocalEndpoint: params.LocalEndpoint,
		AgentCard:     params.AgentCard,
	})
	if err != nil {
		return AgentEnsureResult{}, err
	}
	return AgentEnsureResult{Registration: created.Registration, RegistrationToken: created.RegistrationToken, Created: true}, nil
}

func sameJSON(left, right []byte) bool {
	var leftValue any
	var rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return bytes.Equal(left, right)
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func (handler *Handler) capabilityChallenge(ctx context.Context, params CapabilityChallengeParams) (CapabilityChallengeResult, error) {
	registrationValue, err := handler.registrations.Authenticate(ctx, params.AgentID, params.RegistrationToken)
	if err != nil {
		return CapabilityChallengeResult{}, fmt.Errorf("%w: registration token is invalid", ipc.ErrInvalidRequest)
	}
	if len(registrationValue.CapabilityPublicKey) == 0 || registrationValue.CapabilityGeneration == 0 {
		return CapabilityChallengeResult{}, fmt.Errorf("%w: capability is not provisioned", ipc.ErrInvalidRequest)
	}
	methods := append([]string(nil), params.Methods...)
	if len(methods) == 0 {
		methods = []string{"message.cancel", "message.send", "message.status", "mailbox.list", "mailbox.read", "attachment.init", "attachment.chunk", "attachment.complete", "attachment.status", "attachment.cancel", "attachment.grant"}
	}
	endpointDigest := params.EndpointDigest
	if endpointDigest == "" {
		endpointDigest = registrationValue.LocalEndpoint
	}
	challenge := capability.Challenge{BootID: handler.bootID, Nonce: uuid.NewString(), AgentID: params.AgentID,
		EndpointDigest: endpointDigest, Methods: methods, ExpiresAt: time.Now().UTC().Add(2 * time.Minute)}
	handler.capabilityMu.Lock()
	handler.challenges[capabilityKey(params.AgentID, challenge.Nonce)] = challenge
	handler.capabilityMu.Unlock()
	return CapabilityChallengeResult{Challenge: challenge}, nil
}

func (handler *Handler) capabilityExchange(ctx context.Context, params CapabilityExchangeParams) (CapabilitySessionResult, error) {
	registrationValue, err := handler.store.GetAgentRegistration(ctx, params.AgentID)
	if err != nil {
		return CapabilitySessionResult{}, err
	}
	key := capabilityKey(params.AgentID, params.Challenge.Nonce)
	handler.capabilityMu.Lock()
	challenge, ok := handler.challenges[key]
	if ok {
		delete(handler.challenges, key)
	}
	handler.capabilityMu.Unlock()
	if !ok || challenge.BootID != params.Challenge.BootID || challenge.AgentID != params.AgentID || !challenge.ExpiresAt.Equal(params.Challenge.ExpiresAt) || !time.Now().UTC().Before(challenge.ExpiresAt) {
		return CapabilitySessionResult{}, fmt.Errorf("%w: challenge is unknown or expired", ipc.ErrInvalidRequest)
	}
	if err := capability.Verify(registrationValue.CapabilityPublicKey, challenge, params.Signature); err != nil {
		return CapabilitySessionResult{}, fmt.Errorf("%w: %v", ipc.ErrInvalidRequest, err)
	}
	session := capability.IssueSession(params.AgentID, registrationValue.CapabilityGeneration, challenge.Methods, time.Now().UTC(), 15*time.Minute)
	handler.capabilityMu.Lock()
	handler.sessions[session.Token] = session
	handler.capabilityMu.Unlock()
	return CapabilitySessionResult{Session: session}, nil
}

func (handler *Handler) rotateCapability(ctx context.Context, params CapabilityRotateParams) (CapabilityRotateResult, error) {
	if _, err := handler.registrations.Authenticate(ctx, params.AgentID, params.RegistrationToken); err != nil {
		return CapabilityRotateResult{}, fmt.Errorf("%w: registration token is invalid", ipc.ErrInvalidRequest)
	}
	current, err := handler.store.GetAgentRegistration(ctx, params.AgentID)
	if err != nil {
		return CapabilityRotateResult{}, err
	}
	key, err := capability.GenerateKey()
	if err != nil {
		return CapabilityRotateResult{}, err
	}
	generation := current.CapabilityGeneration + 1
	if generation == 1 && len(current.CapabilityPublicKey) > 0 {
		generation = 2
	}
	if err := handler.store.UpdateAgentCapability(ctx, params.AgentID, key.Public(), generation); err != nil {
		return CapabilityRotateResult{}, err
	}
	if provider, ok := handler.identities.(CapabilityKeyProvider); ok {
		if err := provider.PutCapabilityKey(ctx, params.AgentID, key); err != nil {
			return CapabilityRotateResult{}, fmt.Errorf("persist capability key: %w", err)
		}
	}
	handler.capabilityMu.Lock()
	for token, session := range handler.sessions {
		if session.AgentID == params.AgentID {
			delete(handler.sessions, token)
		}
	}
	handler.capabilityMu.Unlock()
	return CapabilityRotateResult{AgentID: params.AgentID, PublicKey: key.Public(), Generation: generation}, nil
}

func (handler *Handler) authenticateMethod(ctx context.Context, agentID, registrationToken, sessionToken, method string) error {
	if sessionToken == "" {
		if _, err := handler.registrations.Authenticate(ctx, agentID, registrationToken); err != nil {
			return err
		}
		return nil
	}
	handler.capabilityMu.Lock()
	session, ok := handler.sessions[sessionToken]
	handler.capabilityMu.Unlock()
	if !ok {
		return capability.ErrExpired
	}
	registrationValue, err := handler.store.GetAgentRegistration(ctx, agentID)
	if err != nil {
		return err
	}
	return session.Validate(agentID, registrationValue.CapabilityGeneration, method, time.Now().UTC())
}

func (handler *Handler) initAttachment(ctx context.Context, params AttachmentInitParams) (AttachmentResult, error) {
	if handler.attachments == nil {
		return AttachmentResult{}, fmt.Errorf("%w: attachments are not configured", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, params.AgentID, params.RegistrationToken, params.CapabilitySession, "attachment.init"); err != nil {
		return AttachmentResult{}, fmt.Errorf("%w: capability is invalid", ipc.ErrInvalidRequest)
	}
	value, err := handler.attachments.Init(params.AgentID, params.Name, params.MediaType, params.SHA256, params.Size)
	return AttachmentResult{Attachment: value}, err
}

func (handler *Handler) chunkAttachment(ctx context.Context, params AttachmentChunkParams) (AttachmentResult, error) {
	if handler.attachments == nil {
		return AttachmentResult{}, fmt.Errorf("%w: attachments are not configured", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, params.AgentID, params.RegistrationToken, params.CapabilitySession, "attachment.chunk"); err != nil {
		return AttachmentResult{}, fmt.Errorf("%w: capability is invalid", ipc.ErrInvalidRequest)
	}
	value, err := handler.attachments.PutChunk(params.AgentID, params.BlobID, params.Offset, params.Data)
	return AttachmentResult{Attachment: value}, err
}

func (handler *Handler) completeAttachment(ctx context.Context, params AttachmentBlobParams) (AttachmentResult, error) {
	if handler.attachments == nil {
		return AttachmentResult{}, fmt.Errorf("%w: attachments are not configured", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, params.AgentID, params.RegistrationToken, params.CapabilitySession, "attachment.complete"); err != nil {
		return AttachmentResult{}, fmt.Errorf("%w: capability is invalid", ipc.ErrInvalidRequest)
	}
	value, err := handler.attachments.Complete(params.AgentID, params.BlobID)
	return AttachmentResult{Attachment: value}, err
}

func (handler *Handler) grantAttachment(ctx context.Context, params AttachmentGrantParams) (AttachmentGrantResult, error) {
	if handler.attachments == nil {
		return AttachmentGrantResult{}, fmt.Errorf("%w: attachments are not configured", ipc.ErrInvalidRequest)
	}
	if params.TargetAgentID == "" || params.ContextID == "" {
		return AttachmentGrantResult{}, fmt.Errorf("%w: targetAgentId and contextId are required", ipc.ErrInvalidRequest)
	}
	contact, err := handler.store.GetContact(ctx, params.AgentID, params.TargetAgentID)
	if err != nil || contact.State != model.ContactStateActive {
		return AttachmentGrantResult{}, fmt.Errorf("%w: target contact is not active", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, params.AgentID, params.RegistrationToken, params.CapabilitySession, "attachment.grant"); err != nil {
		return AttachmentGrantResult{}, fmt.Errorf("%w: capability is invalid", ipc.ErrInvalidRequest)
	}
	grant, err := handler.attachments.Grant(params.AgentID, params.BlobID, params.TargetAgentID, params.ContextID, time.Duration(params.TTLSeconds)*time.Second)
	if err != nil {
		return AttachmentGrantResult{}, err
	}
	if handler.status != nil {
		grant.BlobURI = blobURI(handler.status.RuntimeStatus(ctx).TailscaleAddress, grant)
	}
	if err := handler.store.CreateAttachmentGrant(ctx, grant); err != nil {
		return AttachmentGrantResult{}, err
	}
	return AttachmentGrantResult{Grant: grant}, nil
}

func blobURI(address string, grant model.AttachmentGrant) string {
	address = strings.TrimSpace(address)
	if address == "" || grant.OwnerAgentID == "" || grant.BlobID == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		if strings.Contains(address, ":") {
			address = "[" + address + "]:7443"
		} else {
			address += ":7443"
		}
	}
	return (&url.URL{Scheme: "http", Host: address, Path: "/agents/" + url.PathEscape(grant.OwnerAgentID) + "/blobs/" + url.PathEscape(grant.BlobID)}).String()
}

func (handler *Handler) statusAttachment(ctx context.Context, params AttachmentBlobParams) (AttachmentResult, error) {
	if handler.attachments == nil {
		return AttachmentResult{}, fmt.Errorf("%w: attachments are not configured", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, params.AgentID, params.RegistrationToken, params.CapabilitySession, "attachment.status"); err != nil {
		return AttachmentResult{}, fmt.Errorf("%w: capability is invalid", ipc.ErrInvalidRequest)
	}
	value, err := handler.attachments.Status(params.AgentID, params.BlobID)
	return AttachmentResult{Attachment: value}, err
}

func (handler *Handler) cancelAttachment(ctx context.Context, params AttachmentBlobParams) (AttachmentResult, error) {
	if handler.attachments == nil {
		return AttachmentResult{}, fmt.Errorf("%w: attachments are not configured", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, params.AgentID, params.RegistrationToken, params.CapabilitySession, "attachment.cancel"); err != nil {
		return AttachmentResult{}, fmt.Errorf("%w: capability is invalid", ipc.ErrInvalidRequest)
	}
	value, err := handler.attachments.Cancel(params.AgentID, params.BlobID)
	return AttachmentResult{Attachment: value}, err
}

func (handler *Handler) listMailbox(ctx context.Context, params MailboxListParams) (MailboxListResult, error) {
	agentID := params.AgentID
	if agentID == "" {
		agentID = params.SourceAgentID
	}
	if agentID == "" {
		return MailboxListResult{}, fmt.Errorf("%w: agentId is required", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, agentID, params.RegistrationToken, params.CapabilitySession, "mailbox.list"); err != nil {
		return MailboxListResult{}, fmt.Errorf("%w: capability is invalid", ipc.ErrInvalidRequest)
	}
	items, err := handler.store.ListInboxMessages(ctx, agentID, params.ContextID, params.UnreadOnly, params.Limit)
	if err != nil {
		return MailboxListResult{}, err
	}
	return MailboxListResult{Items: items}, nil
}

func (handler *Handler) readMailbox(ctx context.Context, params MailboxReadParams) (model.InboxMessage, error) {
	agentID := params.AgentID
	if agentID == "" {
		agentID = params.SourceAgentID
	}
	if agentID == "" || params.MessageID == "" {
		return model.InboxMessage{}, fmt.Errorf("%w: agentId and messageId are required", ipc.ErrInvalidRequest)
	}
	if err := handler.authenticateMethod(ctx, agentID, params.RegistrationToken, params.CapabilitySession, "mailbox.read"); err != nil {
		return model.InboxMessage{}, fmt.Errorf("%w: capability is invalid", ipc.ErrInvalidRequest)
	}
	items, err := handler.store.ListInboxMessages(ctx, agentID, "", false, 500)
	if err != nil {
		return model.InboxMessage{}, err
	}
	for _, item := range items {
		if item.MessageID == params.MessageID {
			_ = handler.store.MarkInboxMessageRead(ctx, item.TargetAgentID, item.SourceAgentID, item.MessageID)
			item.State = "read"
			return item, nil
		}
	}
	return model.InboxMessage{}, store.ErrNotFound
}

func capabilityKey(agentID, nonce string) string { return agentID + "\x00" + nonce }

func (handler *Handler) createInvite(ctx context.Context, params PairInviteParams) (pairing.PairingInvite, error) {
	localIdentity, err := handler.identities.GetIdentity(ctx, params.LocalAgentID)
	if err != nil {
		return pairing.PairingInvite{}, err
	}
	return handler.pairing.CreateInvite(ctx, localIdentity, pairing.CreateInviteInput{
		RemoteAgentID: params.RemoteAgentID, LocalHostFingerprint: params.LocalHostFingerprint,
		LocalTailscaleAddress: params.TailscaleAddress, LocalNodeID: params.TailscaleNodeID, TTL: params.TTL,
	})
}

func (handler *Handler) acceptInvite(ctx context.Context, params PairAcceptParams) (pairing.PairingAcceptance, error) {
	localIdentity, err := handler.identities.GetIdentity(ctx, params.LocalAgentID)
	if err != nil {
		return pairing.PairingAcceptance{}, err
	}
	if _, err := handler.pairing.ImportInvite(ctx, localIdentity, params.Invite); err != nil {
		return pairing.PairingAcceptance{}, err
	}
	if params.InviteID != "" {
		if params.TailscaleNodeID != "" {
			return handler.pairing.AcceptImportedInviteByIDAndAddressAndNode(ctx, localIdentity, params.InviteID, params.LocalHostFingerprint, params.TailscaleAddress, params.TailscaleNodeID)
		}
		return handler.pairing.AcceptImportedInviteByIDAndAddress(ctx, localIdentity, params.InviteID, params.LocalHostFingerprint, params.TailscaleAddress)
	}
	if params.TailscaleAddress != "" {
		if params.TailscaleNodeID != "" {
			return handler.pairing.AcceptImportedInviteAndAddressAndNode(ctx, localIdentity, params.LocalHostFingerprint, params.TailscaleAddress, params.TailscaleNodeID)
		}
		return handler.pairing.AcceptImportedInviteAndAddress(ctx, localIdentity, params.LocalHostFingerprint, params.TailscaleAddress)
	}
	return handler.pairing.AcceptImportedInvite(ctx, localIdentity, params.LocalHostFingerprint)
}

func (handler *Handler) approveAcceptance(ctx context.Context, params PairApproveParams) (pairing.PairingConfirmation, error) {
	localIdentity, err := handler.identities.GetIdentity(ctx, params.LocalAgentID)
	if err != nil {
		return pairing.PairingConfirmation{}, err
	}
	return handler.pairing.ApproveAcceptance(ctx, localIdentity, params.Acceptance, pairing.ApproveAcceptanceInput{
		ExpectedHostFingerprint:  params.ExpectedHostFingerprint,
		ExpectedAgentFingerprint: params.ExpectedAgentFingerprint,
	})
}

func (handler *Handler) applyConfirmation(ctx context.Context, params PairConfirmParams) (pairing.PairingActivationReceipt, error) {
	localIdentity, err := handler.identities.GetIdentity(ctx, params.LocalAgentID)
	if err != nil {
		return pairing.PairingActivationReceipt{}, err
	}
	return handler.pairing.ApplyConfirmation(ctx, localIdentity, params.Confirmation)
}

func (handler *Handler) applyActivation(ctx context.Context, params PairActivateParams) (struct{}, error) {
	localIdentity, err := handler.identities.GetIdentity(ctx, params.LocalAgentID)
	if err != nil {
		return struct{}{}, err
	}
	_, err = handler.pairing.ApplyActivationReceipt(ctx, localIdentity, params.Receipt)
	return struct{}{}, err
}

func (handler *Handler) listContacts(ctx context.Context, params ContactParams) (any, error) {
	if params.LocalAgentID == "" {
		return nil, fmt.Errorf("%w: localAgentId is required", ipc.ErrInvalidRequest)
	}
	return handler.store.ListContacts(ctx, params.LocalAgentID)
}

func (handler *Handler) revokeContact(ctx context.Context, params ContactParams) (ContactRevokeResult, error) {
	localIdentity, err := handler.identities.GetIdentity(ctx, params.LocalAgentID)
	if err != nil {
		return ContactRevokeResult{}, err
	}
	notice, _, err := handler.pairing.RevokeWithNotice(ctx, localIdentity, params.RemoteAgentID, params.Reason)
	return ContactRevokeResult{Notice: notice}, err
}

func (handler *Handler) applyRevocation(ctx context.Context, params ApplyRevocationParams) (struct{}, error) {
	localIdentity, err := handler.identities.GetIdentity(ctx, params.LocalAgentID)
	if err != nil {
		return struct{}{}, err
	}
	_, err = handler.pairing.ApplyRevocation(ctx, localIdentity, params.Notice)
	return struct{}{}, err
}

func (handler *Handler) blockContact(ctx context.Context, params ContactParams) (struct{}, error) {
	if params.LocalAgentID == "" || params.RemoteAgentID == "" {
		return struct{}{}, fmt.Errorf("%w: localAgentId and remoteAgentId are required", ipc.ErrInvalidRequest)
	}
	_, err := handler.pairing.Block(ctx, params.LocalAgentID, params.RemoteAgentID)
	return struct{}{}, err
}

func (handler *Handler) doctor(ctx context.Context) (DoctorResult, error) {
	checks := []DoctorCheck{{Name: "database", OK: true}}
	if _, err := handler.store.ListAgentRegistrations(ctx); err != nil {
		checks[0] = DoctorCheck{Name: "database", OK: false, Message: err.Error()}
	}
	registrations, registrationErr := handler.store.ListAgentRegistrations(ctx)
	identityOK := registrationErr == nil
	identityMessage := ""
	for _, registrationValue := range registrations {
		if _, err := handler.identities.GetIdentity(ctx, registrationValue.AgentID); err != nil {
			identityOK = false
			identityMessage = err.Error()
			break
		}
		if provider, ok := handler.identities.(CapabilityKeyProvider); ok && len(registrationValue.CapabilityPublicKey) > 0 {
			if _, err := provider.GetCapabilityKey(ctx, registrationValue.AgentID); err != nil {
				identityOK = false
				identityMessage = err.Error()
				break
			}
		}
	}
	checks = append(checks, DoctorCheck{Name: "agent_keys", OK: identityOK, Message: identityMessage})
	status, _ := handler.handleStatus(ctx)
	checks = append(checks,
		DoctorCheck{Name: "tailscale_address", OK: status.TailscaleAddress != "", Message: missingMessage(status.TailscaleAddress, "Tailscale address is not configured")},
		DoctorCheck{Name: "tailscale_login", OK: status.TailscaleLoggedIn, Message: boolFailureMessage(status.TailscaleLoggedIn, "Tailscale is not logged in")},
		DoctorCheck{Name: "tailscale_local_api", OK: status.TailscaleLocalAPIReady, Message: boolFailureMessage(status.TailscaleLocalAPIReady, "Tailscale Local API is unavailable")},
		DoctorCheck{Name: "tailscale_whois", OK: status.TailscaleWhoIsReady, Message: boolFailureMessage(status.TailscaleWhoIsReady, "Tailscale WhoIs is unavailable")},
	)
	result := DoctorResult{OK: true, Checks: checks}
	for _, check := range checks {
		result.OK = result.OK && check.OK
	}
	return result, nil
}

func boolFailureMessage(ok bool, message string) string {
	if ok {
		return ""
	}
	return message
}

func missingMessage(value, message string) string {
	if value == "" {
		return message
	}
	return ""
}

func decodeAndCall[P any, R any](ctx context.Context, raw json.RawMessage, function func(context.Context, P) (R, error)) (R, error) {
	var params P
	if len(raw) == 0 || string(raw) == "null" {
		var zero R
		return zero, ipc.ErrInvalidRequest
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		var zero R
		return zero, fmt.Errorf("%w: %v", ipc.ErrInvalidRequest, err)
	}
	return function(ctx, params)
}
