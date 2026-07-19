package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/attachment"
	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/registration"
	"github.com/EvanSener/snw-agent-link/internal/store"
	"github.com/EvanSener/snw-agent-link/internal/tailscale"
	"github.com/EvanSener/snw-agent-link/internal/transport"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

type Router struct {
	store          *store.Store
	registrations  *registration.Service
	attachments    *attachment.Service
	dedupMu        sync.Mutex
	whois          tailscale.WhoIsProvider
	requireWhoIs   bool
	responseSigner transport.ResponseSignerResolver
}

func NewRouter(database *store.Store, registrations *registration.Service, responseSigners ...transport.ResponseSignerResolver) (*Router, error) {
	if database == nil || registrations == nil {
		return nil, errors.New("gateway dependencies are required")
	}
	attachments, err := attachment.NewService(filepath.Join(filepath.Dir(database.Path()), "attachments"), 1<<30, 4<<20)
	if err != nil {
		return nil, fmt.Errorf("initialize gateway attachments: %w", err)
	}
	router := &Router{store: database, registrations: registrations, attachments: attachments}
	if len(responseSigners) > 0 {
		router.responseSigner = responseSigners[0]
	}
	return router, nil
}

// NewRouterWithWhoIs constructs the production router. A Local API WhoIs
// provider is mandatory so peer admission cannot silently fall back to Agent
// signatures alone. The optional response signer is used for signed A2A
// responses, matching NewRouter's test-only constructor.
func NewRouterWithWhoIs(database *store.Store, registrations *registration.Service, provider tailscale.WhoIsProvider, responseSigners ...transport.ResponseSignerResolver) (*Router, error) {
	if provider == nil {
		return nil, errors.New("tailscale WhoIs provider is required")
	}
	router, err := NewRouter(database, registrations, responseSigners...)
	if err != nil {
		return nil, err
	}
	router.whois = provider
	router.requireWhoIs = true
	return router, nil
}

func (r *Router) SetAttachmentService(service *attachment.Service) {
	if service != nil {
		r.attachments = service
	}
}

func (r *Router) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", r.health)
	mux.HandleFunc("GET /agents/{agentID}/agent-card.json", r.agentCard)
	mux.HandleFunc("GET /agents/{agentID}/blobs/{blobID}", r.blob)
	mux.Handle("/agents/", http.HandlerFunc(r.a2a))
	if r.responseSigner != nil {
		return transport.NewResponseSigningMiddleware(r.responseSigner)(mux)
	}
	return mux
}

func (r *Router) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (r *Router) agentCard(w http.ResponseWriter, req *http.Request) {
	agentID := req.PathValue("agentID")
	registration, err := r.store.GetAgentRegistration(req.Context(), agentID)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	card, err := decodeAgentCard(registration.AgentCardJSON)
	if err != nil {
		http.Error(w, "invalid agent card", http.StatusInternalServerError)
		return
	}
	if len(card.SupportedInterfaces) == 0 {
		card.SupportedInterfaces = []*a2a.AgentInterface{{URL: strings.TrimRight(requestBaseURL(req), "/") + "/agents/" + agentID + "/a2a/rest"}}
	}
	card = publicAgentCard(card)
	if len(registration.IdentityPublicKey) == ed25519.PublicKeySize {
		w.Header().Set("X-SNW-Agent-Key-Fingerprint", identity.Fingerprint(ed25519.PublicKey(registration.IdentityPublicKey)))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(card)
}

func publicAgentCard(card *a2a.AgentCard) *a2a.AgentCard {
	if card == nil {
		return &a2a.AgentCard{}
	}
	return &a2a.AgentCard{
		SupportedInterfaces: card.SupportedInterfaces,
		Capabilities:        card.Capabilities,
		Name:                card.Name,
		Version:             card.Version,
	}
}

func (r *Router) a2a(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "agents" {
		http.NotFound(w, req)
		return
	}
	localAgentID := parts[1]
	registration, err := r.store.GetAgentRegistration(req.Context(), localAgentID)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	if len(parts) >= 4 && parts[2] == "a2a" && parts[3] == "rest" {
		if !r.authorized(req, localAgentID) {
			http.Error(w, "agent pairing is required", http.StatusForbidden)
			return
		}
		handler, err := newForwardingHandler(registration, req.Header.Get("X-SNW-Agent-ID"))
		if err != nil {
			http.Error(w, "local agent endpoint is unavailable", http.StatusBadGateway)
			return
		}
		r.serveA2AWithDedup(w, req, handler, localAgentID, false)
		return
	}
	if len(parts) >= 4 && parts[2] == "a2a" && parts[3] == "jsonrpc" {
		if !r.authorized(req, localAgentID) {
			http.Error(w, "agent pairing is required", http.StatusForbidden)
			return
		}
		handler, err := newForwardingHandler(registration, req.Header.Get("X-SNW-Agent-ID"))
		if err != nil {
			http.Error(w, "local agent endpoint is unavailable", http.StatusBadGateway)
			return
		}
		r.serveA2AWithDedup(w, req, handler, localAgentID, true)
		return
	}
	http.NotFound(w, req)
}

func (r *Router) serveA2AWithDedup(w http.ResponseWriter, req *http.Request, handler *forwardingHandler, localAgentID string, jsonRPC bool) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 16<<20))
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	remoteAgentID := req.Header.Get("X-SNW-Agent-ID")
	messageID := inboundMessageID(body, jsonRPC)
	if messageID == "" {
		r.forwardA2A(w, req, handler, localAgentID, jsonRPC)
		return
	}
	const keyEpoch uint64 = 0
	if existing, lookupErr := r.store.GetScopedDeduplication(req.Context(), remoteAgentID, localAgentID, keyEpoch, messageID); lookupErr == nil {
		if existing.ResponseStatus > 0 && len(existing.ResponseBody) > 0 {
			if existing.ResponseType != "" {
				w.Header().Set("Content-Type", existing.ResponseType)
			}
			w.WriteHeader(existing.ResponseStatus)
			_, _ = w.Write(existing.ResponseBody)
			return
		}
		// A concurrent first delivery is still being processed. Returning the
		// reserved task id is safe and prevents a second execution.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, fmt.Sprintf(`{"id":%q,"status":{"state":"working"}}`, existing.TaskID))
		return
	}
	reservation := string(a2a.NewTaskID())
	created, recordErr := r.store.RecordScopedMessageOnce(req.Context(), remoteAgentID, localAgentID, keyEpoch, messageID, reservation)
	if recordErr != nil {
		http.Error(w, "deduplication unavailable", http.StatusInternalServerError)
		return
	}
	if !created {
		r.serveA2AWithDedup(w, req, handler, localAgentID, jsonRPC)
		return
	}
	contextID := inboundContextID(body, jsonRPC)
	if contextID == "" {
		contextID = messageID
	}
	if remoteAgentID != "" && contextID != "" {
		if err := r.store.RecordInboxMessage(req.Context(), model.InboxMessage{
			TargetAgentID: localAgentID,
			SourceAgentID: remoteAgentID,
			MessageID:     messageID,
			ContextID:     contextID,
			Body:          string(body),
		}); err != nil {
			http.Error(w, "inbox persistence unavailable", http.StatusInternalServerError)
			return
		}
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	r.forwardA2A(recorder, req, handler, localAgentID, jsonRPC)
	responseBody := append([]byte(nil), recorder.Body.Bytes()...)
	actualTaskID := taskIDFromResponse(responseBody)
	if actualTaskID == "" {
		actualTaskID = reservation
	}
	contentType := recorder.Header().Get("Content-Type")
	_ = r.store.CompleteScopedMessage(req.Context(), remoteAgentID, localAgentID, keyEpoch, messageID, actualTaskID, recorder.Code, contentType, responseBody)
	copyResponse(w, recorder)
}

func (r *Router) forwardA2A(w http.ResponseWriter, req *http.Request, handler *forwardingHandler, localAgentID string, jsonRPC bool) {
	if jsonRPC {
		a2asrv.NewJSONRPCHandler(handler).ServeHTTP(w, reqWithTrimmedPath(req, "/agents/"+localAgentID+"/a2a/jsonrpc"))
		return
	}
	a2asrv.NewRESTHandler(handler).ServeHTTP(w, reqWithTrimmedPath(req, "/agents/"+localAgentID+"/a2a/rest"))
}

func inboundMessageID(body []byte, jsonRPC bool) string {
	var envelope struct {
		Message *struct {
			ID string `json:"messageId"`
		} `json:"message"`
		Params *struct {
			Message *struct {
				ID string `json:"messageId"`
			} `json:"message"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	if jsonRPC && envelope.Params != nil && envelope.Params.Message != nil {
		return envelope.Params.Message.ID
	}
	if envelope.Message != nil {
		return envelope.Message.ID
	}
	return ""
}

func inboundContextID(body []byte, jsonRPC bool) string {
	var envelope struct {
		Message *struct {
			ContextID string `json:"contextId"`
		} `json:"message"`
		Params *struct {
			Message *struct {
				ContextID string `json:"contextId"`
			} `json:"message"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	if jsonRPC && envelope.Params != nil && envelope.Params.Message != nil {
		return envelope.Params.Message.ContextID
	}
	if envelope.Message != nil {
		return envelope.Message.ContextID
	}
	return ""
}

func taskIDFromResponse(body []byte) string {
	var value struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &value) == nil && value.ID != "" {
		return value.ID
	}
	var rpc struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &rpc) == nil {
		return rpc.Result.ID
	}
	return ""
}

func copyResponse(w http.ResponseWriter, recorder *httptest.ResponseRecorder) {
	for key, values := range recorder.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(recorder.Code)
	_, _ = w.Write(recorder.Body.Bytes())
}

func (r *Router) authorized(req *http.Request, localAgentID string) bool {
	var body []byte
	var err error
	if req.Body != nil {
		body, err = io.ReadAll(io.LimitReader(req.Body, 16<<20))
		if err != nil {
			return false
		}
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	remoteAgentID := req.Header.Get("X-SNW-Agent-ID")
	if remoteAgentID == "" || remoteAgentID == localAgentID {
		return false
	}
	contact, err := r.store.GetContact(req.Context(), localAgentID, remoteAgentID)
	if activeContactError(contact, err) != nil {
		return false
	}
	keyRaw, err := base64.RawURLEncoding.DecodeString(req.Header.Get("X-SNW-Agent-Public-Key"))
	if err != nil || len(keyRaw) != ed25519.PublicKeySize {
		return false
	}
	publicKey := ed25519.PublicKey(keyRaw)
	if identity.Fingerprint(publicKey) != contact.RemoteAgentFingerprint {
		return false
	}
	if r.requireWhoIs {
		if r.whois == nil || contact.RemoteNodeID == "" {
			return false
		}
		sourceAddress := remoteAddress(req)
		peer, err := r.whois.WhoIs(req.Context(), sourceAddress)
		if err != nil || peer.StableNodeID != contact.RemoteNodeID || !peer.HasAddress(sourceAddress) {
			return false
		}
	} else if r.whois != nil && contact.RemoteNodeID != "" {
		peer, err := r.whois.WhoIs(req.Context(), remoteAddress(req))
		if err != nil || (peer.StableNodeID != contact.RemoteNodeID && peer.NodeID != contact.RemoteNodeID) {
			return false
		}
	}
	nonce, err := transport.VerifyRequestForTarget(req, remoteAgentID, localAgentID, publicKey, time.Now().UTC(), 5*time.Minute)
	if err != nil {
		return false
	}
	replayClaimed, err := r.store.ClaimReplayNonce(req.Context(), localAgentID, remoteAgentID, nonce, time.Now().UTC().Add(5*time.Minute), time.Now().UTC())
	return err == nil && replayClaimed
}

func remoteAddress(req *http.Request) string {
	if req == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return req.RemoteAddr
}

func requestBaseURL(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + req.Host
}

func reqWithTrimmedPath(req *http.Request, prefix string) *http.Request {
	clone := req.Clone(context.Background())
	clone.URL.Path = strings.TrimPrefix(clone.URL.Path, prefix)
	if clone.URL.Path == "" {
		clone.URL.Path = "/"
	}
	return clone
}
