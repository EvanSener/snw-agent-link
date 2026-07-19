package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/attachment"
	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/transport"
)

func (r *Router) blob(response http.ResponseWriter, request *http.Request) {
	ownerAgentID := request.PathValue("agentID")
	blobID := request.PathValue("blobID")
	if _, err := r.store.GetAgentRegistration(request.Context(), ownerAgentID); err != nil {
		http.NotFound(response, request)
		return
	}
	remoteAgentID := request.Header.Get("X-SNW-Agent-ID")
	contact, contactErr := r.store.GetContact(request.Context(), ownerAgentID, remoteAgentID)
	if remoteAgentID == "" || remoteAgentID == ownerAgentID || activeContactError(contact, contactErr) != nil {
		r.writeBlobError(response, request, http.StatusForbidden, "BLOB_FORBIDDEN")
		return
	}
	publicKeyRaw, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-SNW-Agent-Public-Key"))
	if err != nil || len(publicKeyRaw) != ed25519.PublicKeySize {
		r.writeBlobError(response, request, http.StatusForbidden, "BLOB_FORBIDDEN")
		return
	}
	publicKey := ed25519.PublicKey(publicKeyRaw)
	if identity.Fingerprint(publicKey) != contact.RemoteAgentFingerprint {
		r.writeBlobError(response, request, http.StatusForbidden, "BLOB_FORBIDDEN")
		return
	}
	now := time.Now().UTC()
	nonce, err := attachment.VerifyBlobRequest(request, remoteAgentID, ownerAgentID, publicKey, now, 5*time.Minute)
	if err != nil {
		r.writeBlobError(response, request, http.StatusForbidden, "BLOB_FORBIDDEN")
		return
	}
	claimed, err := r.store.ClaimReplayNonce(request.Context(), ownerAgentID, remoteAgentID, nonce, now.Add(5*time.Minute), now)
	if err != nil || !claimed {
		r.writeBlobError(response, request, http.StatusForbidden, "BLOB_FORBIDDEN")
		return
	}
	query := request.URL.Query()
	grant, err := r.store.AuthorizeAttachmentGrant(request.Context(), query.Get("grant"), blobID, ownerAgentID,
		remoteAgentID, query.Get("context"), query.Get("digest"), now)
	if err != nil {
		r.writeBlobError(response, request, http.StatusForbidden, "BLOB_FORBIDDEN")
		return
	}
	start, end, err := attachment.ParseRange(request.Header.Get("Range"), grant.Size, r.attachments.ChunkSize())
	if err != nil {
		r.writeBlobError(response, request, http.StatusRequestedRangeNotSatisfiable, "BLOB_RANGE_INVALID")
		return
	}
	metadata, content, err := r.attachments.ReadRange(ownerAgentID, blobID, start, end)
	if err != nil || metadata.SHA256 != grant.Digest || metadata.Size != grant.Size {
		r.writeBlobError(response, request, http.StatusNotFound, "BLOB_UNAVAILABLE")
		return
	}
	response.Header().Set("Accept-Ranges", "bytes")
	response.Header().Set("Content-Type", metadata.MediaType)
	response.Header().Set("Content-Range", attachment.ContentRange(start, end, metadata.Size))
	response.Header().Set("Content-Length", strconv.Itoa(len(content)))
	response.Header().Set("ETag", `"sha256:`+metadata.SHA256+`"`)
	response.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", metadata.Name))
	if signer := r.responseSignerFor(request); signer != nil {
		if err := attachment.SignBlobResponse(response.Header(), http.StatusPartialContent, content, signer); err != nil {
			r.writeBlobError(response, request, http.StatusInternalServerError, "BLOB_SIGNING_FAILED")
			return
		}
	}
	response.WriteHeader(http.StatusPartialContent)
	_, _ = response.Write(content)
}

func (r *Router) writeBlobError(response http.ResponseWriter, request *http.Request, status int, code string) {
	body, _ := json.Marshal(struct {
		Code string `json:"code"`
	}{Code: code})
	response.Header().Set("Content-Type", "application/json")
	if signer := r.responseSignerFor(request); signer != nil {
		_ = attachment.SignBlobResponse(response.Header(), status, body, signer)
	}
	response.WriteHeader(status)
	_, _ = response.Write(body)
}

func (r *Router) responseSignerFor(request *http.Request) transport.Signer {
	if r.responseSigner == nil {
		return nil
	}
	signer, err := r.responseSigner(request)
	if err != nil {
		return nil
	}
	return signer
}
