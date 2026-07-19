package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/attachment"
	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/registration"
	"github.com/EvanSener/snw-agent-link/internal/store"
	"github.com/EvanSener/snw-agent-link/internal/transport"
)

func TestBlobRouteValidatesContactSignatureGrantAndReplay(t *testing.T) {
	fixture := newBlobFixture(t)
	request := fixture.request(t, "bytes=0-7")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusPartialContent || response.Body.String() != string(fixture.data[:8]) {
		t.Fatalf("unexpected blob response %d: %q", response.Code, response.Body.String())
	}
	if err := attachment.VerifyBlobResponse(response.Result(), fixture.owner.AgentID(), fixture.owner.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("verify signed blob response: %v", err)
	}

	replay := httptest.NewRecorder()
	fixture.handler.ServeHTTP(replay, request)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("expected replay rejection, got %d", replay.Code)
	}
	if err := attachment.VerifyBlobResponse(replay.Result(), fixture.owner.AgentID(), fixture.owner.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("verify signed replay response: %v", err)
	}
}

func TestBlobRouteRejectsTamperedRangeAndRevokedGrant(t *testing.T) {
	fixture := newBlobFixture(t)
	tampered := fixture.request(t, "bytes=0-3")
	tampered.Header.Set("Range", "bytes=4-7")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, tampered)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected tampered range rejection, got %d", response.Code)
	}
	if err := fixture.database.RevokeAttachmentGrant(context.Background(), fixture.grant.GrantID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.request(t, "bytes=0-3"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected revoked grant rejection, got %d", response.Code)
	}
}

type blobFixture struct {
	database *store.Store
	handler  http.Handler
	owner    *identity.Identity
	receiver *identity.Identity
	grant    model.AttachmentGrant
	data     []byte
}

func newBlobFixture(t *testing.T) blobFixture {
	t.Helper()
	root := t.TempDir()
	database, err := store.Open(filepath.Join(root, "agent-link.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	owner, err := identity.Generate("agent-owner")
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := identity.Generate("agent-receiver")
	if err != nil {
		t.Fatal(err)
	}
	registrations := registration.NewService(database)
	if _, _, err := registrations.Register(context.Background(), registration.Input{
		AgentID: owner.AgentID(), DisplayName: "Owner", LocalEndpoint: "http://127.0.0.1:7781/a2a",
		AgentCardJSON: []byte(`{"name":"Owner"}`), IdentityPublicKey: owner.PublicKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertContact(context.Background(), model.Contact{
		LocalAgentID: owner.AgentID(), RemoteAgentID: receiver.AgentID(),
		RemoteAgentFingerprint: identity.Fingerprint(receiver.PublicKey()), State: model.ContactStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	attachments, err := attachment.NewService(filepath.Join(root, "attachments"), 1024, 8)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("paired blob range")
	digest := sha256.Sum256(data)
	metadata, err := attachments.Init(owner.AgentID(), "private-note.txt", "text/plain", hex.EncodeToString(digest[:]), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for metadata.Received < metadata.Size {
		end := metadata.Received + 8
		if end > metadata.Size {
			end = metadata.Size
		}
		metadata, err = attachments.PutChunk(owner.AgentID(), metadata.BlobID, metadata.Received, data[metadata.Received:end])
		if err != nil {
			t.Fatal(err)
		}
	}
	metadata, err = attachments.Complete(owner.AgentID(), metadata.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := attachments.Grant(owner.AgentID(), metadata.BlobID, receiver.AgentID(), "context-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateAttachmentGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(database, registrations, func(*http.Request) (transport.Signer, error) {
		return owner, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return blobFixture{database: database, handler: router.Handler(), owner: owner, receiver: receiver, grant: grant, data: data}
}

func (fixture blobFixture) request(t *testing.T, byteRange string) *http.Request {
	t.Helper()
	query := url.Values{"grant": {fixture.grant.GrantID}, "context": {fixture.grant.ContextID}, "digest": {fixture.grant.Digest}}
	request := httptest.NewRequest(http.MethodGet,
		"https://100.64.0.1:7443/agents/"+fixture.owner.AgentID()+"/blobs/"+fixture.grant.BlobID+"?"+query.Encode(), nil)
	request.Header.Set("Range", byteRange)
	if err := attachment.SignBlobRequest(request, fixture.receiver, fixture.owner.AgentID()); err != nil {
		t.Fatal(err)
	}
	return request
}
