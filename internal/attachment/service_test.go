package attachment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
)

func TestUploadResumesAndVerifiesChecksum(t *testing.T) {
	data := []byte("hello attachment")
	digest := sha256.Sum256(data)
	service, err := NewService(t.TempDir(), 1024, 32)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := service.Init("agent-a", "note.txt", "text/plain", hex.EncodeToString(digest[:]), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err = service.PutChunk("agent-a", metadata.BlobID, 0, data[:5])
	if err != nil || metadata.Received != 5 {
		t.Fatalf("first chunk: %v %+v", err, metadata)
	}
	metadata, err = service.PutChunk("agent-a", metadata.BlobID, metadata.Received, data[5:])
	if err != nil || metadata.Received != int64(len(data)) {
		t.Fatalf("second chunk: %v %+v", err, metadata)
	}
	metadata, err = service.Complete("agent-a", metadata.BlobID)
	if err != nil || metadata.State != StateCompleted {
		t.Fatalf("complete: %v %+v", err, metadata)
	}
	if _, err := service.PutChunk("agent-a", metadata.BlobID, 0, data); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected completed upload rejection, got %v", err)
	}
}

func TestUploadRejectsWrongOwnerAndOffset(t *testing.T) {
	service, err := NewService(t.TempDir(), 1024, 16)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := service.Init("agent-a", "file", "application/octet-stream", hex.EncodeToString(make([]byte, 32)), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PutChunk("agent-b", metadata.BlobID, 0, []byte("x")); !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("expected owner rejection, got %v", err)
	}
	if _, err := service.PutChunk("agent-a", metadata.BlobID, 1, []byte("x")); !errors.Is(err, ErrInvalidOffset) {
		t.Fatalf("expected offset rejection, got %v", err)
	}
}

func TestUploadResumesAfterServiceRestart(t *testing.T) {
	root := t.TempDir()
	data := []byte("resume after sender restart")
	digest := sha256.Sum256(data)
	service, err := NewService(root, 1024, 8)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := service.Init("agent-a", "resume.txt", "text/plain", hex.EncodeToString(digest[:]), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err = service.PutChunk("agent-a", metadata.BlobID, 0, data[:8])
	if err != nil {
		t.Fatal(err)
	}
	service, err = NewService(root, 1024, 8)
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.Status("agent-a", metadata.BlobID)
	if err != nil || status.Received != 8 {
		t.Fatalf("restore upload status: %v %+v", err, status)
	}
	for status.Received < status.Size {
		end := status.Received + 8
		if end > status.Size {
			end = status.Size
		}
		status, err = service.PutChunk("agent-a", status.BlobID, status.Received, data[status.Received:end])
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Complete("agent-a", status.BlobID); err != nil {
		t.Fatal(err)
	}
}

func TestReceiverResumesSignedRangeDownloadAfterRestart(t *testing.T) {
	owner, err := identity.Generate("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	receiverIdentity, err := identity.Generate("agent-b")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("signed remote attachment resume")
	digest := sha256.Sum256(data)
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if _, err := VerifyBlobRequest(request, receiverIdentity.AgentID(), owner.AgentID(), receiverIdentity.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
			http.Error(response, "invalid signature", http.StatusForbidden)
			return
		}
		start, end, err := ParseRange(request.Header.Get("Range"), int64(len(data)), 8)
		if err != nil {
			http.Error(response, "invalid range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		body := data[start : end+1]
		response.Header().Set("Content-Range", ContentRange(start, end, int64(len(data))))
		response.Header().Set("ETag", `"sha256:`+hex.EncodeToString(digest[:])+`"`)
		if err := SignBlobResponse(response.Header(), http.StatusPartialContent, body, owner); err != nil {
			t.Fatal(err)
		}
		response.WriteHeader(http.StatusPartialContent)
		_, _ = response.Write(body)
	})
	baseTransport := handlerRoundTripper{handler: handler}

	root := t.TempDir()
	spec := DownloadSpec{
		URL: "http://100.64.0.1:7443/agents/agent-a/blobs/blob-1", GrantID: "grant-1",
		BlobID: "blob-1", OwnerAgentID: owner.AgentID(), ReceiverAgentID: receiverIdentity.AgentID(),
		ContextID: "context-1", Digest: hex.EncodeToString(digest[:]), Size: int64(len(data)),
		OwnerPublicKey: owner.PublicKey(),
	}
	failingClient := &http.Client{Transport: &failAfterRoundTripper{base: baseTransport, remaining: 1}}
	first, err := NewReceiver(root, 8, failingClient)
	if err != nil {
		t.Fatal(err)
	}
	status, err := first.Receive(context.Background(), spec, receiverIdentity)
	if err == nil || status.Received != 8 {
		t.Fatalf("expected interrupted first receive at 8 bytes, got %v %+v", err, status)
	}
	second, err := NewReceiver(root, 8, &http.Client{Transport: baseTransport})
	if err != nil {
		t.Fatal(err)
	}
	status, err = second.Receive(context.Background(), spec, receiverIdentity)
	if err != nil {
		t.Fatalf("resume receive: %v", err)
	}
	if status.Received != int64(len(data)) || status.State != StateCompleted {
		t.Fatalf("unexpected completed status: %+v", status)
	}
	content, err := os.ReadFile(filepath.Join(root, "blob-1.blob"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(data) {
		t.Fatalf("unexpected downloaded content: %q", content)
	}
}

type failAfterRoundTripper struct {
	base      http.RoundTripper
	remaining int
}

type handlerRoundTripper struct {
	handler http.Handler
}

func (roundTripper handlerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	roundTripper.handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

func (roundTripper *failAfterRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if roundTripper.remaining == 0 {
		return nil, errors.New("simulated receiver restart")
	}
	roundTripper.remaining--
	return roundTripper.base.RoundTrip(request)
}
