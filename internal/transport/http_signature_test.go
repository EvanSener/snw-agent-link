package transport

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
)

func TestRFC9421RequestBindsTargetAgentAndRFC9530Digest(t *testing.T) {
	signer, err := identity.Generate("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://100.64.0.2/agents/agent-b/a2a/rest/message:send", strings.NewReader(`{"message":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request, signer, "agent-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequestForTarget(request, "agent-a", "agent-b", signer.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
		t.Fatal(err)
	}
	request.Header.Set(targetAgentIDHeader, "agent-c")
	if _, err := VerifyRequestForTarget(request, "agent-a", "agent-b", signer.PublicKey(), time.Now().UTC(), time.Minute); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected target binding failure, got %v", err)
	}
	request.Header.Set(targetAgentIDHeader, "agent-b")
	request.Body = io.NopCloser(strings.NewReader(`{"message":{"tampered":true}}`))
	if _, err := VerifyRequestForTarget(request, "agent-a", "agent-b", signer.PublicKey(), time.Now().UTC(), time.Minute); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestRFC9421ResponseBindsAgentStatusAndBody(t *testing.T) {
	signer, err := identity.Generate("agent-b")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"status":"ok"}`)
	headers := make(http.Header)
	if err := SignResponse(headers, http.StatusAccepted, body, signer); err != nil {
		t.Fatal(err)
	}
	response := &http.Response{StatusCode: http.StatusAccepted, Header: headers, Body: io.NopCloser(strings.NewReader(string(body)))}
	if err := VerifyResponseForAgent(response, "agent-b", signer.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(strings.NewReader(`{"status":"tampered"}`))
	if err := VerifyResponseForAgent(response, "agent-b", signer.PublicKey(), time.Now().UTC(), time.Minute); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
	response.Body = io.NopCloser(strings.NewReader(string(body)))
	if err := VerifyResponseForAgent(response, "agent-c", signer.PublicKey(), time.Now().UTC(), time.Minute); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected response agent mismatch, got %v", err)
	}
}

func TestRFC9421RejectsMalformedSignatureField(t *testing.T) {
	signer, err := identity.Generate("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://100.64.0.2/agents/agent-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request, signer, "agent-b"); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Signature", strings.Trim(request.Header.Get("Signature"), ":"))
	if _, err := VerifyRequestForTarget(request, "agent-a", "agent-b", signer.PublicKey(), time.Now().UTC(), time.Minute); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected malformed signature rejection, got %v", err)
	}
}
