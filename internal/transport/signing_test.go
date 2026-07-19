package transport

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
)

func TestSignedRoundTripperAddsRFC9421Signature(t *testing.T) {
	signer, err := identity.Generate("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	var captured *http.Request
	base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		captured = request
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: request}, nil
	})
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:7781/a2a/message:send?x=1", strings.NewReader(`{"message":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (SignedRoundTripper{Base: base, Identity: signer, TargetAgent: "agent-b"}).RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	if captured.Header.Get("X-SNW-Agent-ID") != "agent-a" || captured.Header.Get("X-SNW-Target-Agent-ID") != "agent-b" || captured.Header.Get("Signature") == "" || captured.Header.Get("Signature-Input") == "" {
		t.Fatalf("missing signed headers: %v", captured.Header)
	}
	if _, err := VerifyRequestForTarget(captured, "agent-a", "agent-b", signer.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("verify signed request: %v", err)
	}
	if len(signer.PublicKey()) != ed25519.PublicKeySize {
		t.Fatal("unexpected public key")
	}
}

func TestResponseSigningMiddlewareSignsCompleteBody(t *testing.T) {
	signer, err := identity.Generate("agent-response")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewResponseSigningMiddleware(func(*http.Request) (Signer, error) {
		return signer, nil
	})(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	request, err := http.NewRequest(http.MethodGet, "https://100.64.0.1/agents/target", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	result := response.Result()
	defer result.Body.Close()
	if result.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected status: %d", result.StatusCode)
	}
	if err := VerifyResponse(result, signer.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("verify signed response: %v", err)
	}
	if result.Header.Get("Content-Digest") == "" {
		t.Fatal("missing response content digest")
	}
}

func TestResponseSigningMiddlewareSignsSSEEventsAndFinalResponse(t *testing.T) {
	signer, err := identity.Generate("agent-sse-response")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewResponseSigningMiddleware(func(*http.Request) (Signer, error) {
		return signer, nil
	})(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write([]byte("data: one\n\ndata: two\n\n"))
	}))
	request := httptest.NewRequest(http.MethodGet, "https://100.64.0.1/agents/target/a2a/rest", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	result := response.Result()
	defer result.Body.Close()
	if err := VerifyResponse(result, signer.PublicKey(), time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("verify final SSE response: %v", err)
	}
	if result.Header.Get("X-SNW-SSE-Signed") == "" {
		t.Fatal("missing SSE signed marker")
	}
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	frames := bytes.Split(body, []byte("\n\n"))
	var previous []byte
	count := 0
	for _, raw := range frames {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		event, signed, parseErr := ParseSignedSSEFrame(append(append([]byte(nil), raw...), '\n', '\n'))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		previous, err = VerifySSEEvent(event, signed, previous, signer.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("expected two signed SSE events, got %d", count)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
