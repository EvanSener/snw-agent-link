package transport

import (
	"bytes"
	"errors"
	"testing"

	"github.com/EvanSener/snw-agent-link/internal/identity"
)

func TestSSEEventSignerBuildsAndVerifiesHashChain(t *testing.T) {
	signer, err := identity.Generate("agent-sse")
	if err != nil {
		t.Fatal(err)
	}
	eventSigner, err := NewSSEEventSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	first, err := eventSigner.Frame([]byte("event: message\ndata: one\n\n"), "cursor-1")
	if err != nil {
		t.Fatal(err)
	}
	event, signed, err := ParseSignedSSEFrame(first)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := VerifySSEEvent(event, signed, nil, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	second, err := eventSigner.Frame([]byte("event: message\ndata: two\n\n"), "cursor-2")
	if err != nil {
		t.Fatal(err)
	}
	secondEvent, secondSigned, err := ParseSignedSSEFrame(second)
	if err != nil {
		t.Fatal(err)
	}
	next, err := VerifySSEEvent(secondEvent, secondSigned, previous, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(previous, next) {
		t.Fatal("hash chain did not advance")
	}
}

func TestSSEEventSignerResumesFromPreviousHash(t *testing.T) {
	signer, err := identity.Generate("agent-sse")
	if err != nil {
		t.Fatal(err)
	}
	firstSigner, err := NewSSEEventSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstSigner.Sign([]byte("data: one\n\n"), "cursor-1")
	if err != nil {
		t.Fatal(err)
	}
	previous, err := VerifySSEEvent([]byte("data: one\n\n"), first, nil, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := NewSSEEventSignerWithPreviousHash(signer, previous)
	if err != nil {
		t.Fatal(err)
	}
	second, err := resumed.Sign([]byte("data: two\n\n"), "cursor-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySSEEvent([]byte("data: two\n\n"), second, previous, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestSSEEventSignerRejectsTamperingAndCursorInjection(t *testing.T) {
	signer, err := identity.Generate("agent-sse")
	if err != nil {
		t.Fatal(err)
	}
	eventSigner, err := NewSSEEventSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := eventSigner.Frame([]byte("data: safe\n\n"), "cursor-1")
	if err != nil {
		t.Fatal(err)
	}
	event, signed, err := ParseSignedSSEFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	event[bytes.Index(event, []byte("safe"))] = 'x'
	if _, err := VerifySSEEvent(event, signed, nil, signer.PublicKey()); !errors.Is(err, ErrSSEHashChain) {
		t.Fatalf("expected hash-chain failure, got %v", err)
	}
	if _, err := eventSigner.Sign([]byte("data: bad\n\n"), "cursor\nforged"); !errors.Is(err, ErrInvalidSSECursor) {
		t.Fatalf("expected cursor validation failure, got %v", err)
	}
}

func TestSSEEventSignerNormalizesEventBoundaryBeforeSigning(t *testing.T) {
	signer, err := identity.Generate("agent-sse")
	if err != nil {
		t.Fatal(err)
	}
	eventSigner, err := NewSSEEventSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := eventSigner.Frame([]byte("data: no-boundary"), "cursor-1")
	if err != nil {
		t.Fatal(err)
	}
	event, signed, err := ParseSignedSSEFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(event, []byte("\n\n")) {
		t.Fatalf("event boundary was not normalized: %q", event)
	}
	if _, err := VerifySSEEvent(event, signed, nil, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestParseSignedSSEFrameRequiresAllSignatureComments(t *testing.T) {
	if _, _, err := ParseSignedSSEFrame([]byte(": snw-cursor=cursor-1\ndata: one\n\n")); !errors.Is(err, ErrInvalidSSEEvent) {
		t.Fatalf("expected missing metadata failure, got %v", err)
	}
}

func TestSignSSEStreamSignsEveryEvent(t *testing.T) {
	signer, err := identity.Generate("agent-sse-stream")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := SignSSEStream([]byte("data: one\n\ndata: two\n\n"), signer, "")
	if err != nil {
		t.Fatal(err)
	}
	frames := bytes.Split(stream, []byte("\n\n"))
	var previous []byte
	count := 0
	for _, raw := range frames {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		frame := append(append([]byte(nil), raw...), '\n', '\n')
		event, signed, parseErr := ParseSignedSSEFrame(frame)
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
