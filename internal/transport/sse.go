package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const sseSignatureDomain = "snw-agent-link-sse-v1\x00"

var (
	ErrInvalidSSEEvent  = errors.New("invalid signed SSE event")
	ErrInvalidSSECursor = errors.New("invalid SSE cursor")
	ErrSSESignature     = errors.New("invalid SSE event signature")
	ErrSSEHashChain     = errors.New("invalid SSE hash chain")
)

type SignedSSEEvent struct {
	Cursor    string
	Hash      string
	Signature string
}

type SSEEventSigner struct {
	signer       Signer
	previousHash []byte
}

func NewSSEEventSigner(signer Signer) (*SSEEventSigner, error) {
	return NewSSEEventSignerWithPreviousHash(signer, nil)
}

func NewSSEEventSignerWithPreviousHash(signer Signer, previousHash []byte) (*SSEEventSigner, error) {
	if signer == nil || len(signer.PublicKey()) != ed25519.PublicKeySize || len(signer.PrivateKey()) != ed25519.PrivateKeySize {
		return nil, errors.New("SSE signer with a valid Ed25519 key is required")
	}
	if len(previousHash) != 0 && len(previousHash) != sha256.Size {
		return nil, ErrSSEHashChain
	}
	return &SSEEventSigner{signer: signer, previousHash: append([]byte(nil), previousHash...)}, nil
}

func (signer *SSEEventSigner) PreviousHash() []byte {
	if signer == nil {
		return nil
	}
	return append([]byte(nil), signer.previousHash...)
}

func (signer *SSEEventSigner) Sign(event []byte, cursor string) (SignedSSEEvent, error) {
	if signer == nil || signer.signer == nil {
		return SignedSSEEvent{}, errors.New("SSE signer is required")
	}
	if err := validateSSECursor(cursor); err != nil {
		return SignedSSEEvent{}, err
	}
	hash := sseEventHash(signer.previousHash, event, cursor)
	signature := ed25519.Sign(signer.signer.PrivateKey(), sseSigningBytes(event, cursor, hash))
	result := SignedSSEEvent{
		Cursor:    cursor,
		Hash:      base64.RawURLEncoding.EncodeToString(hash),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	signer.previousHash = append(signer.previousHash[:0], hash...)
	return result, nil
}

func (signer *SSEEventSigner) Frame(event []byte, cursor string) ([]byte, error) {
	event = normalizeSSEEvent(event)
	signed, err := signer.Sign(event, cursor)
	if err != nil {
		return nil, err
	}
	var frame bytes.Buffer
	fmt.Fprintf(&frame, ": snw-cursor=%s\n: snw-hash=%s\n: snw-signature=%s\n", signed.Cursor, signed.Hash, signed.Signature)
	frame.Write(event)
	if !bytes.HasSuffix(event, []byte("\n\n")) {
		if !bytes.HasSuffix(event, []byte("\n")) {
			frame.WriteByte('\n')
		}
		frame.WriteByte('\n')
	}
	return frame.Bytes(), nil
}

func VerifySSEEvent(event []byte, signed SignedSSEEvent, previousHash []byte, publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrSSESignature
	}
	if len(previousHash) != 0 && len(previousHash) != sha256.Size {
		return nil, ErrSSEHashChain
	}
	if err := validateSSECursor(signed.Cursor); err != nil {
		return nil, err
	}
	hash, err := base64.RawURLEncoding.DecodeString(signed.Hash)
	if err != nil || len(hash) != sha256.Size {
		return nil, ErrSSEHashChain
	}
	expectedHash := sseEventHash(previousHash, event, signed.Cursor)
	if !bytes.Equal(hash, expectedHash) {
		return nil, ErrSSEHashChain
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, sseSigningBytes(event, signed.Cursor, hash), signature) {
		return nil, ErrSSESignature
	}
	return append([]byte(nil), hash...), nil
}

func ParseSignedSSEFrame(frame []byte) ([]byte, SignedSSEEvent, error) {
	if len(frame) == 0 {
		return nil, SignedSSEEvent{}, ErrInvalidSSEEvent
	}
	var signed SignedSSEEvent
	position := 0
	for position < len(frame) {
		lineEnd := bytes.IndexByte(frame[position:], '\n')
		if lineEnd < 0 {
			return nil, SignedSSEEvent{}, ErrInvalidSSEEvent
		}
		lineEnd += position
		line := strings.TrimSuffix(string(frame[position:lineEnd]), "\r")
		switch {
		case strings.HasPrefix(line, ": snw-cursor="):
			signed.Cursor = strings.TrimPrefix(line, ": snw-cursor=")
		case strings.HasPrefix(line, ": snw-hash="):
			signed.Hash = strings.TrimPrefix(line, ": snw-hash=")
		case strings.HasPrefix(line, ": snw-signature="):
			signed.Signature = strings.TrimPrefix(line, ": snw-signature=")
		default:
			return append([]byte(nil), frame[position:]...), signed, validateParsedSSEMetadata(signed)
		}
		position = lineEnd + 1
	}
	return nil, SignedSSEEvent{}, ErrInvalidSSEEvent
}

func WriteSignedSSEEvent(writer io.Writer, signer *SSEEventSigner, event []byte, cursor string) error {
	if writer == nil {
		return errors.New("SSE event writer is required")
	}
	frame, err := signer.Frame(event, cursor)
	if err != nil {
		return err
	}
	_, err = writer.Write(frame)
	return err
}

// SignSSEStream signs every complete SSE event in an already buffered stream.
// The returned bytes remain valid SSE because signature metadata is emitted as
// comment lines, which standard A2A clients ignore.
func SignSSEStream(stream []byte, signer Signer, initialCursor string) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("SSE signer is required")
	}
	eventSigner, err := NewSSEEventSigner(signer)
	if err != nil {
		return nil, err
	}
	normalized := bytes.ReplaceAll(stream, []byte("\r\n"), []byte("\n"))
	parts := bytes.Split(normalized, []byte("\n\n"))
	var signed bytes.Buffer
	eventIndex := 0
	for _, part := range parts {
		if len(bytes.TrimSpace(part)) == 0 {
			continue
		}
		cursor := sseStreamCursor(initialCursor, eventIndex)
		event := append(append([]byte(nil), part...), '\n', '\n')
		frame, err := eventSigner.Frame(event, cursor)
		if err != nil {
			return nil, err
		}
		signed.Write(frame)
		eventIndex++
	}
	return signed.Bytes(), nil
}

func sseStreamCursor(initial string, index int) string {
	if initial == "" {
		return "cursor-" + strconv.Itoa(index+1)
	}
	if value, err := strconv.ParseUint(initial, 10, 64); err == nil {
		return strconv.FormatUint(value+uint64(index)+1, 10)
	}
	return initial + "-" + strconv.Itoa(index+1)
}

func sseEventHash(previousHash, event []byte, cursor string) []byte {
	hash := sha256.New()
	hash.Write([]byte(sseSignatureDomain))
	hash.Write(previousHash)
	hash.Write([]byte{0})
	hash.Write([]byte(cursor))
	hash.Write([]byte{0})
	hash.Write(event)
	return hash.Sum(nil)
}

func sseSigningBytes(event []byte, cursor string, hash []byte) []byte {
	content := make([]byte, 0, len(sseSignatureDomain)+len(cursor)+len(hash)+len(event)+3)
	content = append(content, []byte(sseSignatureDomain)...)
	content = append(content, []byte(cursor)...)
	content = append(content, 0)
	content = append(content, hash...)
	content = append(content, 0)
	content = append(content, event...)
	return content
}

func validateSSECursor(cursor string) error {
	if cursor == "" || strings.ContainsAny(cursor, "\r\n") {
		return ErrInvalidSSECursor
	}
	return nil
}

func normalizeSSEEvent(event []byte) []byte {
	if bytes.HasSuffix(event, []byte("\n\n")) {
		return append([]byte(nil), event...)
	}
	normalized := append([]byte(nil), event...)
	if !bytes.HasSuffix(normalized, []byte("\n")) {
		normalized = append(normalized, '\n')
	}
	return append(normalized, '\n')
}

func validateParsedSSEMetadata(signed SignedSSEEvent) error {
	if signed.Cursor == "" || signed.Hash == "" || signed.Signature == "" {
		return ErrInvalidSSEEvent
	}
	return validateSSECursor(signed.Cursor)
}
