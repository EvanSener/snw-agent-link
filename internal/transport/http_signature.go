package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
)

const signatureLabel = "snw-agent"

const (
	agentIDHeader       = "X-SNW-Agent-ID"
	publicKeyHeader     = "X-SNW-Agent-Public-Key"
	targetAgentIDHeader = "X-SNW-Target-Agent-ID"
)

var (
	ErrMissingSignature = errors.New("missing RFC 9421 signature")
	ErrInvalidSignature = errors.New("invalid RFC 9421 signature")
	ErrDigestMismatch   = errors.New("RFC 9530 content digest mismatch")
)

type signatureMetadata struct {
	Components []string
	Created    int64
	KeyID      string
	Nonce      string
}

// Signer is the minimum key material required for HTTP message signatures.
// identity.Identity satisfies this interface without coupling transport to
// the identity store.
type Signer interface {
	AgentID() string
	PublicKey() ed25519.PublicKey
	PrivateKey() ed25519.PrivateKey
}

func SignRequest(request *http.Request, signer Signer, targetAgent string) error {
	if request == nil || request.URL == nil || signer == nil || targetAgent == "" {
		return errors.New("request, signer and target agent are required")
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	body, err := readRequestBody(request)
	if err != nil {
		return err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	setContentDigest(request.Header, body)
	request.Header.Set(agentIDHeader, signer.AgentID())
	request.Header.Set(publicKeyHeader, base64.RawURLEncoding.EncodeToString(signer.PublicKey()))
	request.Header.Set(targetAgentIDHeader, targetAgent)
	metadata := signatureMetadata{Components: []string{"@method", "@target-uri", "content-digest", "x-snw-agent-id", "x-snw-target-agent-id"}, Created: time.Now().UTC().Unix(), KeyID: identity.Fingerprint(signer.PublicKey()), Nonce: identityNonce()}
	signature := ed25519.Sign(signer.PrivateKey(), []byte(requestSignatureBase(request, metadata)))
	setSignatureHeaders(request.Header, metadata, signature)
	return nil
}

func VerifyRequest(request *http.Request, expectedAgent string, publicKey ed25519.PublicKey, now time.Time, allowedSkew time.Duration) (string, error) {
	return VerifyRequestForTarget(request, expectedAgent, "", publicKey, now, allowedSkew)
}

func VerifyRequestForTarget(request *http.Request, expectedAgent, expectedTarget string, publicKey ed25519.PublicKey, now time.Time, allowedSkew time.Duration) (string, error) {
	if request == nil || expectedAgent == "" || len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidSignature
	}
	if allowedSkew <= 0 {
		allowedSkew = 5 * time.Minute
	}
	metadata, signature, err := parseSignatureHeaders(request.Header)
	if err != nil {
		return "", err
	}
	if !sameComponents(metadata.Components, []string{"@method", "@target-uri", "content-digest", "x-snw-agent-id", "x-snw-target-agent-id"}) {
		return "", ErrInvalidSignature
	}
	if metadata.KeyID != identity.Fingerprint(publicKey) || request.Header.Get(agentIDHeader) != expectedAgent {
		return "", ErrInvalidSignature
	}
	targetAgent := request.Header.Get(targetAgentIDHeader)
	if targetAgent == "" || (expectedTarget != "" && targetAgent != expectedTarget) {
		return "", ErrInvalidSignature
	}
	issued := time.Unix(metadata.Created, 0)
	if issued.Before(now.Add(-allowedSkew)) || issued.After(now.Add(allowedSkew)) {
		return "", ErrInvalidSignature
	}
	body, err := readRequestBody(request)
	if err != nil {
		return "", err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if request.Header.Get("Content-Digest") != contentDigest(body) {
		return "", ErrDigestMismatch
	}
	if !ed25519.Verify(publicKey, []byte(requestSignatureBase(request, metadata)), signature) {
		return "", ErrInvalidSignature
	}
	return metadata.Nonce, nil
}

func SignResponse(headers http.Header, status int, body []byte, signer Signer) error {
	if headers == nil || signer == nil {
		return errors.New("response signer is required")
	}
	setContentDigest(headers, body)
	metadata := signatureMetadata{Components: []string{"@status", "content-digest", "x-snw-agent-id"}, Created: time.Now().UTC().Unix(), KeyID: identity.Fingerprint(signer.PublicKey()), Nonce: identityNonce()}
	headers.Set(agentIDHeader, signer.AgentID())
	headers.Set(publicKeyHeader, base64.RawURLEncoding.EncodeToString(signer.PublicKey()))
	signature := ed25519.Sign(signer.PrivateKey(), []byte(responseSignatureBase(status, headers, metadata)))
	setSignatureHeaders(headers, metadata, signature)
	return nil
}

func VerifyResponse(response *http.Response, publicKey ed25519.PublicKey, now time.Time, allowedSkew time.Duration) error {
	return VerifyResponseForAgent(response, "", publicKey, now, allowedSkew)
}

func VerifyResponseForAgent(response *http.Response, expectedAgent string, publicKey ed25519.PublicKey, now time.Time, allowedSkew time.Duration) error {
	if response == nil || len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidSignature
	}
	metadata, signature, err := parseSignatureHeaders(response.Header)
	if err != nil {
		return err
	}
	if !sameComponents(metadata.Components, []string{"@status", "content-digest", "x-snw-agent-id"}) || metadata.KeyID != identity.Fingerprint(publicKey) {
		return ErrInvalidSignature
	}
	if expectedAgent != "" && response.Header.Get(agentIDHeader) != expectedAgent {
		return ErrInvalidSignature
	}
	if allowedSkew <= 0 {
		allowedSkew = 5 * time.Minute
	}
	issued := time.Unix(metadata.Created, 0)
	if issued.Before(now.Add(-allowedSkew)) || issued.After(now.Add(allowedSkew)) {
		return ErrInvalidSignature
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	if response.Header.Get("Content-Digest") != contentDigest(body) {
		return ErrDigestMismatch
	}
	if !ed25519.Verify(publicKey, []byte(responseSignatureBase(response.StatusCode, response.Header, metadata)), signature) {
		return ErrInvalidSignature
	}
	return nil
}

func readRequestBody(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	return io.ReadAll(request.Body)
}

func setContentDigest(headers http.Header, body []byte) {
	headers.Set("Content-Digest", contentDigest(body))
}

func contentDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"
}

func requestSignatureBase(request *http.Request, metadata signatureMetadata) string {
	target := request.URL.String()
	if !request.URL.IsAbs() {
		scheme := "http"
		if request.TLS != nil {
			scheme = "https"
		}
		target = scheme + "://" + request.Host + request.URL.RequestURI()
	}
	return fmt.Sprintf("\"@method\": %s\n\"@target-uri\": %s\n\"content-digest\": %s\n\"x-snw-agent-id\": %s\n\"x-snw-target-agent-id\": %s\n\"@signature-params\": %s", request.Method, target, request.Header.Get("Content-Digest"), request.Header.Get(agentIDHeader), request.Header.Get(targetAgentIDHeader), signatureParams(metadata))
}

func responseSignatureBase(status int, headers http.Header, metadata signatureMetadata) string {
	return fmt.Sprintf("\"@status\": %d\n\"content-digest\": %s\n\"x-snw-agent-id\": %s\n\"@signature-params\": %s", status, headers.Get("Content-Digest"), headers.Get("X-SNW-Agent-ID"), signatureParams(metadata))
}

func signatureParams(metadata signatureMetadata) string {
	components := make([]string, 0, len(metadata.Components))
	for _, component := range metadata.Components {
		components = append(components, strconv.Quote(component))
	}
	return "(" + strings.Join(components, " ") + ");created=" + strconv.FormatInt(metadata.Created, 10) + ";keyid=" + strconv.Quote(metadata.KeyID) + ";nonce=" + strconv.Quote(metadata.Nonce)
}

func setSignatureHeaders(headers http.Header, metadata signatureMetadata, signature []byte) {
	headers.Set("Signature-Input", signatureLabel+"="+signatureParams(metadata))
	headers.Set("Signature", signatureLabel+"=:"+base64.StdEncoding.EncodeToString(signature)+":")
}

func parseSignatureHeaders(headers http.Header) (signatureMetadata, []byte, error) {
	input := headers.Get("Signature-Input")
	value := headers.Get("Signature")
	if input == "" || value == "" {
		return signatureMetadata{}, nil, ErrMissingSignature
	}
	prefix := signatureLabel + "="
	if !strings.HasPrefix(input, prefix) || !strings.HasPrefix(value, prefix) {
		return signatureMetadata{}, nil, ErrInvalidSignature
	}
	metadata, err := parseSignatureParams(strings.TrimPrefix(input, prefix))
	if err != nil {
		return signatureMetadata{}, nil, err
	}
	rawValue := strings.TrimPrefix(value, prefix)
	if len(rawValue) < 2 || rawValue[0] != ':' || rawValue[len(rawValue)-1] != ':' {
		return signatureMetadata{}, nil, ErrInvalidSignature
	}
	raw := rawValue[1 : len(rawValue)-1]
	signature, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return signatureMetadata{}, nil, ErrInvalidSignature
	}
	return metadata, signature, nil
}

func parseSignatureParams(value string) (signatureMetadata, error) {
	closeParen := strings.Index(value, ")")
	if !strings.HasPrefix(value, "(") || closeParen < 0 {
		return signatureMetadata{}, ErrInvalidSignature
	}
	var components []string
	for _, token := range strings.Fields(strings.TrimSpace(value[1:closeParen])) {
		component, err := strconv.Unquote(token)
		if err != nil {
			return signatureMetadata{}, ErrInvalidSignature
		}
		components = append(components, component)
	}
	metadata := signatureMetadata{Components: components}
	for _, parameter := range strings.Split(value[closeParen+1:], ";") {
		parts := strings.SplitN(strings.TrimSpace(parameter), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "created":
			created, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return signatureMetadata{}, ErrInvalidSignature
			}
			metadata.Created = created
		case "keyid", "nonce":
			parsed, err := strconv.Unquote(parts[1])
			if err != nil {
				return signatureMetadata{}, ErrInvalidSignature
			}
			if parts[0] == "keyid" {
				metadata.KeyID = parsed
			} else {
				metadata.Nonce = parsed
			}
		}
	}
	if metadata.Created <= 0 || metadata.KeyID == "" || metadata.Nonce == "" {
		return signatureMetadata{}, ErrInvalidSignature
	}
	return metadata, nil
}

func sameComponents(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func identityNonce() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		fallback := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		copy(value, fallback[:16])
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
