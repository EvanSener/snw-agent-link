package attachment

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
	"github.com/EvanSener/snw-agent-link/internal/transport"
)

const blobSignatureLabel = "snw-blob"

var (
	ErrBlobSignature = errors.New("invalid blob HTTP message signature")
	ErrBlobDigest    = errors.New("blob content digest mismatch")
	ErrRange         = errors.New("invalid attachment range")
)

type blobSignatureMetadata struct {
	Components []string
	Created    int64
	Expires    int64
	KeyID      string
	Nonce      string
}

type BlobSigner interface {
	AgentID() string
	PublicKey() ed25519.PublicKey
	PrivateKey() ed25519.PrivateKey
}

var blobRequestComponents = []string{
	"@method", "@authority", "@path", "@query", "content-digest", "range",
	"x-snw-agent-id", "x-snw-target-agent-id",
}

var blobResponseComponents = []string{
	"@status", "content-digest", "content-range", "etag", "x-snw-agent-id",
}

func SignBlobRequest(request *http.Request, signer *identity.Identity, targetAgentID string) error {
	if request == nil || signer == nil || targetAgentID == "" {
		return ErrBlobSignature
	}
	body, err := readBlobRequestBody(request)
	if err != nil {
		return err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.Header.Set("Content-Digest", blobContentDigest(body))
	request.Header.Set("X-SNW-Agent-ID", signer.AgentID())
	request.Header.Set("X-SNW-Target-Agent-ID", targetAgentID)
	request.Header.Set("X-SNW-Agent-Public-Key", base64.RawURLEncoding.EncodeToString(signer.PublicKey()))
	metadata := newBlobSignatureMetadata(blobRequestComponents)
	metadata.KeyID = identity.Fingerprint(signer.PublicKey())
	signature := ed25519.Sign(signer.PrivateKey(), []byte(blobRequestSignatureBase(request, metadata)))
	setBlobSignatureHeaders(request.Header, metadata, signature)
	return nil
}

func VerifyBlobRequest(
	request *http.Request,
	expectedAgentID, expectedTargetAgentID string,
	publicKey ed25519.PublicKey,
	now time.Time,
	allowedSkew time.Duration,
) (string, error) {
	if request == nil || expectedAgentID == "" || expectedTargetAgentID == "" || len(publicKey) != ed25519.PublicKeySize {
		return "", ErrBlobSignature
	}
	metadata, signature, err := parseBlobSignatureHeaders(request.Header)
	if err != nil || !sameBlobComponents(metadata.Components, blobRequestComponents) {
		return "", ErrBlobSignature
	}
	if request.Header.Get("X-SNW-Agent-ID") != expectedAgentID || request.Header.Get("X-SNW-Target-Agent-ID") != expectedTargetAgentID ||
		metadata.KeyID != identity.Fingerprint(publicKey) || !validBlobSignatureTime(metadata, now, allowedSkew) {
		return "", ErrBlobSignature
	}
	body, err := readBlobRequestBody(request)
	if err != nil {
		return "", err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if request.Header.Get("Content-Digest") != blobContentDigest(body) {
		return "", ErrBlobDigest
	}
	if !ed25519.Verify(publicKey, []byte(blobRequestSignatureBase(request, metadata)), signature) {
		return "", ErrBlobSignature
	}
	return metadata.Nonce, nil
}

func SignBlobResponse(headers http.Header, status int, body []byte, signer BlobSigner) error {
	if headers == nil || signer == nil {
		return ErrBlobSignature
	}
	headers.Set("Content-Digest", blobContentDigest(body))
	headers.Set("X-SNW-Agent-ID", signer.AgentID())
	headers.Set("X-SNW-Agent-Public-Key", base64.RawURLEncoding.EncodeToString(signer.PublicKey()))
	metadata := newBlobSignatureMetadata(blobResponseComponents)
	metadata.KeyID = identity.Fingerprint(signer.PublicKey())
	signature := ed25519.Sign(signer.PrivateKey(), []byte(blobResponseSignatureBase(status, headers, metadata)))
	setBlobSignatureHeaders(headers, metadata, signature)
	return nil
}

func VerifyBlobResponse(response *http.Response, expectedAgentID string, publicKey ed25519.PublicKey, now time.Time, allowedSkew time.Duration) error {
	if response == nil || expectedAgentID == "" || len(publicKey) != ed25519.PublicKeySize {
		return ErrBlobSignature
	}
	if strings.HasPrefix(response.Header.Get("Signature-Input"), "snw-agent=") {
		if response.Header.Get("X-SNW-Agent-ID") != expectedAgentID {
			return ErrBlobSignature
		}
		return transport.VerifyResponse(response, publicKey, now, allowedSkew)
	}
	metadata, signature, err := parseBlobSignatureHeaders(response.Header)
	if err != nil || !sameBlobComponents(metadata.Components, blobResponseComponents) ||
		response.Header.Get("X-SNW-Agent-ID") != expectedAgentID || metadata.KeyID != identity.Fingerprint(publicKey) ||
		!validBlobSignatureTime(metadata, now, allowedSkew) {
		return ErrBlobSignature
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	if response.Header.Get("Content-Digest") != blobContentDigest(body) {
		return ErrBlobDigest
	}
	if !ed25519.Verify(publicKey, []byte(blobResponseSignatureBase(response.StatusCode, response.Header, metadata)), signature) {
		return ErrBlobSignature
	}
	return nil
}

func ParseRange(value string, size, maxLength int64) (int64, int64, error) {
	if size <= 0 || maxLength <= 0 || !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") {
		return 0, 0, ErrRange
	}
	parts := strings.SplitN(strings.TrimPrefix(value, "bytes="), "-", 2)
	if len(parts) != 2 || parts[0] == "" {
		return 0, 0, ErrRange
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, ErrRange
	}
	end := size - 1
	if parts[1] != "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, ErrRange
		}
	}
	if end < start || end >= size || end-start+1 > maxLength {
		return 0, 0, ErrRange
	}
	return start, end, nil
}

func ContentRange(start, end, size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", start, end, size)
}

func newBlobSignatureMetadata(components []string) blobSignatureMetadata {
	now := time.Now().UTC()
	return blobSignatureMetadata{
		Components: append([]string(nil), components...), Created: now.Unix(), Expires: now.Add(2 * time.Minute).Unix(),
		Nonce: blobNonce(),
	}
}

func blobRequestSignatureBase(request *http.Request, metadata blobSignatureMetadata) string {
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	query := request.URL.RawQuery
	if query != "" {
		query = "?" + query
	}
	return fmt.Sprintf("\"@method\": %s\n\"@authority\": %s\n\"@path\": %s\n\"@query\": %s\n\"content-digest\": %s\n\"range\": %s\n\"x-snw-agent-id\": %s\n\"x-snw-target-agent-id\": %s\n\"@signature-params\": %s",
		request.Method, authority, request.URL.EscapedPath(), query, request.Header.Get("Content-Digest"),
		request.Header.Get("Range"), request.Header.Get("X-SNW-Agent-ID"), request.Header.Get("X-SNW-Target-Agent-ID"),
		blobSignatureParams(metadata))
}

func blobResponseSignatureBase(status int, headers http.Header, metadata blobSignatureMetadata) string {
	return fmt.Sprintf("\"@status\": %d\n\"content-digest\": %s\n\"content-range\": %s\n\"etag\": %s\n\"x-snw-agent-id\": %s\n\"@signature-params\": %s",
		status, headers.Get("Content-Digest"), headers.Get("Content-Range"), headers.Get("ETag"),
		headers.Get("X-SNW-Agent-ID"), blobSignatureParams(metadata))
}

func blobSignatureParams(metadata blobSignatureMetadata) string {
	components := make([]string, 0, len(metadata.Components))
	for _, component := range metadata.Components {
		components = append(components, strconv.Quote(component))
	}
	return "(" + strings.Join(components, " ") + ");created=" + strconv.FormatInt(metadata.Created, 10) +
		";expires=" + strconv.FormatInt(metadata.Expires, 10) + ";keyid=" + strconv.Quote(metadata.KeyID) +
		";nonce=" + strconv.Quote(metadata.Nonce)
}

func setBlobSignatureHeaders(headers http.Header, metadata blobSignatureMetadata, signature []byte) {
	headers.Set("Signature-Input", blobSignatureLabel+"="+blobSignatureParams(metadata))
	headers.Set("Signature", blobSignatureLabel+"=:"+base64.StdEncoding.EncodeToString(signature)+":")
}

func parseBlobSignatureHeaders(headers http.Header) (blobSignatureMetadata, []byte, error) {
	prefix := blobSignatureLabel + "="
	input := headers.Get("Signature-Input")
	value := headers.Get("Signature")
	if !strings.HasPrefix(input, prefix) || !strings.HasPrefix(value, prefix) {
		return blobSignatureMetadata{}, nil, ErrBlobSignature
	}
	metadata, err := parseBlobSignatureParams(strings.TrimPrefix(input, prefix))
	if err != nil {
		return blobSignatureMetadata{}, nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(strings.Trim(strings.TrimPrefix(value, prefix), ":"))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return blobSignatureMetadata{}, nil, ErrBlobSignature
	}
	return metadata, signature, nil
}

func parseBlobSignatureParams(value string) (blobSignatureMetadata, error) {
	closeParen := strings.Index(value, ")")
	if !strings.HasPrefix(value, "(") || closeParen < 0 {
		return blobSignatureMetadata{}, ErrBlobSignature
	}
	metadata := blobSignatureMetadata{}
	for _, token := range strings.Fields(strings.TrimSpace(value[1:closeParen])) {
		component, err := strconv.Unquote(token)
		if err != nil {
			return blobSignatureMetadata{}, ErrBlobSignature
		}
		metadata.Components = append(metadata.Components, component)
	}
	for _, parameter := range strings.Split(value[closeParen+1:], ";") {
		parts := strings.SplitN(strings.TrimSpace(parameter), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "created", "expires":
			parsed, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return blobSignatureMetadata{}, ErrBlobSignature
			}
			if parts[0] == "created" {
				metadata.Created = parsed
			} else {
				metadata.Expires = parsed
			}
		case "keyid", "nonce":
			parsed, err := strconv.Unquote(parts[1])
			if err != nil {
				return blobSignatureMetadata{}, ErrBlobSignature
			}
			if parts[0] == "keyid" {
				metadata.KeyID = parsed
			} else {
				metadata.Nonce = parsed
			}
		}
	}
	if metadata.Created == 0 || metadata.Expires == 0 || metadata.KeyID == "" || metadata.Nonce == "" {
		return blobSignatureMetadata{}, ErrBlobSignature
	}
	return metadata, nil
}

func validBlobSignatureTime(metadata blobSignatureMetadata, now time.Time, allowedSkew time.Duration) bool {
	if allowedSkew <= 0 {
		allowedSkew = 5 * time.Minute
	}
	created := time.Unix(metadata.Created, 0)
	expires := time.Unix(metadata.Expires, 0)
	return !created.Before(now.Add(-allowedSkew)) && !created.After(now.Add(allowedSkew)) &&
		expires.After(now) && !expires.After(created.Add(5*time.Minute))
}

func readBlobRequestBody(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	return io.ReadAll(request.Body)
}

func blobContentDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"
}

func sameBlobComponents(actual, expected []string) bool {
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

func blobNonce() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		fallback := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		copy(value, fallback[:16])
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
