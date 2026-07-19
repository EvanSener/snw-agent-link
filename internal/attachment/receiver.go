package attachment

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
)

type DownloadSpec struct {
	URL             string
	GrantID         string
	BlobID          string
	OwnerAgentID    string
	ReceiverAgentID string
	ContextID       string
	Digest          string
	Size            int64
	OwnerPublicKey  ed25519.PublicKey
}

type ReceiveStatus struct {
	BlobID   string `json:"blobId"`
	Received int64  `json:"received"`
	Size     int64  `json:"size"`
	Digest   string `json:"digest"`
	State    State  `json:"state"`
}

type Receiver struct {
	root      string
	chunkSize int64
	client    *http.Client
}

func NewReceiver(root string, chunkSize int64, client *http.Client) (*Receiver, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("attachment receiver root is required")
	}
	if chunkSize <= 0 {
		chunkSize = 4 << 20
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create attachment receiver root: %w", err)
	}
	if client == nil {
		client = &http.Client{}
	}
	cloned := *client
	cloned.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("attachment redirects are disabled")
	}
	return &Receiver{root: root, chunkSize: chunkSize, client: &cloned}, nil
}

func (receiver *Receiver) Receive(ctx context.Context, spec DownloadSpec, signer *identity.Identity) (ReceiveStatus, error) {
	status := ReceiveStatus{BlobID: spec.BlobID, Size: spec.Size, Digest: strings.ToLower(spec.Digest), State: StateUploading}
	endpoint, err := validateDownloadSpec(spec, signer)
	if err != nil {
		return status, err
	}
	finalPath := receiver.finalPath(spec.BlobID)
	if info, statErr := os.Stat(finalPath); statErr == nil && info.Size() == spec.Size {
		if digest, digestErr := fileDigest(finalPath); digestErr == nil && digest == status.Digest {
			status.Received = spec.Size
			status.State = StateCompleted
			return status, nil
		}
	}
	partPath := receiver.partPath(spec.BlobID)
	part, err := os.OpenFile(partPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return status, fmt.Errorf("open attachment receiver part: %w", err)
	}
	defer part.Close()
	info, err := part.Stat()
	if err != nil {
		return status, err
	}
	status.Received = info.Size()
	if status.Received > spec.Size {
		return status, ErrInvalidOffset
	}
	for status.Received < spec.Size {
		end := status.Received + receiver.chunkSize - 1
		if end >= spec.Size {
			end = spec.Size - 1
		}
		requestURL := *endpoint
		query := requestURL.Query()
		query.Set("grant", spec.GrantID)
		query.Set("context", spec.ContextID)
		query.Set("digest", status.Digest)
		requestURL.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if err != nil {
			return status, err
		}
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", status.Received, end))
		if err := SignBlobRequest(request, signer, spec.OwnerAgentID); err != nil {
			return status, err
		}
		response, err := receiver.client.Do(request)
		if err != nil {
			return status, fmt.Errorf("download attachment range: %w", err)
		}
		if err := VerifyBlobResponse(response, spec.OwnerAgentID, spec.OwnerPublicKey, time.Now().UTC(), 5*time.Minute); err != nil {
			_ = response.Body.Close()
			return status, fmt.Errorf("verify attachment response: %w", err)
		}
		if response.StatusCode != http.StatusPartialContent {
			_ = response.Body.Close()
			return status, fmt.Errorf("attachment download returned %s", response.Status)
		}
		if response.Header.Get("Content-Range") != ContentRange(status.Received, end, spec.Size) {
			_ = response.Body.Close()
			return status, ErrRange
		}
		content, err := io.ReadAll(io.LimitReader(response.Body, receiver.chunkSize+1))
		_ = response.Body.Close()
		if err != nil {
			return status, err
		}
		if int64(len(content)) != end-status.Received+1 {
			return status, ErrRange
		}
		if _, err := part.WriteAt(content, status.Received); err != nil {
			return status, fmt.Errorf("write attachment receiver part: %w", err)
		}
		if err := part.Sync(); err != nil {
			return status, err
		}
		status.Received += int64(len(content))
	}
	if err := part.Close(); err != nil {
		return status, err
	}
	digest, err := fileDigest(partPath)
	if err != nil {
		return status, err
	}
	if digest != status.Digest {
		return status, ErrChecksum
	}
	if err := os.Rename(partPath, finalPath); err != nil {
		return status, fmt.Errorf("finalize received attachment: %w", err)
	}
	status.State = StateCompleted
	return status, nil
}

func validateDownloadSpec(spec DownloadSpec, signer *identity.Identity) (*url.URL, error) {
	if signer == nil || signer.AgentID() != spec.ReceiverAgentID || spec.GrantID == "" || spec.BlobID == "" ||
		spec.OwnerAgentID == "" || spec.ContextID == "" || spec.Size < 0 || len(spec.OwnerPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid attachment download specification")
	}
	if filepath.Base(spec.BlobID) != spec.BlobID || len(spec.Digest) != sha256.Size*2 {
		return nil, errors.New("invalid attachment blob identity")
	}
	if _, err := hex.DecodeString(spec.Digest); err != nil {
		return nil, errors.New("invalid attachment digest")
	}
	endpoint, err := url.Parse(spec.URL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil {
		return nil, errors.New("invalid paired blob endpoint")
	}
	if err := validateTailnetBlobHost(endpoint.Hostname()); err != nil {
		return nil, err
	}
	return endpoint, nil
}

func validateTailnetBlobHost(host string) error {
	if host == "" {
		return errors.New("blob endpoint host is required")
	}
	addresses, err := net.LookupIP(host)
	if err != nil || len(addresses) == 0 {
		return errors.New("blob endpoint must resolve to a Tailscale address")
	}
	for _, address := range addresses {
		parsed, parseErr := netip.ParseAddr(address.String())
		if parseErr != nil || (!netip.MustParsePrefix("100.64.0.0/10").Contains(parsed.Unmap()) && !netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(parsed.Unmap())) {
			return errors.New("blob endpoint must resolve only to Tailscale addresses")
		}
	}
	return nil
}

func (receiver *Receiver) partPath(blobID string) string {
	return filepath.Join(receiver.root, filepath.Base(blobID)+".part")
}

func (receiver *Receiver) finalPath(blobID string) string {
	return filepath.Join(receiver.root, filepath.Base(blobID)+".blob")
}
