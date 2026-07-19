package attachment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/google/uuid"
)

type State string

const (
	StateUploading State = "uploading"
	StateCompleted State = "completed"
	StateCancelled State = "cancelled"
)

var (
	ErrNotFound      = errors.New("attachment not found")
	ErrOwnerMismatch = errors.New("attachment owner mismatch")
	ErrInvalidOffset = errors.New("attachment offset does not match progress")
	ErrQuotaExceeded = errors.New("attachment quota exceeded")
	ErrChecksum      = errors.New("attachment checksum mismatch")
	ErrInvalidState  = errors.New("invalid attachment state")
)

type Metadata struct {
	BlobID    string    `json:"blobId"`
	OwnerID   string    `json:"ownerId"`
	Name      string    `json:"name"`
	MediaType string    `json:"mediaType,omitempty"`
	Size      int64     `json:"size"`
	Received  int64     `json:"received"`
	SHA256    string    `json:"sha256"`
	State     State     `json:"state"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Service struct {
	root      string
	maxBytes  int64
	chunkSize int64
	mu        sync.Mutex
}

func (service *Service) ChunkSize() int64 { return service.chunkSize }

func NewService(root string, maxBytes, chunkSize int64) (*Service, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("attachment root is required")
	}
	if maxBytes <= 0 {
		maxBytes = 1 << 30
	}
	if chunkSize <= 0 {
		chunkSize = 4 << 20
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create attachment root: %w", err)
	}
	return &Service{root: root, maxBytes: maxBytes, chunkSize: chunkSize}, nil
}

func (service *Service) Init(ownerID, name, mediaType, checksum string, size int64) (Metadata, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if ownerID == "" || name == "" || size < 0 || size > service.maxBytes {
		return Metadata{}, ErrQuotaExceeded
	}
	if len(checksum) != 64 {
		return Metadata{}, errors.New("attachment sha256 must be a 64-character hex digest")
	}
	if _, err := hex.DecodeString(checksum); err != nil {
		return Metadata{}, errors.New("attachment sha256 is not hexadecimal")
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	metadata := Metadata{BlobID: id, OwnerID: ownerID, Name: filepath.Base(name), MediaType: mediaType, Size: size, SHA256: strings.ToLower(checksum), State: StateUploading, CreatedAt: now, UpdatedAt: now}
	if err := service.writeMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	file, err := os.OpenFile(service.partPath(id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.Remove(service.metaPath(id))
		return Metadata{}, fmt.Errorf("create attachment part: %w", err)
	}
	if err := file.Close(); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (service *Service) PutChunk(ownerID, blobID string, offset int64, data []byte) (Metadata, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	metadata, err := service.readMetadata(blobID)
	if err != nil {
		return Metadata{}, err
	}
	if metadata.OwnerID != ownerID {
		return Metadata{}, ErrOwnerMismatch
	}
	if metadata.State != StateUploading {
		return Metadata{}, ErrInvalidState
	}
	if offset != metadata.Received {
		return Metadata{}, ErrInvalidOffset
	}
	if int64(len(data)) > service.chunkSize || metadata.Received+int64(len(data)) > metadata.Size {
		return Metadata{}, ErrQuotaExceeded
	}
	file, err := os.OpenFile(service.partPath(blobID), os.O_WRONLY, 0o600)
	if err != nil {
		return Metadata{}, fmt.Errorf("open attachment part: %w", err)
	}
	if _, err := file.WriteAt(data, offset); err != nil {
		_ = file.Close()
		return Metadata{}, fmt.Errorf("write attachment chunk: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return Metadata{}, err
	}
	if err := file.Close(); err != nil {
		return Metadata{}, err
	}
	metadata.Received += int64(len(data))
	metadata.UpdatedAt = time.Now().UTC()
	if err := service.writeMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (service *Service) Complete(ownerID, blobID string) (Metadata, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	metadata, err := service.readMetadata(blobID)
	if err != nil {
		return Metadata{}, err
	}
	if metadata.OwnerID != ownerID {
		return Metadata{}, ErrOwnerMismatch
	}
	if metadata.State != StateUploading || metadata.Received != metadata.Size {
		return Metadata{}, ErrInvalidState
	}
	digest, err := fileDigest(service.partPath(blobID))
	if err != nil {
		return Metadata{}, err
	}
	if digest != metadata.SHA256 {
		return Metadata{}, ErrChecksum
	}
	if err := os.Rename(service.partPath(blobID), service.blobPath(blobID)); err != nil {
		return Metadata{}, fmt.Errorf("finalize attachment: %w", err)
	}
	metadata.State = StateCompleted
	metadata.UpdatedAt = time.Now().UTC()
	if err := service.writeMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (service *Service) Status(ownerID, blobID string) (Metadata, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	metadata, err := service.readMetadata(blobID)
	if err != nil {
		return Metadata{}, err
	}
	if metadata.OwnerID != ownerID {
		return Metadata{}, ErrOwnerMismatch
	}
	return metadata, nil
}

func (service *Service) Grant(ownerID, blobID, targetAgentID, contextID string, ttl time.Duration) (model.AttachmentGrant, error) {
	metadata, err := service.Status(ownerID, blobID)
	if err != nil {
		return model.AttachmentGrant{}, err
	}
	if metadata.State != StateCompleted || targetAgentID == "" || contextID == "" {
		return model.AttachmentGrant{}, ErrInvalidState
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	return model.AttachmentGrant{
		GrantID: uuid.NewString(), BlobID: metadata.BlobID, OwnerAgentID: ownerID,
		TargetAgentID: targetAgentID, ContextID: contextID, Digest: metadata.SHA256,
		Size: metadata.Size, ExpiresAt: now.Add(ttl), CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (service *Service) ReadRange(ownerID, blobID string, start, end int64) (Metadata, []byte, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	metadata, err := service.readMetadata(blobID)
	if err != nil {
		return Metadata{}, nil, err
	}
	if metadata.OwnerID != ownerID {
		return Metadata{}, nil, ErrOwnerMismatch
	}
	if metadata.State != StateCompleted {
		return Metadata{}, nil, ErrInvalidState
	}
	if start < 0 || end < start || end >= metadata.Size || end-start+1 > service.chunkSize {
		return Metadata{}, nil, ErrInvalidOffset
	}
	file, err := os.Open(service.blobPath(blobID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Metadata{}, nil, ErrNotFound
		}
		return Metadata{}, nil, fmt.Errorf("open attachment blob: %w", err)
	}
	defer file.Close()
	content := make([]byte, end-start+1)
	if _, err := file.ReadAt(content, start); err != nil && !errors.Is(err, io.EOF) {
		return Metadata{}, nil, fmt.Errorf("read attachment range: %w", err)
	}
	return metadata, content, nil
}

func (service *Service) Cancel(ownerID, blobID string) (Metadata, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	metadata, err := service.readMetadata(blobID)
	if err != nil {
		return Metadata{}, err
	}
	if metadata.OwnerID != ownerID {
		return Metadata{}, ErrOwnerMismatch
	}
	if metadata.State == StateCompleted {
		return Metadata{}, ErrInvalidState
	}
	metadata.State = StateCancelled
	metadata.UpdatedAt = time.Now().UTC()
	_ = os.Remove(service.partPath(blobID))
	if err := service.writeMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (service *Service) GC(retention time.Duration) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if retention <= 0 {
		retention = 24 * time.Hour
	}
	entries, err := os.ReadDir(service.root)
	if err != nil {
		return err
	}
	cutoff := time.Now().UTC().Add(-retention)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		metadata, readErr := service.readMetadata(strings.TrimSuffix(entry.Name(), ".json"))
		if readErr != nil || metadata.UpdatedAt.After(cutoff) {
			continue
		}
		_ = os.Remove(service.metaPath(metadata.BlobID))
		_ = os.Remove(service.partPath(metadata.BlobID))
		_ = os.Remove(service.blobPath(metadata.BlobID))
	}
	return nil
}

func (service *Service) writeMetadata(metadata Metadata) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(service.root, ".attachment-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, service.metaPath(metadata.BlobID))
}

func (service *Service) readMetadata(blobID string) (Metadata, error) {
	if blobID == "" || filepath.Base(blobID) != blobID {
		return Metadata{}, ErrNotFound
	}
	payload, err := os.ReadFile(service.metaPath(blobID))
	if errors.Is(err, os.ErrNotExist) {
		return Metadata{}, ErrNotFound
	}
	if err != nil {
		return Metadata{}, err
	}
	var metadata Metadata
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (service *Service) metaPath(blobID string) string {
	return filepath.Join(service.root, blobID+".json")
}
func (service *Service) partPath(blobID string) string {
	return filepath.Join(service.root, blobID+".part")
}
func (service *Service) blobPath(blobID string) string {
	return filepath.Join(service.root, blobID+".blob")
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
