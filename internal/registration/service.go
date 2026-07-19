package registration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/store"
)

var ErrInvalidRegistrationToken = errors.New("invalid registration token")

type Service struct {
	store *store.Store
}

type Input struct {
	AgentID              string
	DisplayName          string
	LocalEndpoint        string
	AgentCardJSON        []byte
	IdentityPublicKey    []byte
	CapabilityPublicKey  []byte
	CapabilityGeneration uint64
}

func NewService(database *store.Store) *Service {
	return &Service{store: database}
}

func (s *Service) Register(ctx context.Context, input Input) (model.AgentRegistration, string, error) {
	if input.AgentID == "" || input.DisplayName == "" || input.LocalEndpoint == "" ||
		len(input.AgentCardJSON) == 0 || len(input.IdentityPublicKey) == 0 {
		return model.AgentRegistration{}, "", errors.New("agent registration fields are required")
	}
	if err := validateLocalEndpoint(input.LocalEndpoint); err != nil {
		return model.AgentRegistration{}, "", err
	}
	token, err := newToken()
	if err != nil {
		return model.AgentRegistration{}, "", err
	}
	registration := model.AgentRegistration{
		AgentID:               input.AgentID,
		DisplayName:           input.DisplayName,
		LocalEndpoint:         input.LocalEndpoint,
		AgentCardJSON:         append([]byte(nil), input.AgentCardJSON...),
		IdentityPublicKey:     append([]byte(nil), input.IdentityPublicKey...),
		CapabilityPublicKey:   append([]byte(nil), input.CapabilityPublicKey...),
		CapabilityGeneration:  input.CapabilityGeneration,
		RegistrationTokenHash: tokenHash(token),
	}
	if err := s.store.RegisterAgent(ctx, registration); err != nil {
		return model.AgentRegistration{}, "", err
	}
	stored, err := s.store.GetAgentRegistration(ctx, input.AgentID)
	return stored, token, err
}

func validateLocalEndpoint(raw string) error {
	endpoint, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse local endpoint: %w", err)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return errors.New("local endpoint must use HTTP or HTTPS")
	}
	if endpoint.User != nil || endpoint.Hostname() == "" {
		return errors.New("local endpoint must not contain credentials and must include a host")
	}
	addresses, err := net.LookupIP(endpoint.Hostname())
	if err != nil || len(addresses) == 0 {
		if err == nil {
			err = errors.New("no address returned")
		}
		return fmt.Errorf("resolve local endpoint: %w", err)
	}
	for _, address := range addresses {
		if !address.IsLoopback() {
			return errors.New("local endpoint must resolve only to loopback addresses")
		}
	}
	return nil
}

func (s *Service) Authenticate(ctx context.Context, agentID, token string) (model.AgentRegistration, error) {
	registration, err := s.store.GetAgentRegistration(ctx, agentID)
	if err != nil {
		return model.AgentRegistration{}, err
	}
	if subtle.ConstantTimeCompare(registration.RegistrationTokenHash, tokenHash(token)) != 1 {
		return model.AgentRegistration{}, ErrInvalidRegistrationToken
	}
	return registration, nil
}

func newToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate registration token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func tokenHash(token string) []byte {
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}
