package transport

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/identity"
	"github.com/EvanSener/snw-agent-link/internal/model"
)

type VerifyingRoundTripper struct {
	Base          http.RoundTripper
	PublicKey     ed25519.PublicKey
	ExpectedAgent string
	AllowedSkew   time.Duration
}

func (roundTripper VerifyingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	base := roundTripper.Base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if len(roundTripper.PublicKey) == ed25519.PublicKeySize {
		if err := VerifyResponseForAgent(response, roundTripper.ExpectedAgent, roundTripper.PublicKey, time.Now().UTC(), roundTripper.AllowedSkew); err != nil {
			_ = response.Body.Close()
			return nil, err
		}
	}
	return response, nil
}

type SignedRoundTripper struct {
	Base        http.RoundTripper
	Identity    *identity.Identity
	TargetAgent string
}

func (roundTripper SignedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if roundTripper.Identity == nil {
		return nil, fmt.Errorf("signing identity is required")
	}
	base := roundTripper.Base
	if base == nil {
		base = http.DefaultTransport
	}
	clone := request.Clone(request.Context())
	if err := SignRequest(clone, roundTripper.Identity, roundTripper.TargetAgent); err != nil {
		return nil, err
	}
	return base.RoundTrip(clone)
}

func EnvelopeForRequest(identityValue *identity.Identity, targetAgent, method, path string, body []byte) (model.SignedEnvelope, error) {
	claim := struct {
		Method        string `json:"method"`
		Path          string `json:"path"`
		TargetAgentID string `json:"targetAgentId"`
		BodyDigest    string `json:"bodyDigest"`
	}{method, path, targetAgent, fmt.Sprintf("%x", sha256.Sum256(body))}
	claimed, err := json.Marshal(claim)
	if err != nil {
		return model.SignedEnvelope{}, err
	}
	return identityValue.Sign(identityValue.AgentID(), "http-request", claimed)
}
