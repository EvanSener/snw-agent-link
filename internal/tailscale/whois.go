package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

var ErrPeerIdentityMismatch = errors.New("tailscale peer identity mismatch")

type NodeIdentity struct {
	NodeID       string
	StableNodeID string
	NodeName     string
	UserID       string
	LoginName    string
	Addresses    []string
}

// HasAddress confirms that a Local API identity actually owns the address
// used by the incoming connection. This prevents a provider response for a
// different Tailnet peer from being accepted on an otherwise matching node
// identifier.
func (identity NodeIdentity) HasAddress(remoteAddr string) bool {
	host := strings.TrimSpace(remoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	for _, raw := range identity.Addresses {
		raw = strings.TrimSpace(raw)
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			if prefix.Contains(address) {
				return true
			}
			continue
		}
		if candidate, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil && candidate == address {
			return true
		}
	}
	return false
}

type WhoIsProvider interface {
	WhoIs(context.Context, string) (NodeIdentity, error)
}

type PeerExpectation struct {
	NodeID       string
	StableNodeID string
	NodeName     string
	UserID       string
	LoginName    string
}

type LocalAPIClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewLocalAPIClient(baseURL string, httpClient *http.Client) *LocalAPIClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &LocalAPIClient{baseURL: strings.TrimRight(baseURL, "/"), httpClient: httpClient}
}

// NewLocalAPISocketClient connects to the tailscaled Local API over its Unix
// socket or Windows named pipe. The endpoint is intentionally not exposed as
// TCP: the daemon and tailscaled must share the host's local IPC boundary.
func NewLocalAPISocketClient(socketPath string) *LocalAPIClient {
	socketPath = strings.TrimSpace(socketPath)
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialLocalAPI(ctx, socketPath)
		},
	}
	return &LocalAPIClient{
		baseURL:    "http://local-tailscaled.sock",
		httpClient: &http.Client{Transport: transport},
	}
}

func (c *LocalAPIClient) WhoIs(ctx context.Context, remoteAddr string) (NodeIdentity, error) {
	endpoint, err := url.Parse(c.baseURL + "/localapi/v0/whois")
	if err != nil {
		return NodeIdentity{}, fmt.Errorf("build tailscale whois URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("addr", remoteAddr)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return NodeIdentity{}, fmt.Errorf("create tailscale whois request: %w", err)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return NodeIdentity{}, fmt.Errorf("request tailscale whois: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return NodeIdentity{}, fmt.Errorf("tailscale whois returned %s", response.Status)
	}
	var payload struct {
		Node struct {
			ID        json.RawMessage `json:"ID"`
			StableID  string          `json:"StableID"`
			Name      string          `json:"Name"`
			Addresses []string        `json:"Addresses"`
		} `json:"Node"`
		UserProfile struct {
			ID        json.RawMessage `json:"ID"`
			LoginName string          `json:"LoginName"`
		} `json:"UserProfile"`
	}
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return NodeIdentity{}, fmt.Errorf("decode tailscale whois: %w", err)
	}
	return NodeIdentity{
		NodeID:       identifierString(payload.Node.ID),
		StableNodeID: payload.Node.StableID,
		NodeName:     payload.Node.Name,
		UserID:       identifierString(payload.UserProfile.ID),
		LoginName:    payload.UserProfile.LoginName,
		Addresses:    append([]string(nil), payload.Node.Addresses...),
	}, nil
}

func VerifyPeer(ctx context.Context, provider WhoIsProvider, remoteAddr string, expected PeerExpectation) error {
	identity, err := provider.WhoIs(ctx, remoteAddr)
	if err != nil {
		return err
	}
	checks := []struct {
		name     string
		expected string
		actual   string
	}{
		{"node id", expected.NodeID, identity.NodeID},
		{"stable node id", expected.StableNodeID, identity.StableNodeID},
		{"node name", expected.NodeName, identity.NodeName},
		{"user id", expected.UserID, identity.UserID},
		{"login name", expected.LoginName, identity.LoginName},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("%w: %s", ErrPeerIdentityMismatch, check.name)
		}
	}
	return nil
}

func identifierString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return value
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return number.String()
	}
	return ""
}
