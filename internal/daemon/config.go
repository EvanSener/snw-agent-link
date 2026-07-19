package daemon

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/EvanSener/snw-agent-link/internal/tailscale"
)

const DefaultGatewayPort = 7443

var DefaultTailscaleLocalAPISocket = defaultTailscaleLocalAPISocket()

type Config struct {
	DataDir                 string
	DatabasePath            string
	IdentityDir             string
	IPCEndpoint             string
	TailscaleBindIP         string
	TailscaleLocalAPISocket string
	GatewayPort             int
	HostFingerprint         string
	Version                 string
}

func DefaultConfig(dataDir string) Config {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		dataDir = defaultDataDir()
	}
	return Config{
		DataDir:                 dataDir,
		DatabasePath:            filepath.Join(dataDir, "agent-link.sqlite3"),
		IdentityDir:             filepath.Join(dataDir, "identities"),
		IPCEndpoint:             defaultIPCEndpoint(dataDir),
		TailscaleLocalAPISocket: DefaultTailscaleLocalAPISocket,
		GatewayPort:             DefaultGatewayPort,
		Version:                 "dev",
	}
}

func defaultIPCEndpoint(dataDir string) string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\snw-agent-link`
	}
	return filepath.Join(dataDir, "snw-agent-link.sock")
}

func (c Config) Validate() (Config, error) {
	c.DataDir = strings.TrimSpace(c.DataDir)
	if c.DataDir == "" {
		return Config{}, errors.New("data directory is required")
	}
	if filepath.IsAbs(c.DataDir) == false {
		absolute, err := filepath.Abs(c.DataDir)
		if err != nil {
			return Config{}, fmt.Errorf("resolve data directory: %w", err)
		}
		c.DataDir = absolute
	}
	if c.DatabasePath == "" {
		c.DatabasePath = filepath.Join(c.DataDir, "agent-link.sqlite3")
	}
	if c.IdentityDir == "" {
		c.IdentityDir = filepath.Join(c.DataDir, "identities")
	}
	if c.IPCEndpoint == "" {
		c.IPCEndpoint = defaultIPCEndpoint(c.DataDir)
	}
	if strings.TrimSpace(c.TailscaleLocalAPISocket) == "" {
		c.TailscaleLocalAPISocket = DefaultTailscaleLocalAPISocket
	}
	if !validTailscaleLocalAPIEndpoint(c.TailscaleLocalAPISocket) {
		return Config{}, fmt.Errorf("tailscale Local API endpoint must be an absolute socket path or named pipe: %s", c.TailscaleLocalAPISocket)
	}
	if c.GatewayPort == 0 {
		c.GatewayPort = DefaultGatewayPort
	}
	if c.GatewayPort < 1 || c.GatewayPort > 65535 {
		return Config{}, fmt.Errorf("gateway port must be between 1 and 65535: %d", c.GatewayPort)
	}
	if strings.TrimSpace(c.TailscaleBindIP) == "" {
		return Config{}, errors.New("tailscale bind IP is required")
	}
	if _, err := tailscale.DefaultAddressPolicy().ValidateBindAddress(c.TailscaleBindIP); err != nil {
		return Config{}, fmt.Errorf("validate tailscale bind IP: %w", err)
	}
	if strings.TrimSpace(c.Version) == "" {
		c.Version = "dev"
	}
	return c, nil
}

func (c Config) BindAddress() (netip.Addr, error) {
	return tailscale.DefaultAddressPolicy().ValidateBindAddress(c.TailscaleBindIP)
}

func (c Config) GatewayAddress() (string, error) {
	address, err := c.BindAddress()
	if err != nil {
		return "", err
	}
	return netip.AddrPortFrom(address, uint16(c.GatewayPort)).String(), nil
}

func (c Config) EnsureDirectories() error {
	paths := []string{c.DataDir, c.IdentityDir, filepath.Dir(c.DatabasePath)}
	if runtime.GOOS != "windows" {
		paths = append(paths, filepath.Dir(c.IPCEndpoint))
	}
	for _, path := range paths {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create daemon directory %q: %w", path, err)
		}
		if runtime.GOOS != "windows" {
			if err := os.Chmod(path, 0o700); err != nil {
				return fmt.Errorf("secure daemon directory %q: %w", path, err)
			}
		}
	}
	return nil
}

func validTailscaleLocalAPIEndpoint(endpoint string) bool {
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(endpoint, `\\.\pipe\`) && len(endpoint) > len(`\\.\pipe\`)
	}
	return filepath.IsAbs(endpoint)
}

func defaultTailscaleLocalAPISocket() string {
	switch runtime.GOOS {
	case "windows":
		return `\\.\pipe\ProtectedPrefix\Administrators\Tailscale\tailscaled`
	case "darwin":
		return "/var/run/tailscaled.socket"
	default:
		return "/var/run/tailscale/tailscaled.sock"
	}
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".snw-agent-link")
	}
	return filepath.Join(os.TempDir(), "snw-agent-link")
}
