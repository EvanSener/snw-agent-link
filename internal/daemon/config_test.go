package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigDerivesPaths(t *testing.T) {
	config := DefaultConfig("/tmp/snw-agent-link")
	if config.DatabasePath != "/tmp/snw-agent-link/agent-link.sqlite3" {
		t.Fatalf("unexpected database path: %s", config.DatabasePath)
	}
	if config.IdentityDir != "/tmp/snw-agent-link/identities" {
		t.Fatalf("unexpected identity directory: %s", config.IdentityDir)
	}
	if config.IPCEndpoint != "/tmp/snw-agent-link/snw-agent-link.sock" {
		t.Fatalf("unexpected IPC endpoint: %s", config.IPCEndpoint)
	}
	if config.GatewayPort != DefaultGatewayPort {
		t.Fatalf("unexpected gateway port: %d", config.GatewayPort)
	}
	if config.TailscaleLocalAPISocket != DefaultTailscaleLocalAPISocket {
		t.Fatalf("unexpected Local API socket: %s", config.TailscaleLocalAPISocket)
	}
}

func TestConfigValidateRequiresTailscaleOnly(t *testing.T) {
	config := DefaultConfig(t.TempDir())
	if _, err := config.Validate(); err == nil {
		t.Fatal("expected missing tailscale bind IP error")
	}
	config.TailscaleBindIP = "100.100.100.10"
	if _, err := config.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestConfigValidateRejectsNonTailscaleAddressAndBadPort(t *testing.T) {
	config := DefaultConfig(t.TempDir())
	config.TailscaleBindIP = "127.0.0.1"
	if _, err := config.Validate(); err == nil {
		t.Fatal("expected non-Tailscale address error")
	}
	config.TailscaleBindIP = "100.100.100.10"
	config.GatewayPort = 70000
	if _, err := config.Validate(); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestConfigValidateRequiresAbsoluteLocalAPISocket(t *testing.T) {
	config := DefaultConfig(t.TempDir())
	config.TailscaleBindIP = "100.100.100.10"
	config.TailscaleLocalAPISocket = "tailscaled.sock"
	if _, err := config.Validate(); err == nil {
		t.Fatal("expected relative Local API socket to be rejected")
	}
}

func TestEnsureDirectoriesUsesPrivatePermissions(t *testing.T) {
	root := t.TempDir()
	config := DefaultConfig(filepath.Join(root, "data"))
	config.TailscaleBindIP = "100.100.100.10"
	if err := config.EnsureDirectories(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(config.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("unexpected directory permissions: %o", info.Mode().Perm())
	}
}
