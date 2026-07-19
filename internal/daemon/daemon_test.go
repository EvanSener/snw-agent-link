package daemon

import (
	"context"
	"strings"
	"testing"
)

func TestRunFailsClosedWhenTailscaleLocalAPIUnavailable(t *testing.T) {
	config := DefaultConfig(t.TempDir())
	config.TailscaleBindIP = "100.100.100.10"
	config.TailscaleLocalAPISocket = "/tmp/snw-agent-link-missing-tailscaled.sock"
	service, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = service.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "tailscale Local API WhoIs unavailable") {
		t.Fatalf("expected Local API startup failure, got %v", err)
	}
}
