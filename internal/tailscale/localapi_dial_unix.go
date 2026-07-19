//go:build !windows

package tailscale

import (
	"context"
	"net"
)

func dialLocalAPI(ctx context.Context, endpoint string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", endpoint)
}
