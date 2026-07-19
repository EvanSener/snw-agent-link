//go:build windows

package tailscale

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func dialLocalAPI(ctx context.Context, endpoint string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return winio.DialPipeAccessImpLevel(
		ctx,
		endpoint,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		winio.PipeImpLevelIdentification,
	)
}
