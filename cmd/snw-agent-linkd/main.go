package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/EvanSener/snw-agent-link/internal/daemon"
)

func main() {
	var config daemon.Config
	defaults := daemon.DefaultConfig("")
	flag.StringVar(&config.DataDir, "data-dir", defaults.DataDir, "daemon data directory")
	flag.StringVar(&config.TailscaleBindIP, "tailscale-bind-ip", "", "Tailscale IPv4/IPv6 address to bind")
	flag.StringVar(&config.TailscaleLocalAPISocket, "tailscale-local-api-socket", defaults.TailscaleLocalAPISocket, "Tailscale Local API Unix socket")
	flag.IntVar(&config.GatewayPort, "gateway-port", defaults.GatewayPort, "A2A gateway port")
	flag.StringVar(&config.Version, "version", defaults.Version, "daemon version")
	flag.Parse()

	validated, err := config.Validate()
	if err != nil {
		fatal(err)
	}
	service, err := daemon.New(validated)
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := service.Run(ctx); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	log.Printf("snw-agent-linkd: %v", err)
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
