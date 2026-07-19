//go:build !windows

package main

import "github.com/EvanSener/snw-agent-link/internal/daemon"

func runPlatformService(*daemon.Daemon) (bool, error) {
	return false, nil
}
