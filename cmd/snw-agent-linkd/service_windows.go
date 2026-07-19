//go:build windows

package main

import (
	"context"

	"github.com/EvanSener/snw-agent-link/internal/daemon"
	"golang.org/x/sys/windows/svc"
)

const windowsServiceName = "snw-agent-linkd"

type serviceRunner interface {
	Run(context.Context) error
}

type windowsServiceHandler struct {
	runner serviceRunner
}

func runPlatformService(linkDaemon *daemon.Daemon) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, err
	}
	if !isService {
		return false, nil
	}
	if err := svc.Run(windowsServiceName, windowsServiceHandler{runner: linkDaemon}); err != nil {
		return true, err
	}
	return true, nil
}

func (handler windowsServiceHandler) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- handler.runner.Run(ctx)
	}()

	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	select {
	case err := <-runDone:
		if err != nil {
			return true, 1
		}
		return false, 0
	default:
		changes <- current
	}

	for {
		select {
		case err := <-runDone:
			if err != nil {
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- current
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-runDone; err != nil {
					return true, 1
				}
				return false, 0
			}
		}
	}
}
