//go:build windows

package main

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

type blockingServiceRunner struct {
	started chan struct{}
	stopped chan struct{}
}

func (runner blockingServiceRunner) Run(ctx context.Context) error {
	close(runner.started)
	<-ctx.Done()
	close(runner.stopped)
	return nil
}

func TestWindowsServiceHandlerStopsDaemon(t *testing.T) {
	runner := blockingServiceRunner{started: make(chan struct{}), stopped: make(chan struct{})}
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 4)
	done := make(chan struct{})
	var serviceSpecific bool
	var exitCode uint32
	go func() {
		serviceSpecific, exitCode = (windowsServiceHandler{runner: runner}).Execute(nil, requests, changes)
		close(done)
	}()

	waitForServiceStatus(t, changes, svc.StartPending)
	waitForServiceStatus(t, changes, svc.Running)
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("daemon did not start")
	}

	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	waitForServiceStatus(t, changes, svc.StopPending)
	select {
	case <-runner.stopped:
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("service handler did not exit")
	}
	if serviceSpecific || exitCode != 0 {
		t.Fatalf("unexpected service exit: serviceSpecific=%t code=%d", serviceSpecific, exitCode)
	}
}

func waitForServiceStatus(t *testing.T, changes <-chan svc.Status, want svc.State) {
	t.Helper()
	select {
	case status := <-changes:
		if status.State != want {
			t.Fatalf("service state = %v, want %v", status.State, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("service did not report state %v", want)
	}
}
