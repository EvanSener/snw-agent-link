package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/daemon"
	"github.com/EvanSener/snw-agent-link/internal/ipc"
)

func main() {
	dataDir := flag.String("data-dir", "", "daemon data directory")
	ipcEndpoint := flag.String("ipc", "", "IPC socket or named pipe")
	paramsPath := flag.String("params", "", "JSON parameter file; stdin when omitted")
	timeout := flag.Duration("timeout", 30*time.Second, "IPC request timeout")
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	config := daemon.DefaultConfig(*dataDir)
	if *ipcEndpoint != "" {
		config.IPCEndpoint = *ipcEndpoint
	}
	method := normalizeMethod(flag.Args())
	if method == "help" || method == "--help" {
		usage()
		return
	}
	params, err := readParams(*paramsPath)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client := ipc.NewClient(config.IPCEndpoint)
	var result json.RawMessage
	if err := client.Call(ctx, method, params, &result); err != nil {
		fatal(err)
	}
	if len(result) == 0 || string(result) == "null" {
		return
	}
	var output any
	if err := json.Unmarshal(result, &output); err != nil {
		fatal(err)
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(encoded))
}

func readParams(path string) (json.RawMessage, error) {
	if path == "" || path == "-" {
		info, err := os.Stdin.Stat()
		if err == nil && info.Mode()&os.ModeCharDevice != 0 {
			return json.RawMessage(`{}`), nil
		}
		return readJSON(os.Stdin)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open params: %w", err)
	}
	defer file.Close()
	return readJSON(file)
}

func readJSON(reader io.Reader) (json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read params: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if !json.Valid(data) {
		return nil, errors.New("params must be valid JSON")
	}
	return json.RawMessage(data), nil
}

func usage() {
	fmt.Println("snw-agent-link <method> [flags]")
	fmt.Println("commands: status, agent ensure/register/list/capability challenge/exchange/rotate/recover, pair invite/accept/approve/status, contact list/revoke/block, mailbox list/read, send/status/wait/reply/cancel, doctor")
	fmt.Println("examples:")
	fmt.Println("  snw-agent-link status")
	fmt.Println("  snw-agent-link agent list")
	fmt.Println("  cat agent.json | snw-agent-link agent ensure")
	fmt.Println("  cat params.json | snw-agent-link agent register")
}

func normalizeMethod(args []string) string {
	if len(args) == 0 {
		return ""
	}
	if len(args) == 1 {
		return args[0]
	}
	return args[0] + "." + strings.Join(args[1:], ".")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
