package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/attachment"
	"github.com/EvanSener/snw-agent-link/internal/delivery"
	"github.com/EvanSener/snw-agent-link/internal/gateway"
	"github.com/EvanSener/snw-agent-link/internal/identitystore"
	"github.com/EvanSener/snw-agent-link/internal/ipc"
	"github.com/EvanSener/snw-agent-link/internal/management"
	"github.com/EvanSener/snw-agent-link/internal/pairing"
	"github.com/EvanSener/snw-agent-link/internal/registration"
	"github.com/EvanSener/snw-agent-link/internal/secure"
	"github.com/EvanSener/snw-agent-link/internal/store"
	"github.com/EvanSener/snw-agent-link/internal/tailscale"
	"github.com/EvanSener/snw-agent-link/internal/transport"
)

type Daemon struct {
	config    Config
	store     *store.Store
	ipcServer *ipc.Server
	gateway   *httpServer

	mu                     sync.RWMutex
	listening              bool
	tailscaleNodeID        string
	tailscaleStableNodeID  string
	tailscaleProvider      *tailscale.LocalAPIClient
	tailscaleLocalAPIReady bool
	tailscaleWhoIsReady    bool
	closeOnce              sync.Once
	closeResult            error
	cancel                 context.CancelFunc
	deliveryWG             sync.WaitGroup
}

// httpServer is kept as a small wrapper so the daemon owns shutdown and listener state.
type httpServer struct {
	server   *http.Server
	listener net.Listener
}

type runtimeStatus struct {
	daemon *Daemon
}

func (status runtimeStatus) RuntimeStatus(ctx context.Context) management.RuntimeStatus {
	status.daemon.mu.RLock()
	listening := status.daemon.listening
	nodeID := status.daemon.tailscaleNodeID
	stableNodeID := status.daemon.tailscaleStableNodeID
	localAPI := status.daemon.tailscaleProvider
	localAPIReady := status.daemon.tailscaleLocalAPIReady
	whoIsReady := status.daemon.tailscaleWhoIsReady
	status.daemon.mu.RUnlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if localAPI != nil {
		whoIsAddress, addressErr := status.daemon.config.GatewayAddress()
		if addressErr != nil {
			whoIsAddress = status.daemon.config.TailscaleBindIP
		}
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		liveNode, err := localAPI.WhoIs(checkCtx, whoIsAddress)
		cancel()
		localAPIReady = err == nil
		whoIsReady = err == nil && (strings.TrimSpace(liveNode.NodeID) != "" || strings.TrimSpace(liveNode.StableNodeID) != "")
		if err == nil {
			nodeID = liveNode.NodeID
			stableNodeID = liveNode.StableNodeID
		} else {
			nodeID = ""
			stableNodeID = ""
		}
	}
	address, _ := status.daemon.config.GatewayAddress()
	return management.RuntimeStatus{
		Version:                status.daemon.config.Version,
		TailscaleAddress:       address,
		HostFingerprint:        status.daemon.config.HostFingerprint,
		GatewayListening:       listening,
		TailscaleNodeID:        nodeID,
		TailscaleStableNodeID:  stableNodeID,
		TailscaleLoggedIn:      localAPIReady && (nodeID != "" || stableNodeID != ""),
		TailscaleLocalAPIReady: localAPIReady,
		TailscaleWhoIsReady:    whoIsReady,
	}
}

func New(config Config) (*Daemon, error) {
	validated, err := config.Validate()
	if err != nil {
		return nil, err
	}
	return &Daemon{config: validated}, nil
}

func (daemon *Daemon) Config() Config { return daemon.config }

// Run initializes all local services and blocks until ctx is canceled.
func (daemon *Daemon) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("daemon context is required")
	}
	if err := daemon.config.EnsureDirectories(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	daemon.mu.Lock()
	daemon.cancel = cancel
	daemon.mu.Unlock()
	defer cancel()
	localAPI := tailscale.NewLocalAPISocketClient(daemon.config.TailscaleLocalAPISocket)
	daemon.mu.Lock()
	daemon.tailscaleProvider = localAPI
	daemon.mu.Unlock()
	whoIsCtx, whoIsCancel := context.WithTimeout(runCtx, 5*time.Second)
	whoIsAddress, err := daemon.config.GatewayAddress()
	if err != nil {
		whoIsCancel()
		return fmt.Errorf("resolve Tailscale gateway address for WhoIs: %w", err)
	}
	localNode, err := localAPI.WhoIs(whoIsCtx, whoIsAddress)
	whoIsCancel()
	if err != nil {
		return fmt.Errorf("tailscale Local API WhoIs unavailable: %w", err)
	}
	if strings.TrimSpace(localNode.NodeID) == "" && strings.TrimSpace(localNode.StableNodeID) == "" {
		return errors.New("tailscale Local API WhoIs returned no node identity")
	}
	daemon.mu.Lock()
	daemon.tailscaleNodeID = localNode.NodeID
	daemon.tailscaleStableNodeID = localNode.StableNodeID
	daemon.tailscaleLocalAPIReady = true
	daemon.tailscaleWhoIsReady = true
	daemon.mu.Unlock()
	outboxKey, err := loadOrCreateOutboxKey(filepath.Join(daemon.config.DataDir, "outbox.key"))
	if err != nil {
		return err
	}
	database, err := store.OpenWithKey(daemon.config.DatabasePath, secure.StaticKeyProvider(outboxKey))
	if err != nil {
		return err
	}
	daemon.store = database
	identities, err := identitystore.NewFileStore(daemon.config.IdentityDir)
	if err != nil {
		_ = daemon.Close()
		return err
	}
	registrations := registration.NewService(database)
	pairingService := pairing.NewService(database, nil)
	attachments, err := attachment.NewService(filepath.Join(daemon.config.DataDir, "attachments"), 1<<30, 4<<20)
	if err != nil {
		_ = daemon.Close()
		return err
	}
	managementHandler := management.NewHandler(database, registrations, pairingService, identities, runtimeStatus{daemon: daemon}, attachments)
	deliveryTransport, err := delivery.NewDynamicA2ATransport(database, identities)
	if err != nil {
		_ = daemon.Close()
		return err
	}
	deliveryTransport.SetRequireRemoteNodeID(true)
	deliveryTransport.SetReadinessCheck(func(ctx context.Context) error {
		if ctx == nil {
			ctx = context.Background()
		}
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, err := localAPI.WhoIs(checkCtx, whoIsAddress)
		return err
	})
	deliveryTransport.SetTaskStore(database)
	deliveryService := delivery.NewService(database, deliveryTransport, delivery.Config{})
	daemon.deliveryWG.Add(1)
	go func() {
		defer daemon.deliveryWG.Done()
		daemon.runDeliveryWorker(runCtx, deliveryService)
	}()

	server := ipc.NewServer(managementHandler, 8<<20)
	daemon.ipcServer = server
	go func() {
		if serveErr := server.Serve(runCtx, daemon.config.IPCEndpoint); serveErr != nil && runCtx.Err() == nil {
			// IPC failures are surfaced by Run through the gateway/error channel below.
		}
	}()

	router, err := gateway.NewRouterWithWhoIs(database, registrations, localAPI, func(request *http.Request) (transport.Signer, error) {
		parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
		if len(parts) < 2 || parts[0] != "agents" {
			return nil, nil
		}
		return identities.GetIdentity(request.Context(), parts[1])
	})
	if err != nil {
		_ = daemon.Close()
		return err
	}
	router.SetAttachmentService(attachments)
	address, err := daemon.config.GatewayAddress()
	if err != nil {
		_ = daemon.Close()
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		_ = daemon.Close()
		return fmt.Errorf("listen on Tailscale gateway %s: %w", address, err)
	}
	httpSrv := &http.Server{Handler: router.Handler(), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10}
	daemon.gateway = &httpServer{server: httpSrv, listener: listener}
	daemon.mu.Lock()
	daemon.listening = true
	daemon.mu.Unlock()

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.Serve(listener) }()
	select {
	case <-ctx.Done():
		cancel()
		_ = daemon.Close()
		return nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		cancel()
		_ = daemon.Close()
		return fmt.Errorf("gateway server: %w", err)
	}
}

func (daemon *Daemon) Close() error {
	daemon.closeOnce.Do(func() {
		var errs []error
		daemon.mu.Lock()
		daemon.listening = false
		cancel := daemon.cancel
		gatewayServer := daemon.gateway
		ipcServer := daemon.ipcServer
		database := daemon.store
		daemon.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		daemon.deliveryWG.Wait()
		if gatewayServer != nil {
			if err := gatewayServer.server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs = append(errs, err)
			}
			if err := gatewayServer.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		if ipcServer != nil {
			if err := ipcServer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		if database != nil {
			if err := database.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			daemon.closeResult = errors.Join(errs...)
		}
	})
	return daemon.closeResult
}

func (daemon *Daemon) runDeliveryWorker(ctx context.Context, service *delivery.Service) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = service.ProcessDue(ctx)
		}
	}
}
