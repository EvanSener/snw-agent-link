package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
)

type forwardingHandler struct {
	transport a2aclient.Transport
}

func newForwardingHandler(registration model.AgentRegistration, sourceAgentID string) (*forwardingHandler, error) {
	endpoint, err := url.Parse(registration.LocalEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse local endpoint: %w", err)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, errors.New("local endpoint must use HTTP or HTTPS")
	}
	if endpoint.User != nil || endpoint.Hostname() == "" {
		return nil, errors.New("local endpoint must not contain credentials")
	}
	pinnedClient, err := loopbackClient(endpoint, registration.RegistrationTokenHash, sourceAgentID)
	if err != nil {
		return nil, err
	}
	return &forwardingHandler{transport: a2aclient.NewRESTTransport(endpoint, pinnedClient)}, nil
}

func loopbackClient(endpoint *url.URL, ingressTokenHash []byte, sourceAgentID string) (*http.Client, error) {
	host := endpoint.Hostname()
	port := endpoint.Port()
	if port == "" {
		if endpoint.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addresses, err := net.LookupIP(host)
	if err != nil || len(addresses) == 0 {
		if err == nil {
			err = errors.New("no addresses returned")
		}
		return nil, fmt.Errorf("resolve local endpoint: %w", err)
	}
	var pinned net.IP
	for _, address := range addresses {
		if address.IsLoopback() {
			pinned = append(net.IP(nil), address...)
			break
		}
	}
	if pinned == nil {
		return nil, errors.New("local endpoint must resolve to a loopback address")
	}
	pinnedAddress := net.JoinHostPort(pinned.String(), port)
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, pinnedAddress)
		},
	}
	return &http.Client{
		Transport: ingressRoundTripper{base: transport, token: base64.RawURLEncoding.EncodeToString(ingressTokenHash), sourceAgentID: sourceAgentID},
		Timeout:   3 * time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("local endpoint redirects are disabled")
		},
	}, nil
}

type ingressRoundTripper struct {
	base          http.RoundTripper
	token         string
	sourceAgentID string
}

func (roundTripper ingressRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("X-SNW-Linkd-Ingress", roundTripper.token)
	if roundTripper.sourceAgentID != "" {
		clone.Header.Set("X-SNW-Agent-ID", roundTripper.sourceAgentID)
	}
	return roundTripper.base.RoundTrip(clone)
}

func (handler *forwardingHandler) GetTask(ctx context.Context, request *a2a.GetTaskRequest) (*a2a.Task, error) {
	return handler.transport.GetTask(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) ListTasks(ctx context.Context, request *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	return handler.transport.ListTasks(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) CancelTask(ctx context.Context, request *a2a.CancelTaskRequest) (*a2a.Task, error) {
	return handler.transport.CancelTask(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) SendMessage(ctx context.Context, request *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	return handler.transport.SendMessage(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) SubscribeToTask(ctx context.Context, request *a2a.SubscribeToTaskRequest) iter.Seq2[a2a.Event, error] {
	return handler.transport.SubscribeToTask(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) SendStreamingMessage(ctx context.Context, request *a2a.SendMessageRequest) iter.Seq2[a2a.Event, error] {
	return handler.transport.SendStreamingMessage(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) GetTaskPushConfig(ctx context.Context, request *a2a.GetTaskPushConfigRequest) (*a2a.PushConfig, error) {
	return handler.transport.GetTaskPushConfig(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) ListTaskPushConfigs(ctx context.Context, request *a2a.ListTaskPushConfigRequest) (*a2a.ListTaskPushConfigResponse, error) {
	configs, err := handler.transport.ListTaskPushConfigs(ctx, a2aclient.ServiceParams{}, request)
	if err != nil {
		return nil, err
	}
	return &a2a.ListTaskPushConfigResponse{Configs: configs}, nil
}

func (handler *forwardingHandler) CreateTaskPushConfig(ctx context.Context, request *a2a.PushConfig) (*a2a.PushConfig, error) {
	return handler.transport.CreateTaskPushConfig(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) DeleteTaskPushConfig(ctx context.Context, request *a2a.DeleteTaskPushConfigRequest) error {
	return handler.transport.DeleteTaskPushConfig(ctx, a2aclient.ServiceParams{}, request)
}

func (handler *forwardingHandler) GetExtendedAgentCard(ctx context.Context, request *a2a.GetExtendedAgentCardRequest) (*a2a.AgentCard, error) {
	return handler.transport.GetExtendedAgentCard(ctx, a2aclient.ServiceParams{}, request)
}
