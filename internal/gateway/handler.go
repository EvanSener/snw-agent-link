package gateway

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/a2aproject/a2a-go/v2/a2a"
)

var errGatewayNotReady = errors.New("gateway authentication and forwarding are not configured")

type rejectingHandler struct{}

func (rejectingHandler) GetTask(context.Context, *a2a.GetTaskRequest) (*a2a.Task, error) {
	return nil, errGatewayNotReady
}
func (rejectingHandler) ListTasks(context.Context, *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	return nil, errGatewayNotReady
}
func (rejectingHandler) CancelTask(context.Context, *a2a.CancelTaskRequest) (*a2a.Task, error) {
	return nil, errGatewayNotReady
}
func (rejectingHandler) SendMessage(context.Context, *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	return nil, errGatewayNotReady
}
func (rejectingHandler) SubscribeToTask(context.Context, *a2a.SubscribeToTaskRequest) iter.Seq2[a2a.Event, error] {
	return rejectStream
}
func (rejectingHandler) SendStreamingMessage(context.Context, *a2a.SendMessageRequest) iter.Seq2[a2a.Event, error] {
	return rejectStream
}
func (rejectingHandler) GetTaskPushConfig(context.Context, *a2a.GetTaskPushConfigRequest) (*a2a.PushConfig, error) {
	return nil, errGatewayNotReady
}
func (rejectingHandler) ListTaskPushConfigs(context.Context, *a2a.ListTaskPushConfigRequest) (*a2a.ListTaskPushConfigResponse, error) {
	return nil, errGatewayNotReady
}
func (rejectingHandler) CreateTaskPushConfig(context.Context, *a2a.PushConfig) (*a2a.PushConfig, error) {
	return nil, errGatewayNotReady
}
func (rejectingHandler) DeleteTaskPushConfig(context.Context, *a2a.DeleteTaskPushConfigRequest) error {
	return errGatewayNotReady
}
func (rejectingHandler) GetExtendedAgentCard(context.Context, *a2a.GetExtendedAgentCardRequest) (*a2a.AgentCard, error) {
	return nil, errGatewayNotReady
}

func rejectStream(yield func(a2a.Event, error) bool) {
	yield(nil, errGatewayNotReady)
}

func activeContactError(contact model.Contact, err error) error {
	if err != nil {
		return fmt.Errorf("lookup contact: %w", err)
	}
	if contact.State != model.ContactStateActive {
		return fmt.Errorf("contact is not active: %s", contact.State)
	}
	return nil
}
