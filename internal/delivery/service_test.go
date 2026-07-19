package delivery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/store"
)

type fakeTransport struct {
	receipt string
	err     error
	sent    []model.OutboxMessage
}

func (transport *fakeTransport) Deliver(_ context.Context, message model.OutboxMessage) (string, error) {
	transport.sent = append(transport.sent, message)
	return transport.receipt, transport.err
}

func TestProcessDueMarksSuccessfulDelivery(t *testing.T) {
	database := openDeliveryStore(t)
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	enqueueDeliveryMessage(t, database, "message-1", now.Add(-time.Second))
	transport := &fakeTransport{receipt: "remote-receipt-1"}
	service := NewService(database, transport, Config{
		Clock: func() time.Time { return now },
	})

	result, err := service.ProcessDue(context.Background())
	if err != nil {
		t.Fatalf("process due: %v", err)
	}
	if result.Delivered != 1 || result.Retried != 0 || len(transport.sent) != 1 {
		t.Fatalf("unexpected delivery result: %+v sent=%d", result, len(transport.sent))
	}
	message, err := database.GetOutbox(context.Background(), "message-1")
	if err != nil {
		t.Fatalf("get delivered message: %v", err)
	}
	if message.State != model.OutboxStateDelivered {
		t.Fatalf("expected delivered state, got %s", message.State)
	}
}

func TestProcessDueSchedulesExponentialRetry(t *testing.T) {
	database := openDeliveryStore(t)
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	enqueueDeliveryMessage(t, database, "message-1", now.Add(-time.Second))
	transport := &fakeTransport{err: errors.New("peer offline")}
	service := NewService(database, transport, Config{
		BaseDelay: time.Second,
		MaxDelay:  time.Minute,
		Jitter:    func(time.Duration) time.Duration { return 250 * time.Millisecond },
		Clock:     func() time.Time { return now },
	})

	result, err := service.ProcessDue(context.Background())
	if err != nil {
		t.Fatalf("process due: %v", err)
	}
	if result.Delivered != 0 || result.Retried != 1 {
		t.Fatalf("unexpected retry result: %+v", result)
	}
	message, err := database.GetOutbox(context.Background(), "message-1")
	if err != nil {
		t.Fatalf("get retried message: %v", err)
	}
	if message.AttemptCount != 1 {
		t.Fatalf("expected one attempt, got %d", message.AttemptCount)
	}
	expected := now.Add(1250 * time.Millisecond)
	if !message.NextAttemptAt.Equal(expected) {
		t.Fatalf("expected retry at %s, got %s", expected, message.NextAttemptAt)
	}

	service.clock = func() time.Time { return expected }
	if _, err := service.ProcessDue(context.Background()); err != nil {
		t.Fatalf("process second retry: %v", err)
	}
	message, err = database.GetOutbox(context.Background(), "message-1")
	if err != nil {
		t.Fatalf("get second retry: %v", err)
	}
	if message.AttemptCount != 2 {
		t.Fatalf("expected two attempts, got %d", message.AttemptCount)
	}
	expected = expected.Add(2250 * time.Millisecond)
	if !message.NextAttemptAt.Equal(expected) {
		t.Fatalf("expected exponential retry at %s, got %s", expected, message.NextAttemptAt)
	}
}

func TestProcessDueRespectsBatchLimit(t *testing.T) {
	database := openDeliveryStore(t)
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	enqueueDeliveryMessage(t, database, "message-1", now.Add(-2*time.Second))
	enqueueDeliveryMessage(t, database, "message-2", now.Add(-time.Second))
	transport := &fakeTransport{receipt: "receipt"}
	service := NewService(database, transport, Config{
		BatchSize: 1,
		Clock:     func() time.Time { return now },
	})

	result, err := service.ProcessDue(context.Background())
	if err != nil {
		t.Fatalf("process due: %v", err)
	}
	if result.Delivered != 1 || len(transport.sent) != 1 || transport.sent[0].MessageID != "message-1" {
		t.Fatalf("unexpected batch result: %+v sent=%+v", result, transport.sent)
	}
}

func openDeliveryStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := store.Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func enqueueDeliveryMessage(t *testing.T, database *store.Store, messageID string, nextAttemptAt time.Time) {
	t.Helper()
	err := database.EnqueueOutbox(context.Background(), model.OutboxMessage{
		MessageID:      messageID,
		IdempotencyKey: "idem-" + messageID,
		SourceAgentID:  "agent-a",
		TargetAgentID:  "agent-b",
		ContextID:      "context-1",
		Payload:        []byte(`{"text":"hello"}`),
		State:          model.OutboxStatePending,
		NextAttemptAt:  nextAttemptAt,
	})
	if err != nil {
		t.Fatalf("enqueue message: %v", err)
	}
}
