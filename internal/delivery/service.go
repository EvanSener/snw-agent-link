package delivery

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/store"
)

const (
	defaultBatchSize = 100
	defaultBaseDelay = time.Second
	defaultMaxDelay  = 15 * time.Minute
)

type Transport interface {
	Deliver(context.Context, model.OutboxMessage) (string, error)
}

type Config struct {
	BatchSize int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Clock     func() time.Time
	Jitter    func(time.Duration) time.Duration
}

type ProcessResult struct {
	Delivered int
	Retried   int
}

type Service struct {
	store     *store.Store
	transport Transport
	batchSize int
	baseDelay time.Duration
	maxDelay  time.Duration
	clock     func() time.Time
	jitter    func(time.Duration) time.Duration
}

func NewService(database *store.Store, transport Transport, config Config) *Service {
	batchSize := config.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	baseDelay := config.BaseDelay
	if baseDelay <= 0 {
		baseDelay = defaultBaseDelay
	}
	maxDelay := config.MaxDelay
	if maxDelay <= 0 {
		maxDelay = defaultMaxDelay
	}
	if maxDelay < baseDelay {
		maxDelay = baseDelay
	}
	clock := config.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	jitter := config.Jitter
	if jitter == nil {
		jitter = randomJitter
	}
	return &Service{
		store: database, transport: transport, batchSize: batchSize,
		baseDelay: baseDelay, maxDelay: maxDelay, clock: clock, jitter: jitter,
	}
}

func (service *Service) ProcessDue(ctx context.Context) (ProcessResult, error) {
	if service.store == nil {
		return ProcessResult{}, fmt.Errorf("delivery store is required")
	}
	if service.transport == nil {
		return ProcessResult{}, fmt.Errorf("delivery transport is required")
	}

	now := service.clock().UTC()
	messages, err := service.store.ListDueOutbox(ctx, now, service.batchSize)
	if err != nil {
		return ProcessResult{}, err
	}

	result := ProcessResult{}
	for _, message := range messages {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		remoteReceiptID, deliverErr := service.transport.Deliver(ctx, message)
		if deliverErr != nil {
			nextAttemptAt := now.Add(service.retryDelay(message.AttemptCount + 1))
			if err := service.store.ScheduleOutboxRetry(ctx, message.MessageID, nextAttemptAt); err != nil {
				return result, fmt.Errorf("schedule retry for %s: %w", message.MessageID, err)
			}
			result.Retried++
			continue
		}

		receipt := model.DeliveryReceipt{
			MessageID:       message.MessageID,
			TargetAgentID:   message.TargetAgentID,
			RemoteReceiptID: remoteReceiptID,
			DeliveredAt:     now,
		}
		if err := service.store.MarkOutboxDelivered(ctx, receipt); err != nil {
			return result, fmt.Errorf("mark %s delivered: %w", message.MessageID, err)
		}
		result.Delivered++
	}
	return result, nil
}

func (service *Service) retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	exponent := attempt - 1
	if exponent > 62 {
		exponent = 62
	}
	multiplier := math.Pow(2, float64(exponent))
	delay := time.Duration(float64(service.baseDelay) * multiplier)
	if delay <= 0 || delay > service.maxDelay {
		delay = service.maxDelay
	}
	jitter := service.jitter(delay)
	if jitter < 0 {
		jitter = 0
	}
	if delay > service.maxDelay-jitter {
		return service.maxDelay
	}
	return delay + jitter
}

func randomJitter(delay time.Duration) time.Duration {
	window := delay / 4
	if window <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(window) + 1))
}
