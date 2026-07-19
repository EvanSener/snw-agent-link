package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/secure"
)

func TestOutboxSurvivesRestart(t *testing.T) {
	path := t.TempDir() + "/link.db"
	ctx := context.Background()
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	message := model.OutboxMessage{
		MessageID:      "018f-message",
		IdempotencyKey: "idem-1",
		SourceAgentID:  "agent-a",
		TargetAgentID:  "agent-b",
		ContextID:      "context-1",
		Payload:        []byte(`{"text":"hello"}`),
		State:          model.OutboxStatePending,
		NextAttemptAt:  time.Now().UTC(),
	}
	if err := db.EnqueueOutbox(ctx, message); err != nil {
		t.Fatalf("enqueue outbox: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer db.Close()
	got, err := db.GetOutbox(ctx, message.MessageID)
	if err != nil {
		t.Fatalf("get outbox: %v", err)
	}
	if got.MessageID != message.MessageID || string(got.Payload) != string(message.Payload) {
		t.Fatalf("unexpected restored message: %+v", got)
	}
}

func TestEncryptedOutboxRoundTrip(t *testing.T) {
	path := t.TempDir() + "/encrypted.db"
	key := secure.StaticKeyProvider([]byte("0123456789abcdef0123456789abcdef"))
	db, err := OpenWithKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	want := model.OutboxMessage{MessageID: "encrypted-1", IdempotencyKey: "encrypted-idem", SourceAgentID: "agent-a", TargetAgentID: "agent-b", ContextID: "context", Payload: []byte("secret payload"), State: model.OutboxStatePending, NextAttemptAt: time.Now().UTC()}
	if err := db.EnqueueOutbox(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetOutbox(context.Background(), want.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != string(want.Payload) {
		t.Fatalf("payload mismatch: %q", got.Payload)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedInboxRoundTripAndScopedListing(t *testing.T) {
	path := t.TempDir() + "/inbox.db"
	key := secure.StaticKeyProvider([]byte("0123456789abcdef0123456789abcdef"))
	db, err := OpenWithKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	want := model.InboxMessage{TargetAgentID: "agent-local", SourceAgentID: "agent-remote", MessageID: "message-1", ContextID: "context-1", Body: `{"message":"hello"}`}
	if err := db.RecordInboxMessage(ctx, want); err != nil {
		t.Fatal(err)
	}
	items, err := db.ListInboxMessages(ctx, "agent-local", "context-1", true, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Body != want.Body || items[0].State != "unread" {
		t.Fatalf("unexpected inbox items: %+v", items)
	}
	if err := db.MarkInboxMessageRead(ctx, "agent-local", "agent-remote", "message-1"); err != nil {
		t.Fatal(err)
	}
	items, err = db.ListInboxMessages(ctx, "agent-local", "", true, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("read inbox message remained unread: %+v", items)
	}
	var stored []byte
	if err := db.db.QueryRowContext(ctx, `SELECT body FROM inbox_messages WHERE target_agent_id = ? AND source_agent_id = ? AND message_id = ?`, "agent-local", "agent-remote", "message-1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == want.Body {
		t.Fatal("inbox body was stored in plaintext")
	}
}

func TestActiveContactRejectsIdentityDrift(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	contact := model.Contact{
		LocalAgentID:           "agent-a",
		RemoteAgentID:          "agent-b",
		RemoteHostFingerprint:  "host-b-v1",
		RemoteAgentFingerprint: "key-b-v1",
		State:                  model.ContactStateActive,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := db.UpsertContact(ctx, contact); err != nil {
		t.Fatalf("insert contact: %v", err)
	}

	contact.RemoteHostFingerprint = "host-b-v2"
	contact.UpdatedAt = now.Add(time.Minute)
	if err := db.UpsertContact(ctx, contact); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("expected host identity conflict, got %v", err)
	}
	contact.RemoteHostFingerprint = "host-b-v1"
	contact.RemoteAgentFingerprint = "key-b-v2"
	if err := db.UpsertContact(ctx, contact); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("expected agent identity conflict, got %v", err)
	}
	contact.RemoteAgentFingerprint = "key-b-v1"
	contact.State = model.ContactStateRevoked
	if err := db.UpsertContact(ctx, contact); err != nil {
		t.Fatalf("same identity state update should be allowed: %v", err)
	}
}

func TestOutboxLifecycleFiltersDueMessages(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	for _, message := range []model.OutboxMessage{
		{
			MessageID: "due", IdempotencyKey: "idem-due", SourceAgentID: "agent-a",
			TargetAgentID: "agent-b", ContextID: "context-1", Payload: []byte("due"),
			State: model.OutboxStatePending, NextAttemptAt: now.Add(-time.Second),
		},
		{
			MessageID: "future", IdempotencyKey: "idem-future", SourceAgentID: "agent-a",
			TargetAgentID: "agent-b", ContextID: "context-1", Payload: []byte("future"),
			State: model.OutboxStatePending, NextAttemptAt: now.Add(time.Hour),
		},
		{
			MessageID: "cancelled", IdempotencyKey: "idem-cancelled", SourceAgentID: "agent-a",
			TargetAgentID: "agent-b", ContextID: "context-1", Payload: []byte("cancelled"),
			State: model.OutboxStatePending, NextAttemptAt: now.Add(-time.Second),
		},
	} {
		if err := db.EnqueueOutbox(ctx, message); err != nil {
			t.Fatalf("enqueue %s: %v", message.MessageID, err)
		}
	}
	if err := db.CancelOutbox(ctx, "cancelled"); err != nil {
		t.Fatalf("cancel outbox: %v", err)
	}

	due, err := db.ListDueOutbox(ctx, now, 10)
	if err != nil {
		t.Fatalf("list due outbox: %v", err)
	}
	if len(due) != 1 || due[0].MessageID != "due" {
		t.Fatalf("unexpected due messages: %+v", due)
	}

	nextAttempt := now.Add(2 * time.Minute)
	if err := db.ScheduleOutboxRetry(ctx, "due", nextAttempt); err != nil {
		t.Fatalf("schedule retry: %v", err)
	}
	retried, err := db.GetOutbox(ctx, "due")
	if err != nil {
		t.Fatalf("get retried outbox: %v", err)
	}
	if retried.AttemptCount != 1 || !retried.NextAttemptAt.Equal(nextAttempt) {
		t.Fatalf("unexpected retry state: %+v", retried)
	}

	receipt := model.DeliveryReceipt{
		MessageID:       "due",
		TargetAgentID:   "agent-b",
		RemoteReceiptID: "receipt-1",
		DeliveredAt:     now.Add(3 * time.Minute),
	}
	if err := db.MarkOutboxDelivered(ctx, receipt); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	delivered, err := db.GetOutbox(ctx, "due")
	if err != nil {
		t.Fatalf("get delivered outbox: %v", err)
	}
	if delivered.State != model.OutboxStateDelivered {
		t.Fatalf("expected delivered state, got %s", delivered.State)
	}
	var receiptCount int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM delivery_receipts
		WHERE message_id = ? AND target_agent_id = ?`, "due", "agent-b").Scan(&receiptCount); err != nil {
		t.Fatalf("read delivery receipt: %v", err)
	}
	if receiptCount != 1 {
		t.Fatalf("expected one delivery receipt, got %d", receiptCount)
	}
	due, err = db.ListDueOutbox(ctx, receipt.DeliveredAt.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("list due after delivery: %v", err)
	}
	if len(due) != 1 || due[0].MessageID != "future" {
		t.Fatalf("delivered and cancelled messages must not be due: %+v", due)
	}
}

func TestDeduplicationRejectsDuplicateMessageID(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()

	created, err := db.RecordMessageOnce(ctx, "agent-b", "message-1", "task-1")
	if err != nil {
		t.Fatalf("record message: %v", err)
	}
	if !created {
		t.Fatal("first message should be recorded")
	}
	created, err = db.RecordMessageOnce(ctx, "agent-b", "message-1", "task-2")
	if err != nil {
		t.Fatalf("record duplicate: %v", err)
	}
	if created {
		t.Fatal("duplicate message must not create another task")
	}
	record, err := db.GetDeduplication(ctx, "agent-b", "message-1")
	if err != nil {
		t.Fatalf("get deduplication: %v", err)
	}
	if record.TaskID != "task-1" {
		t.Fatalf("duplicate changed original task: %+v", record)
	}
}

func TestScopedDeduplicationSeparatesSourcesAndEpochs(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	created, err := db.RecordScopedMessageOnce(ctx, "source-a", "target", 1, "message", "task-a")
	if err != nil || !created {
		t.Fatalf("record first scoped message: %v %v", created, err)
	}
	created, err = db.RecordScopedMessageOnce(ctx, "source-b", "target", 1, "message", "task-b")
	if err != nil || !created {
		t.Fatalf("different source must be independent: %v %v", created, err)
	}
	created, err = db.RecordScopedMessageOnce(ctx, "source-a", "target", 2, "message", "task-c")
	if err != nil || !created {
		t.Fatalf("different epoch must be independent: %v %v", created, err)
	}
	created, err = db.RecordScopedMessageOnce(ctx, "source-a", "target", 1, "message", "task-d")
	if err != nil || created {
		t.Fatalf("same scoped key must be duplicate: %v %v", created, err)
	}
	record, err := db.GetScopedDeduplication(ctx, "source-a", "target", 1, "message")
	if err != nil || record.TaskID != "task-a" {
		t.Fatalf("unexpected scoped record: %+v %v", record, err)
	}
}

func TestDeliveryReceiptCanBeReadAndDeliveredTransitionIsIdempotent(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	message := model.OutboxMessage{
		MessageID: "message-1", IdempotencyKey: "idem-1", SourceAgentID: "agent-a",
		TargetAgentID: "agent-b", ContextID: "context-1", Payload: []byte("payload"),
		State: model.OutboxStatePending, NextAttemptAt: now,
	}
	if err := db.EnqueueOutbox(ctx, message); err != nil {
		t.Fatalf("enqueue outbox: %v", err)
	}
	receipt := model.DeliveryReceipt{
		MessageID: "message-1", TargetAgentID: "agent-b",
		RemoteReceiptID: "remote-1", DeliveredAt: now.Add(time.Second),
	}
	if err := db.MarkOutboxDelivered(ctx, receipt); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	if err := db.MarkOutboxDelivered(ctx, receipt); err != nil {
		t.Fatalf("repeat mark delivered should be idempotent: %v", err)
	}
	stored, err := db.GetDeliveryReceipt(ctx, "message-1", "agent-b")
	if err != nil {
		t.Fatalf("get delivery receipt: %v", err)
	}
	if stored.RemoteReceiptID != receipt.RemoteReceiptID || !stored.DeliveredAt.Equal(receipt.DeliveredAt) {
		t.Fatalf("unexpected delivery receipt: %+v", stored)
	}
}

func TestCancelOutboxIsIdempotentButCannotCancelDeliveredMessage(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, id := range []string{"cancelled", "delivered"} {
		if err := db.EnqueueOutbox(ctx, model.OutboxMessage{
			MessageID: id, IdempotencyKey: "idem-" + id, SourceAgentID: "agent-a",
			TargetAgentID: "agent-b", ContextID: "context-1", Payload: []byte(id),
			State: model.OutboxStatePending, NextAttemptAt: now,
		}); err != nil {
			t.Fatalf("enqueue %s: %v", id, err)
		}
	}
	if err := db.CancelOutbox(ctx, "cancelled"); err != nil {
		t.Fatalf("cancel outbox: %v", err)
	}
	if err := db.CancelOutbox(ctx, "cancelled"); err != nil {
		t.Fatalf("repeat cancel should be idempotent: %v", err)
	}
	if err := db.MarkOutboxDelivered(ctx, model.DeliveryReceipt{
		MessageID: "delivered", TargetAgentID: "agent-b", RemoteReceiptID: "receipt",
		DeliveredAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	if err := db.CancelOutbox(ctx, "delivered"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected invalid state, got %v", err)
	}
}

func TestClaimReplayNonceRejectsDuplicatesUntilExpiry(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	claimed, err := db.ClaimReplayNonce(ctx, "agent-local", "agent-remote", "nonce-1", now.Add(time.Minute), now)
	if err != nil {
		t.Fatalf("claim nonce: %v", err)
	}
	if !claimed {
		t.Fatal("first nonce claim should succeed")
	}

	claimed, err = db.ClaimReplayNonce(ctx, "agent-local", "agent-remote", "nonce-1", now.Add(time.Minute), now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("claim duplicate nonce: %v", err)
	}
	if claimed {
		t.Fatal("duplicate nonce must be rejected while active")
	}

	claimed, err = db.ClaimReplayNonce(ctx, "agent-local", "agent-remote", "nonce-1", now.Add(2*time.Minute), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("reclaim expired nonce: %v", err)
	}
	if !claimed {
		t.Fatal("expired nonce should be reclaimable")
	}
}

func TestTaskIndexUpsertAndContextListing(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	task := model.TaskIndex{
		TaskID: "task-1", ContextID: "context-1", LocalAgentID: "agent-a",
		RemoteAgentID: "agent-b", State: "working", Cursor: "cursor-1", UpdatedAt: now,
	}
	if err := db.UpsertTaskIndex(ctx, task); err != nil {
		t.Fatalf("upsert task index: %v", err)
	}
	task.State = "completed"
	task.Cursor = "cursor-2"
	task.UpdatedAt = now.Add(time.Minute)
	if err := db.UpsertTaskIndex(ctx, task); err != nil {
		t.Fatalf("update task index: %v", err)
	}
	stored, err := db.GetTaskIndex(ctx, "task-1")
	if err != nil {
		t.Fatalf("get task index: %v", err)
	}
	if stored.State != "completed" || stored.Cursor != "cursor-2" || !stored.UpdatedAt.Equal(task.UpdatedAt) {
		t.Fatalf("unexpected task index: %+v", stored)
	}
	tasks, err := db.ListTaskIndexesByContext(ctx, "agent-a", "context-1")
	if err != nil {
		t.Fatalf("list task indexes: %v", err)
	}
	if len(tasks) != 1 || tasks[0].TaskID != "task-1" {
		t.Fatalf("unexpected task indexes: %+v", tasks)
	}
}

func TestAttachmentGrantPersistsAndAuthorizesExactScope(t *testing.T) {
	databasePath := t.TempDir() + "/link.db"
	db, err := Open(databasePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	grant := model.AttachmentGrant{
		GrantID: "grant-1", BlobID: "blob-1", OwnerAgentID: "agent-a",
		TargetAgentID: "agent-b", ContextID: "context-1", Digest: "digest-1",
		Size: 1024, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if err := db.CreateAttachmentGrant(ctx, grant); err != nil {
		t.Fatalf("create attachment grant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	db, err = Open(databasePath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer db.Close()

	stored, err := db.AuthorizeAttachmentGrant(ctx, grant.GrantID, grant.BlobID, grant.OwnerAgentID, grant.TargetAgentID, grant.ContextID, grant.Digest, now)
	if err != nil {
		t.Fatalf("authorize attachment grant: %v", err)
	}
	if stored.Size != grant.Size || stored.GrantID != grant.GrantID {
		t.Fatalf("unexpected stored grant: %+v", stored)
	}
	if _, err := db.AuthorizeAttachmentGrant(ctx, grant.GrantID, grant.BlobID, grant.OwnerAgentID, "agent-c", grant.ContextID, grant.Digest, now); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("expected target mismatch rejection, got %v", err)
	}
	if err := db.RevokeAttachmentGrant(ctx, grant.GrantID, now.Add(time.Minute)); err != nil {
		t.Fatalf("revoke attachment grant: %v", err)
	}
	if _, err := db.AuthorizeAttachmentGrant(ctx, grant.GrantID, grant.BlobID, grant.OwnerAgentID, grant.TargetAgentID, grant.ContextID, grant.Digest, now.Add(2*time.Minute)); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("expected revoked grant rejection, got %v", err)
	}
}

func TestAttachmentGrantRejectsExpiryAndContactRevocation(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, grantID := range []string{"grant-expired", "grant-contact"} {
		if err := db.CreateAttachmentGrant(ctx, model.AttachmentGrant{
			GrantID: grantID, BlobID: "blob-1", OwnerAgentID: "agent-a",
			TargetAgentID: "agent-b", ContextID: "context-1", Digest: "digest-1",
			Size: 10, ExpiresAt: now.Add(time.Minute), CreatedAt: now,
		}); err != nil {
			t.Fatalf("create %s: %v", grantID, err)
		}
	}
	if _, err := db.AuthorizeAttachmentGrant(ctx, "grant-expired", "blob-1", "agent-a", "agent-b", "context-1", "digest-1", now.Add(2*time.Minute)); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expected expired grant rejection, got %v", err)
	}
	revoked, err := db.RevokeAttachmentGrantsForContact(ctx, "agent-a", "agent-b", now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("revoke contact grants: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("expected two grants revoked, got %d", revoked)
	}
	if _, err := db.AuthorizeAttachmentGrant(ctx, "grant-contact", "blob-1", "agent-a", "agent-b", "context-1", "digest-1", now.Add(40*time.Second)); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("expected contact-revoked grant rejection, got %v", err)
	}
}

func TestAuditEntriesAreAppendOnlyAndFilterable(t *testing.T) {
	db, err := Open(t.TempDir() + "/link.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	entries := []model.AuditEntry{
		{ID: "audit-1", ActorAgentID: "agent-a", RemoteAgentID: "agent-b", Action: "message.accept", Outcome: "allowed", RequestID: "request-1", CreatedAt: now},
		{ID: "audit-2", ActorAgentID: "agent-a", RemoteAgentID: "agent-c", Action: "message.reject", Outcome: "blocked", RequestID: "request-2", CreatedAt: now.Add(time.Second)},
	}
	for _, entry := range entries {
		if err := db.AppendAuditEntry(ctx, entry); err != nil {
			t.Fatalf("append audit entry: %v", err)
		}
	}
	filtered, err := db.ListAuditEntries(ctx, "agent-a", "agent-b", 10)
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ID != "audit-1" {
		t.Fatalf("unexpected audit entries: %+v", filtered)
	}
	if err := db.AppendAuditEntry(ctx, entries[0]); err == nil {
		t.Fatal("duplicate audit id must not overwrite existing entry")
	}
}
