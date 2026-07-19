package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/EvanSener/snw-agent-link/internal/model"
	"github.com/EvanSener/snw-agent-link/internal/secure"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound         = errors.New("record not found")
	ErrInvalidState     = errors.New("invalid record state")
	ErrIdentityConflict = errors.New("contact identity fingerprint conflict")
	ErrGrantDenied      = errors.New("attachment grant denied")
	ErrGrantExpired     = errors.New("attachment grant expired")
	ErrGrantRevoked     = errors.New("attachment grant revoked")
)

type Store struct {
	db   *sql.DB
	aead *secure.AEAD
	path string
}

type PairingRequestValidator func(model.PairingRequest) error

func Open(path string) (*Store, error) {
	return open(path, nil)
}

func OpenWithKey(path string, provider secure.KeyProvider) (*Store, error) {
	if provider == nil {
		return nil, errors.New("outbox key provider is required")
	}
	return open(path, secure.NewAEAD(provider))
}

func open(path string, aead *secure.AEAD) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, aead: aead, path: path}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Path() string { return s.path }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE IF NOT EXISTS contacts (
			local_agent_id TEXT NOT NULL,
			remote_agent_id TEXT NOT NULL,
			remote_node_id TEXT NOT NULL DEFAULT '',
			remote_endpoint TEXT NOT NULL DEFAULT '',
			remote_binding TEXT NOT NULL DEFAULT '',
			remote_host_fingerprint TEXT NOT NULL,
			remote_agent_fingerprint TEXT NOT NULL,
			state TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (local_agent_id, remote_agent_id)
		)`,
		`CREATE TABLE IF NOT EXISTS agent_registrations (
			agent_id TEXT PRIMARY KEY,
			display_name TEXT NOT NULL,
			local_endpoint TEXT NOT NULL,
			agent_card_json BLOB NOT NULL,
			identity_public_key BLOB NOT NULL,
			capability_public_key BLOB NOT NULL DEFAULT X'',
			capability_generation INTEGER NOT NULL DEFAULT 0,
			registration_token_hash BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS pairing_requests (
			id TEXT NOT NULL,
			local_agent_id TEXT NOT NULL,
			remote_agent_id TEXT NOT NULL,
			remote_host_fingerprint TEXT NOT NULL,
			remote_agent_fingerprint TEXT NOT NULL,
			secret_hash BLOB NOT NULL,
			expires_at INTEGER NOT NULL,
			consumed_at INTEGER,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (id, local_agent_id)
		)`,
		`CREATE TABLE IF NOT EXISTS pairing_sessions (
			invite_id TEXT NOT NULL,
			local_agent_id TEXT NOT NULL,
			remote_agent_id TEXT NOT NULL,
			role TEXT NOT NULL,
			local_host_fingerprint TEXT NOT NULL,
			remote_host_fingerprint TEXT NOT NULL,
			remote_agent_public_key BLOB,
			invite_digest TEXT NOT NULL,
			acceptance_digest TEXT NOT NULL,
			confirmation_digest TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (invite_id, local_agent_id)
		)`,
		`CREATE TABLE IF NOT EXISTS outbox_messages (
			message_id TEXT PRIMARY KEY,
			idempotency_key TEXT NOT NULL UNIQUE,
			source_agent_id TEXT NOT NULL,
			target_agent_id TEXT NOT NULL,
			context_id TEXT NOT NULL,
			payload BLOB NOT NULL,
			state TEXT NOT NULL,
			attempt_count INTEGER NOT NULL,
			next_attempt_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS deduplication_records (
			target_agent_id TEXT NOT NULL,
			message_id TEXT NOT NULL,
			task_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (target_agent_id, message_id)
		)`,
		`CREATE TABLE IF NOT EXISTS scoped_deduplication_records (
			source_agent_id TEXT NOT NULL,
			target_agent_id TEXT NOT NULL,
			agent_key_epoch INTEGER NOT NULL,
			message_id TEXT NOT NULL,
			task_id TEXT NOT NULL,
			response_status INTEGER NOT NULL DEFAULT 0,
			response_type TEXT NOT NULL DEFAULT '',
			response_body BLOB NOT NULL DEFAULT X'',
			created_at INTEGER NOT NULL,
			PRIMARY KEY (source_agent_id, target_agent_id, agent_key_epoch, message_id)
		)`,
		`CREATE TABLE IF NOT EXISTS delivery_receipts (
			message_id TEXT NOT NULL,
			target_agent_id TEXT NOT NULL,
			remote_receipt_id TEXT NOT NULL,
			delivered_at INTEGER NOT NULL,
			PRIMARY KEY (message_id, target_agent_id)
		)`,
		`CREATE TABLE IF NOT EXISTS task_index (
			task_id TEXT PRIMARY KEY,
			context_id TEXT NOT NULL,
			local_agent_id TEXT NOT NULL,
			remote_agent_id TEXT NOT NULL,
			state TEXT NOT NULL,
			cursor TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS inbox_messages (
			target_agent_id TEXT NOT NULL,
			source_agent_id TEXT NOT NULL,
			message_id TEXT NOT NULL,
			context_id TEXT NOT NULL,
			body BLOB NOT NULL,
			state TEXT NOT NULL,
			received_at INTEGER NOT NULL,
			read_at INTEGER,
			PRIMARY KEY (target_agent_id, source_agent_id, message_id)
		)`,
		`CREATE INDEX IF NOT EXISTS inbox_messages_unread_idx
			ON inbox_messages(target_agent_id, state, received_at DESC)`,
		`CREATE TABLE IF NOT EXISTS audit_entries (
			id TEXT PRIMARY KEY,
			actor_agent_id TEXT NOT NULL,
			remote_agent_id TEXT NOT NULL,
			action TEXT NOT NULL,
			outcome TEXT NOT NULL,
			request_id TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS replay_nonces (
			local_agent_id TEXT NOT NULL,
			remote_agent_id TEXT NOT NULL,
			nonce TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (local_agent_id, remote_agent_id, nonce)
		)`,
		`CREATE TABLE IF NOT EXISTS attachment_grants (
			grant_id TEXT PRIMARY KEY,
			blob_id TEXT NOT NULL,
			owner_agent_id TEXT NOT NULL,
			target_agent_id TEXT NOT NULL,
			context_id TEXT NOT NULL,
			digest TEXT NOT NULL,
			size INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked_at INTEGER,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS attachment_grants_contact_idx
			ON attachment_grants(owner_agent_id, target_agent_id, revoked_at, expires_at)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply sqlite migration: %w", err)
		}
	}
	for _, column := range []struct{ name, definition string }{
		{name: "remote_node_id", definition: "TEXT NOT NULL DEFAULT ''"},
		{name: "remote_endpoint", definition: "TEXT NOT NULL DEFAULT ''"},
		{name: "remote_binding", definition: "TEXT NOT NULL DEFAULT ''"},
		{name: "capability_public_key", definition: "BLOB NOT NULL DEFAULT X''"},
		{name: "capability_generation", definition: "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := s.ensureColumn(ctx, "contacts", column.name, column.definition); err != nil {
			return err
		}
	}
	for _, column := range []struct{ name, definition string }{
		{name: "response_status", definition: "INTEGER NOT NULL DEFAULT 0"},
		{name: "response_type", definition: "TEXT NOT NULL DEFAULT ''"},
		{name: "response_body", definition: "BLOB NOT NULL DEFAULT X''"},
	} {
		if err := s.ensureColumn(ctx, "scoped_deduplication_records", column.name, column.definition); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	defer rows.Close()
	var found bool
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan %s schema: %w", table, err)
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+definition); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}

func (s *Store) UpsertContact(ctx context.Context, contact model.Contact) error {
	now := time.Now().UTC()
	if contact.CreatedAt.IsZero() {
		contact.CreatedAt = now
	}
	contact.UpdatedAt = now
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO contacts (
			local_agent_id, remote_agent_id, remote_node_id, remote_endpoint, remote_binding,
			remote_host_fingerprint, remote_agent_fingerprint, state, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(local_agent_id, remote_agent_id) DO UPDATE SET
			remote_node_id = excluded.remote_node_id,
			remote_endpoint = excluded.remote_endpoint,
			remote_binding = excluded.remote_binding,
			remote_host_fingerprint = excluded.remote_host_fingerprint,
			remote_agent_fingerprint = excluded.remote_agent_fingerprint,
			state = excluded.state,
			updated_at = excluded.updated_at
		WHERE contacts.state NOT IN ('active', 'awaiting_confirmation')
			OR (contacts.remote_host_fingerprint = excluded.remote_host_fingerprint
				AND contacts.remote_agent_fingerprint = excluded.remote_agent_fingerprint)`,
		contact.LocalAgentID, contact.RemoteAgentID, contact.RemoteNodeID, contact.RemoteEndpoint, contact.RemoteBinding,
		contact.RemoteHostFingerprint, contact.RemoteAgentFingerprint, contact.State, millis(contact.CreatedAt), millis(contact.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("upsert contact: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("upsert contact rows: %w", err)
	}
	if rows != 1 {
		return ErrIdentityConflict
	}
	return nil
}

func (s *Store) ListContacts(ctx context.Context, localAgentID string) ([]model.Contact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT local_agent_id, remote_agent_id, remote_node_id, remote_endpoint, remote_binding,
		remote_host_fingerprint, remote_agent_fingerprint, state, created_at, updated_at
		FROM contacts WHERE local_agent_id = ? ORDER BY remote_agent_id`, localAgentID)
	if err != nil {
		return nil, fmt.Errorf("list contacts: %w", err)
	}
	defer rows.Close()
	var contacts []model.Contact
	for rows.Next() {
		var contact model.Contact
		var createdAt, updatedAt int64
		if err := rows.Scan(&contact.LocalAgentID, &contact.RemoteAgentID, &contact.RemoteNodeID, &contact.RemoteEndpoint, &contact.RemoteBinding, &contact.RemoteHostFingerprint,
			&contact.RemoteAgentFingerprint, &contact.State, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan contact: %w", err)
		}
		contact.CreatedAt = fromMillis(createdAt)
		contact.UpdatedAt = fromMillis(updatedAt)
		contacts = append(contacts, contact)
	}
	return contacts, rows.Err()
}

func (s *Store) RegisterAgent(ctx context.Context, registration model.AgentRegistration) error {
	now := time.Now().UTC()
	if registration.CreatedAt.IsZero() {
		registration.CreatedAt = now
	}
	registration.UpdatedAt = now
	if registration.CapabilityPublicKey == nil {
		registration.CapabilityPublicKey = []byte{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO agent_registrations (
		agent_id, display_name, local_endpoint, agent_card_json, identity_public_key,
		capability_public_key, capability_generation, registration_token_hash, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, registration.AgentID, registration.DisplayName,
		registration.LocalEndpoint, registration.AgentCardJSON, registration.IdentityPublicKey,
		registration.CapabilityPublicKey, registration.CapabilityGeneration,
		registration.RegistrationTokenHash, millis(registration.CreatedAt), millis(registration.UpdatedAt))
	if err != nil {
		return fmt.Errorf("register agent: %w", err)
	}
	return nil
}

func (s *Store) GetAgentRegistration(ctx context.Context, agentID string) (model.AgentRegistration, error) {
	var registration model.AgentRegistration
	var createdAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT agent_id, display_name, local_endpoint, agent_card_json,
		identity_public_key, capability_public_key, capability_generation, registration_token_hash, created_at, updated_at
		FROM agent_registrations WHERE agent_id = ?`, agentID).Scan(&registration.AgentID,
		&registration.DisplayName, &registration.LocalEndpoint, &registration.AgentCardJSON,
		&registration.IdentityPublicKey, &registration.CapabilityPublicKey, &registration.CapabilityGeneration,
		&registration.RegistrationTokenHash, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AgentRegistration{}, ErrNotFound
	}
	if err != nil {
		return model.AgentRegistration{}, fmt.Errorf("get agent registration: %w", err)
	}
	registration.CreatedAt = fromMillis(createdAt)
	registration.UpdatedAt = fromMillis(updatedAt)
	return registration, nil
}

func (s *Store) ListAgentRegistrations(ctx context.Context) ([]model.AgentRegistration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT agent_id, display_name, local_endpoint, agent_card_json,
		identity_public_key, capability_public_key, capability_generation, registration_token_hash, created_at, updated_at
		FROM agent_registrations ORDER BY agent_id`)
	if err != nil {
		return nil, fmt.Errorf("list agent registrations: %w", err)
	}
	defer rows.Close()
	var registrations []model.AgentRegistration
	for rows.Next() {
		var registration model.AgentRegistration
		var createdAt, updatedAt int64
		if err := rows.Scan(&registration.AgentID, &registration.DisplayName, &registration.LocalEndpoint,
			&registration.AgentCardJSON, &registration.IdentityPublicKey, &registration.CapabilityPublicKey,
			&registration.CapabilityGeneration, &registration.RegistrationTokenHash,
			&createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan agent registration: %w", err)
		}
		registration.CreatedAt = fromMillis(createdAt)
		registration.UpdatedAt = fromMillis(updatedAt)
		registrations = append(registrations, registration)
	}
	return registrations, rows.Err()
}

func (s *Store) UpdateAgentCapability(ctx context.Context, agentID string, publicKey []byte, generation uint64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE agent_registrations SET capability_public_key = ?, capability_generation = ?, updated_at = ? WHERE agent_id = ?`, publicKey, generation, millis(time.Now().UTC()), agentID)
	if err != nil {
		return fmt.Errorf("update agent capability: %w", err)
	}
	return requireOneRow(result, "update agent capability")
}

func (s *Store) GetContact(ctx context.Context, localAgentID, remoteAgentID string) (model.Contact, error) {
	var contact model.Contact
	var createdAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT local_agent_id, remote_agent_id, remote_node_id, remote_endpoint, remote_binding,
		remote_host_fingerprint, remote_agent_fingerprint, state, created_at, updated_at
		FROM contacts WHERE local_agent_id = ? AND remote_agent_id = ?`, localAgentID, remoteAgentID).Scan(
		&contact.LocalAgentID, &contact.RemoteAgentID, &contact.RemoteNodeID, &contact.RemoteEndpoint, &contact.RemoteBinding, &contact.RemoteHostFingerprint,
		&contact.RemoteAgentFingerprint, &contact.State, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Contact{}, ErrNotFound
	}
	if err != nil {
		return model.Contact{}, fmt.Errorf("get contact: %w", err)
	}
	contact.CreatedAt = fromMillis(createdAt)
	contact.UpdatedAt = fromMillis(updatedAt)
	return contact, nil
}

func (s *Store) CreatePairingRequest(ctx context.Context, request model.PairingRequest) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO pairing_requests (
		id, local_agent_id, remote_agent_id, remote_host_fingerprint,
		remote_agent_fingerprint, secret_hash, expires_at, consumed_at, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`, request.ID, request.LocalAgentID,
		request.RemoteAgentID, request.RemoteHostFingerprint, request.RemoteAgentFingerprint,
		request.SecretHash, millis(request.ExpiresAt), millis(request.CreatedAt))
	if err != nil {
		return fmt.Errorf("create pairing request: %w", err)
	}
	return nil
}

func (s *Store) GetPairingRequest(ctx context.Context, id string) (model.PairingRequest, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return model.PairingRequest{}, fmt.Errorf("begin get pairing request: %w", err)
	}
	defer tx.Rollback()
	return getPairingRequest(ctx, tx, id)
}

func (s *Store) GetPairingRequestForAgent(ctx context.Context, id, localAgentID string) (model.PairingRequest, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return model.PairingRequest{}, fmt.Errorf("begin get pairing request: %w", err)
	}
	defer tx.Rollback()
	return getPairingRequestForAgent(ctx, tx, id, localAgentID)
}

func (s *Store) UpsertPairingSession(ctx context.Context, session model.PairingSession) error {
	now := time.Now().UTC()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	session.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO pairing_sessions (
		invite_id, local_agent_id, remote_agent_id, role, local_host_fingerprint,
		remote_host_fingerprint, remote_agent_public_key, invite_digest,
		acceptance_digest, confirmation_digest, expires_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(invite_id, local_agent_id) DO UPDATE SET
		remote_agent_id = excluded.remote_agent_id,
		role = excluded.role,
		local_host_fingerprint = excluded.local_host_fingerprint,
		remote_host_fingerprint = excluded.remote_host_fingerprint,
		remote_agent_public_key = excluded.remote_agent_public_key,
		invite_digest = excluded.invite_digest,
		acceptance_digest = excluded.acceptance_digest,
		confirmation_digest = excluded.confirmation_digest,
		expires_at = excluded.expires_at,
		updated_at = excluded.updated_at`,
		session.InviteID, session.LocalAgentID, session.RemoteAgentID, session.Role,
		session.LocalHostFingerprint, session.RemoteHostFingerprint, session.RemoteAgentPublicKey,
		session.InviteDigest, session.AcceptanceDigest, session.ConfirmationDigest,
		millis(session.ExpiresAt), millis(session.CreatedAt), millis(session.UpdatedAt))
	if err != nil {
		return fmt.Errorf("upsert pairing session: %w", err)
	}
	return nil
}

func (s *Store) GetPairingSession(ctx context.Context, inviteID, localAgentID string) (model.PairingSession, error) {
	var session model.PairingSession
	var expiresAt, createdAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT invite_id, local_agent_id, remote_agent_id,
		role, local_host_fingerprint, remote_host_fingerprint, remote_agent_public_key,
		invite_digest, acceptance_digest, confirmation_digest, expires_at, created_at, updated_at
		FROM pairing_sessions WHERE invite_id = ? AND local_agent_id = ?`, inviteID, localAgentID).Scan(
		&session.InviteID, &session.LocalAgentID, &session.RemoteAgentID, &session.Role,
		&session.LocalHostFingerprint, &session.RemoteHostFingerprint, &session.RemoteAgentPublicKey,
		&session.InviteDigest, &session.AcceptanceDigest, &session.ConfirmationDigest,
		&expiresAt, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PairingSession{}, ErrNotFound
	}
	if err != nil {
		return model.PairingSession{}, fmt.Errorf("get pairing session: %w", err)
	}
	session.ExpiresAt = fromMillis(expiresAt)
	session.CreatedAt = fromMillis(createdAt)
	session.UpdatedAt = fromMillis(updatedAt)
	return session, nil
}

func (s *Store) FindPairingSession(ctx context.Context, localAgentID, remoteAgentID string) (model.PairingSession, error) {
	var session model.PairingSession
	var expiresAt, createdAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT invite_id, local_agent_id, remote_agent_id,
		role, local_host_fingerprint, remote_host_fingerprint, remote_agent_public_key,
		invite_digest, acceptance_digest, confirmation_digest, expires_at, created_at, updated_at
		FROM pairing_sessions WHERE local_agent_id = ? AND remote_agent_id = ?
		ORDER BY updated_at DESC LIMIT 1`, localAgentID, remoteAgentID).Scan(
		&session.InviteID, &session.LocalAgentID, &session.RemoteAgentID, &session.Role,
		&session.LocalHostFingerprint, &session.RemoteHostFingerprint, &session.RemoteAgentPublicKey,
		&session.InviteDigest, &session.AcceptanceDigest, &session.ConfirmationDigest,
		&expiresAt, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PairingSession{}, ErrNotFound
	}
	if err != nil {
		return model.PairingSession{}, fmt.Errorf("find pairing session: %w", err)
	}
	session.ExpiresAt = fromMillis(expiresAt)
	session.CreatedAt = fromMillis(createdAt)
	session.UpdatedAt = fromMillis(updatedAt)
	return session, nil
}

func (s *Store) ValidateAndConsumePairingRequest(
	ctx context.Context,
	id string,
	consumedAt time.Time,
	validate PairingRequestValidator,
) (model.PairingRequest, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.PairingRequest{}, false, fmt.Errorf("begin consume pairing request: %w", err)
	}
	defer tx.Rollback()
	request, err := getPairingRequest(ctx, tx, id)
	if err != nil {
		return model.PairingRequest{}, false, err
	}
	if request.ConsumedAt != nil {
		return request, false, nil
	}
	if validate != nil {
		if err := validate(request); err != nil {
			return model.PairingRequest{}, false, err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE pairing_requests SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL`, millis(consumedAt), id)
	if err != nil {
		return model.PairingRequest{}, false, fmt.Errorf("consume pairing request: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return model.PairingRequest{}, false, fmt.Errorf("consume pairing request rows: %w", err)
	}
	if rows != 1 {
		return request, false, nil
	}
	request.ConsumedAt = &consumedAt
	if err := tx.Commit(); err != nil {
		return model.PairingRequest{}, false, fmt.Errorf("commit pairing request: %w", err)
	}
	return request, true, nil
}

func (s *Store) ValidateAndConsumePairingRequestForAgent(
	ctx context.Context,
	id, localAgentID string,
	consumedAt time.Time,
	validate PairingRequestValidator,
) (model.PairingRequest, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.PairingRequest{}, false, fmt.Errorf("begin consume pairing request: %w", err)
	}
	defer tx.Rollback()
	request, err := getPairingRequestForAgent(ctx, tx, id, localAgentID)
	if err != nil {
		return model.PairingRequest{}, false, err
	}
	if request.ConsumedAt != nil {
		return request, false, nil
	}
	if validate != nil {
		if err := validate(request); err != nil {
			return model.PairingRequest{}, false, err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE pairing_requests SET consumed_at = ? WHERE id = ? AND local_agent_id = ? AND consumed_at IS NULL`, millis(consumedAt), id, localAgentID)
	if err != nil {
		return model.PairingRequest{}, false, fmt.Errorf("consume pairing request: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return model.PairingRequest{}, false, fmt.Errorf("consume pairing request rows: %w", err)
	}
	if rows != 1 {
		return request, false, nil
	}
	request.ConsumedAt = &consumedAt
	if err := tx.Commit(); err != nil {
		return model.PairingRequest{}, false, fmt.Errorf("commit pairing request: %w", err)
	}
	return request, true, nil
}

func getPairingRequest(ctx context.Context, tx *sql.Tx, id string) (model.PairingRequest, error) {
	var request model.PairingRequest
	var expiresAt, createdAt int64
	var consumedAt sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id, local_agent_id, remote_agent_id,
		remote_host_fingerprint, remote_agent_fingerprint, secret_hash, expires_at,
		consumed_at, created_at FROM pairing_requests WHERE id = ? ORDER BY created_at LIMIT 1`, id).Scan(
		&request.ID, &request.LocalAgentID, &request.RemoteAgentID,
		&request.RemoteHostFingerprint, &request.RemoteAgentFingerprint, &request.SecretHash,
		&expiresAt, &consumedAt, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PairingRequest{}, ErrNotFound
	}
	if err != nil {
		return model.PairingRequest{}, fmt.Errorf("get pairing request: %w", err)
	}
	request.ExpiresAt = fromMillis(expiresAt)
	request.CreatedAt = fromMillis(createdAt)
	if consumedAt.Valid {
		value := fromMillis(consumedAt.Int64)
		request.ConsumedAt = &value
	}
	return request, nil
}

func getPairingRequestForAgent(ctx context.Context, tx *sql.Tx, id, localAgentID string) (model.PairingRequest, error) {
	var request model.PairingRequest
	var expiresAt, createdAt int64
	var consumedAt sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id, local_agent_id, remote_agent_id,
		remote_host_fingerprint, remote_agent_fingerprint, secret_hash, expires_at,
		consumed_at, created_at FROM pairing_requests WHERE id = ? AND local_agent_id = ?`, id, localAgentID).Scan(
		&request.ID, &request.LocalAgentID, &request.RemoteAgentID,
		&request.RemoteHostFingerprint, &request.RemoteAgentFingerprint, &request.SecretHash,
		&expiresAt, &consumedAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PairingRequest{}, ErrNotFound
	}
	if err != nil {
		return model.PairingRequest{}, fmt.Errorf("get pairing request: %w", err)
	}
	request.ExpiresAt = fromMillis(expiresAt)
	request.CreatedAt = fromMillis(createdAt)
	if consumedAt.Valid {
		value := fromMillis(consumedAt.Int64)
		request.ConsumedAt = &value
	}
	return request, nil
}

func (s *Store) EnqueueOutbox(ctx context.Context, message model.OutboxMessage) error {
	now := time.Now().UTC()
	if message.CreatedAt.IsZero() {
		message.CreatedAt = now
	}
	message.UpdatedAt = now
	payload := append([]byte(nil), message.Payload...)
	if s.aead != nil {
		var err error
		payload, err = s.aead.Encrypt(ctx, payload, outboxAssociatedData(message))
		if err != nil {
			return fmt.Errorf("encrypt outbox payload: %w", err)
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO outbox_messages (
		message_id, idempotency_key, source_agent_id, target_agent_id, context_id,
		payload, state, attempt_count, next_attempt_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, message.MessageID, message.IdempotencyKey,
		message.SourceAgentID, message.TargetAgentID, message.ContextID, payload,
		message.State, message.AttemptCount, millis(message.NextAttemptAt),
		millis(message.CreatedAt), millis(message.UpdatedAt))
	if err != nil {
		return fmt.Errorf("enqueue outbox: %w", err)
	}
	return nil
}

func (s *Store) GetOutbox(ctx context.Context, messageID string) (model.OutboxMessage, error) {
	var message model.OutboxMessage
	var nextAttemptAt, createdAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT message_id, idempotency_key, source_agent_id,
		target_agent_id, context_id, payload, state, attempt_count, next_attempt_at,
		created_at, updated_at FROM outbox_messages WHERE message_id = ?`, messageID).Scan(
		&message.MessageID, &message.IdempotencyKey, &message.SourceAgentID,
		&message.TargetAgentID, &message.ContextID, &message.Payload, &message.State,
		&message.AttemptCount, &nextAttemptAt, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OutboxMessage{}, ErrNotFound
	}
	if err != nil {
		return model.OutboxMessage{}, fmt.Errorf("get outbox: %w", err)
	}
	message.NextAttemptAt = fromMillis(nextAttemptAt)
	message.CreatedAt = fromMillis(createdAt)
	message.UpdatedAt = fromMillis(updatedAt)
	return s.restoreOutbox(ctx, message)
}

func (s *Store) ListDueOutbox(ctx context.Context, now time.Time, limit int) ([]model.OutboxMessage, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT message_id, idempotency_key, source_agent_id,
		target_agent_id, context_id, payload, state, attempt_count, next_attempt_at, created_at, updated_at
		FROM outbox_messages WHERE state = ? AND next_attempt_at <= ?
		ORDER BY next_attempt_at, created_at LIMIT ?`, model.OutboxStatePending, millis(now), limit)
	if err != nil {
		return nil, fmt.Errorf("list due outbox: %w", err)
	}
	defer rows.Close()
	var messages []model.OutboxMessage
	for rows.Next() {
		message, err := scanOutbox(rows)
		if err != nil {
			return nil, err
		}
		message, err = s.restoreOutbox(ctx, message)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

func (s *Store) ScheduleOutboxRetry(ctx context.Context, messageID string, nextAttemptAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE outbox_messages SET attempt_count = attempt_count + 1,
		next_attempt_at = ?, updated_at = ? WHERE message_id = ? AND state = ?`, millis(nextAttemptAt),
		millis(time.Now().UTC()), messageID, model.OutboxStatePending)
	if err != nil {
		return fmt.Errorf("schedule outbox retry: %w", err)
	}
	return requireOneRow(result, "schedule outbox retry")
}

func (s *Store) MarkOutboxDelivered(ctx context.Context, receipt model.DeliveryReceipt) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin mark delivered: %w", err)
	}
	defer tx.Rollback()
	var state model.OutboxState
	err = tx.QueryRowContext(ctx, `SELECT state FROM outbox_messages
		WHERE message_id = ? AND target_agent_id = ?`, receipt.MessageID, receipt.TargetAgentID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get outbox delivery state: %w", err)
	}
	if state == model.OutboxStateDelivered {
		existing, err := getDeliveryReceipt(ctx, tx, receipt.MessageID, receipt.TargetAgentID)
		if err != nil {
			return err
		}
		if existing.RemoteReceiptID != receipt.RemoteReceiptID || !existing.DeliveredAt.Equal(receipt.DeliveredAt) {
			return ErrInvalidState
		}
		return tx.Commit()
	}
	if state != model.OutboxStatePending {
		return ErrInvalidState
	}
	result, err := tx.ExecContext(ctx, `UPDATE outbox_messages SET state = ?, updated_at = ?
		WHERE message_id = ? AND target_agent_id = ? AND state = ?`, model.OutboxStateDelivered,
		millis(receipt.DeliveredAt), receipt.MessageID, receipt.TargetAgentID, model.OutboxStatePending)
	if err != nil {
		return fmt.Errorf("mark outbox delivered: %w", err)
	}
	if err := requireOneRow(result, "mark outbox delivered"); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO delivery_receipts (
		message_id, target_agent_id, remote_receipt_id, delivered_at
	) VALUES (?, ?, ?, ?) ON CONFLICT(message_id, target_agent_id) DO NOTHING`, receipt.MessageID,
		receipt.TargetAgentID, receipt.RemoteReceiptID, millis(receipt.DeliveredAt))
	if err != nil {
		return fmt.Errorf("record delivery receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delivered outbox: %w", err)
	}
	return nil
}

func (s *Store) CancelOutbox(ctx context.Context, messageID string) error {
	var state model.OutboxState
	err := s.db.QueryRowContext(ctx, `SELECT state FROM outbox_messages WHERE message_id = ?`, messageID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get outbox cancel state: %w", err)
	}
	if state == model.OutboxStateCancelled {
		return nil
	}
	if state != model.OutboxStatePending {
		return ErrInvalidState
	}
	result, err := s.db.ExecContext(ctx, `UPDATE outbox_messages SET state = ?, updated_at = ?
		WHERE message_id = ? AND state = ?`, model.OutboxStateCancelled, millis(time.Now().UTC()),
		messageID, model.OutboxStatePending)
	if err != nil {
		return fmt.Errorf("cancel outbox: %w", err)
	}
	return requireOneRow(result, "cancel outbox")
}

func (s *Store) CancelOutboxForContact(ctx context.Context, sourceAgentID, targetAgentID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE outbox_messages SET state = ?, updated_at = ?
		WHERE source_agent_id = ? AND target_agent_id = ? AND state = ?`,
		model.OutboxStateCancelled, millis(time.Now().UTC()), sourceAgentID, targetAgentID, model.OutboxStatePending)
	if err != nil {
		return fmt.Errorf("cancel contact outbox: %w", err)
	}
	return nil
}

func (s *Store) GetDeliveryReceipt(
	ctx context.Context,
	messageID string,
	targetAgentID string,
) (model.DeliveryReceipt, error) {
	return getDeliveryReceipt(ctx, s.db, messageID, targetAgentID)
}

func getDeliveryReceipt(
	ctx context.Context,
	queryer interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	},
	messageID string,
	targetAgentID string,
) (model.DeliveryReceipt, error) {
	var receipt model.DeliveryReceipt
	var deliveredAt int64
	err := queryer.QueryRowContext(ctx, `SELECT message_id, target_agent_id, remote_receipt_id, delivered_at
		FROM delivery_receipts WHERE message_id = ? AND target_agent_id = ?`, messageID, targetAgentID).Scan(
		&receipt.MessageID, &receipt.TargetAgentID, &receipt.RemoteReceiptID, &deliveredAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DeliveryReceipt{}, ErrNotFound
	}
	if err != nil {
		return model.DeliveryReceipt{}, fmt.Errorf("get delivery receipt: %w", err)
	}
	receipt.DeliveredAt = fromMillis(deliveredAt)
	return receipt, nil
}

func (s *Store) UpsertTaskIndex(ctx context.Context, task model.TaskIndex) error {
	if task.UpdatedAt.IsZero() {
		task.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO task_index (
		task_id, context_id, local_agent_id, remote_agent_id, state, cursor, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(task_id) DO UPDATE SET
		context_id = excluded.context_id,
		local_agent_id = excluded.local_agent_id,
		remote_agent_id = excluded.remote_agent_id,
		state = excluded.state,
		cursor = excluded.cursor,
		updated_at = excluded.updated_at`, task.TaskID, task.ContextID, task.LocalAgentID,
		task.RemoteAgentID, task.State, task.Cursor, millis(task.UpdatedAt))
	if err != nil {
		return fmt.Errorf("upsert task index: %w", err)
	}
	return nil
}

func (s *Store) GetTaskIndex(ctx context.Context, taskID string) (model.TaskIndex, error) {
	return scanTaskIndex(s.db.QueryRowContext(ctx, `SELECT task_id, context_id, local_agent_id,
		remote_agent_id, state, cursor, updated_at FROM task_index WHERE task_id = ?`, taskID))
}

func (s *Store) ListTaskIndexesByContext(
	ctx context.Context,
	localAgentID string,
	contextID string,
) ([]model.TaskIndex, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT task_id, context_id, local_agent_id,
		remote_agent_id, state, cursor, updated_at FROM task_index
		WHERE local_agent_id = ? AND context_id = ? ORDER BY updated_at, task_id`, localAgentID, contextID)
	if err != nil {
		return nil, fmt.Errorf("list task indexes by context: %w", err)
	}
	defer rows.Close()
	var tasks []model.TaskIndex
	for rows.Next() {
		task, err := scanTaskIndex(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

func scanTaskIndex(scanner rowScanner) (model.TaskIndex, error) {
	var task model.TaskIndex
	var updatedAt int64
	if err := scanner.Scan(&task.TaskID, &task.ContextID, &task.LocalAgentID,
		&task.RemoteAgentID, &task.State, &task.Cursor, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.TaskIndex{}, ErrNotFound
		}
		return model.TaskIndex{}, fmt.Errorf("scan task index: %w", err)
	}
	task.UpdatedAt = fromMillis(updatedAt)
	return task, nil
}

func (s *Store) RecordInboxMessage(ctx context.Context, message model.InboxMessage) error {
	if message.TargetAgentID == "" || message.SourceAgentID == "" || message.MessageID == "" || message.ContextID == "" {
		return errors.New("inbox message identity fields are required")
	}
	if message.State == "" {
		message.State = "unread"
	}
	if message.ReceivedAt.IsZero() {
		message.ReceivedAt = time.Now().UTC()
	}
	body := []byte(message.Body)
	if s.aead != nil {
		var err error
		body, err = s.aead.Encrypt(ctx, body, inboxAssociatedData(message))
		if err != nil {
			return fmt.Errorf("encrypt inbox message: %w", err)
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO inbox_messages(
		target_agent_id, source_agent_id, message_id, context_id, body, state, received_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, message.TargetAgentID, message.SourceAgentID, message.MessageID,
		message.ContextID, body, message.State, millis(message.ReceivedAt))
	if err != nil {
		return fmt.Errorf("record inbox message: %w", err)
	}
	return nil
}

func (s *Store) ListInboxMessages(ctx context.Context, targetAgentID, contextID string, unreadOnly bool, limit int) ([]model.InboxMessage, error) {
	if targetAgentID == "" {
		return nil, errors.New("target agent id is required")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	query := `SELECT target_agent_id, source_agent_id, message_id, context_id, body, state, received_at
		FROM inbox_messages WHERE target_agent_id = ?`
	args := []any{targetAgentID}
	if unreadOnly {
		query += ` AND state = 'unread'`
	}
	if contextID != "" {
		query += ` AND context_id = ?`
		args = append(args, contextID)
	}
	query += ` ORDER BY received_at DESC, message_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list inbox messages: %w", err)
	}
	defer rows.Close()
	var messages []model.InboxMessage
	for rows.Next() {
		var message model.InboxMessage
		var body []byte
		var receivedAt int64
		if err := rows.Scan(&message.TargetAgentID, &message.SourceAgentID, &message.MessageID,
			&message.ContextID, &body, &message.State, &receivedAt); err != nil {
			return nil, fmt.Errorf("scan inbox message: %w", err)
		}
		if s.aead != nil {
			body, err = s.aead.Decrypt(ctx, body, inboxAssociatedData(message))
			if err != nil {
				return nil, fmt.Errorf("decrypt inbox message: %w", err)
			}
		}
		message.Body = string(body)
		message.ReceivedAt = fromMillis(receivedAt)
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate inbox messages: %w", err)
	}
	return messages, nil
}

func (s *Store) MarkInboxMessageRead(ctx context.Context, targetAgentID, sourceAgentID, messageID string) error {
	if targetAgentID == "" || sourceAgentID == "" || messageID == "" {
		return errors.New("inbox message identity fields are required")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE inbox_messages SET state = 'read', read_at = ?
		WHERE target_agent_id = ? AND source_agent_id = ? AND message_id = ?`, millis(time.Now().UTC()), targetAgentID, sourceAgentID, messageID)
	if err != nil {
		return fmt.Errorf("mark inbox message read: %w", err)
	}
	return requireOneRow(result, "mark inbox message read")
}

func inboxAssociatedData(message model.InboxMessage) []byte {
	return []byte("snw-agent-link:inbox:" + message.TargetAgentID + ":" + message.SourceAgentID + ":" + message.MessageID)
}

func (s *Store) AppendAuditEntry(ctx context.Context, entry model.AuditEntry) error {
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_entries (
		id, actor_agent_id, remote_agent_id, action, outcome, request_id, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, entry.ID, entry.ActorAgentID, entry.RemoteAgentID,
		entry.Action, entry.Outcome, entry.RequestID, millis(entry.CreatedAt))
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

func (s *Store) ListAuditEntries(
	ctx context.Context,
	actorAgentID string,
	remoteAgentID string,
	limit int,
) ([]model.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, actor_agent_id, remote_agent_id,
		action, outcome, request_id, created_at FROM audit_entries
		WHERE (? = '' OR actor_agent_id = ?) AND (? = '' OR remote_agent_id = ?)
		ORDER BY created_at DESC, id DESC LIMIT ?`, actorAgentID, actorAgentID,
		remoteAgentID, remoteAgentID, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer rows.Close()
	var entries []model.AuditEntry
	for rows.Next() {
		var entry model.AuditEntry
		var createdAt int64
		if err := rows.Scan(&entry.ID, &entry.ActorAgentID, &entry.RemoteAgentID,
			&entry.Action, &entry.Outcome, &entry.RequestID, &createdAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		entry.CreatedAt = fromMillis(createdAt)
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *Store) ClaimReplayNonce(
	ctx context.Context,
	localAgentID string,
	remoteAgentID string,
	nonce string,
	expiresAt time.Time,
	now time.Time,
) (bool, error) {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin replay nonce claim: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `DELETE FROM replay_nonces
		WHERE local_agent_id = ? AND remote_agent_id = ? AND nonce = ? AND expires_at <= ?`,
		localAgentID, remoteAgentID, nonce, millis(now)); err != nil {
		return false, fmt.Errorf("delete expired replay nonce: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `INSERT OR IGNORE INTO replay_nonces (
		local_agent_id, remote_agent_id, nonce, expires_at, created_at
	) VALUES (?, ?, ?, ?, ?)`, localAgentID, remoteAgentID, nonce, millis(expiresAt), millis(now))
	if err != nil {
		return false, fmt.Errorf("claim replay nonce: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read replay nonce claim result: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return false, fmt.Errorf("commit replay nonce claim: %w", err)
	}
	return rowsAffected == 1, nil
}

func (s *Store) CreateAttachmentGrant(ctx context.Context, grant model.AttachmentGrant) error {
	if grant.GrantID == "" || grant.BlobID == "" || grant.OwnerAgentID == "" || grant.TargetAgentID == "" ||
		grant.ContextID == "" || grant.Digest == "" || grant.Size < 0 || grant.ExpiresAt.IsZero() {
		return ErrGrantDenied
	}
	now := time.Now().UTC()
	if grant.CreatedAt.IsZero() {
		grant.CreatedAt = now
	}
	grant.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO attachment_grants (
		grant_id, blob_id, owner_agent_id, target_agent_id, context_id, digest,
		size, expires_at, revoked_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`, grant.GrantID, grant.BlobID,
		grant.OwnerAgentID, grant.TargetAgentID, grant.ContextID, grant.Digest, grant.Size,
		millis(grant.ExpiresAt), millis(grant.CreatedAt), millis(grant.UpdatedAt))
	if err != nil {
		return fmt.Errorf("create attachment grant: %w", err)
	}
	return nil
}

func (s *Store) GetAttachmentGrant(ctx context.Context, grantID string) (model.AttachmentGrant, error) {
	var grant model.AttachmentGrant
	var expiresAt, createdAt, updatedAt int64
	var revokedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT grant_id, blob_id, owner_agent_id, target_agent_id,
		context_id, digest, size, expires_at, revoked_at, created_at, updated_at
		FROM attachment_grants WHERE grant_id = ?`, grantID).Scan(&grant.GrantID, &grant.BlobID,
		&grant.OwnerAgentID, &grant.TargetAgentID, &grant.ContextID, &grant.Digest, &grant.Size,
		&expiresAt, &revokedAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AttachmentGrant{}, ErrNotFound
	}
	if err != nil {
		return model.AttachmentGrant{}, fmt.Errorf("get attachment grant: %w", err)
	}
	grant.ExpiresAt = fromMillis(expiresAt)
	grant.CreatedAt = fromMillis(createdAt)
	grant.UpdatedAt = fromMillis(updatedAt)
	if revokedAt.Valid {
		value := fromMillis(revokedAt.Int64)
		grant.RevokedAt = &value
	}
	return grant, nil
}

func (s *Store) AuthorizeAttachmentGrant(
	ctx context.Context,
	grantID, blobID, ownerAgentID, targetAgentID, contextID, digest string,
	now time.Time,
) (model.AttachmentGrant, error) {
	grant, err := s.GetAttachmentGrant(ctx, grantID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return model.AttachmentGrant{}, ErrGrantDenied
		}
		return model.AttachmentGrant{}, err
	}
	if grant.BlobID != blobID || grant.OwnerAgentID != ownerAgentID || grant.TargetAgentID != targetAgentID ||
		grant.ContextID != contextID || grant.Digest != digest {
		return model.AttachmentGrant{}, ErrGrantDenied
	}
	if grant.RevokedAt != nil {
		return model.AttachmentGrant{}, ErrGrantRevoked
	}
	if !now.Before(grant.ExpiresAt) {
		return model.AttachmentGrant{}, ErrGrantExpired
	}
	return grant, nil
}

func (s *Store) RevokeAttachmentGrant(ctx context.Context, grantID string, revokedAt time.Time) error {
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE attachment_grants
		SET revoked_at = COALESCE(revoked_at, ?), updated_at = ? WHERE grant_id = ?`,
		millis(revokedAt), millis(revokedAt), grantID)
	if err != nil {
		return fmt.Errorf("revoke attachment grant: %w", err)
	}
	return requireOneRow(result, "revoke attachment grant")
}

func (s *Store) RevokeAttachmentGrantsForContact(ctx context.Context, ownerAgentID, targetAgentID string, revokedAt time.Time) (int64, error) {
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE attachment_grants SET revoked_at = ?, updated_at = ?
		WHERE owner_agent_id = ? AND target_agent_id = ? AND revoked_at IS NULL`,
		millis(revokedAt), millis(revokedAt), ownerAgentID, targetAgentID)
	if err != nil {
		return 0, fmt.Errorf("revoke contact attachment grants: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke contact attachment grants rows: %w", err)
	}
	return rows, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanOutbox(scanner rowScanner) (model.OutboxMessage, error) {
	var message model.OutboxMessage
	var nextAttemptAt, createdAt, updatedAt int64
	if err := scanner.Scan(&message.MessageID, &message.IdempotencyKey, &message.SourceAgentID,
		&message.TargetAgentID, &message.ContextID, &message.Payload, &message.State, &message.AttemptCount,
		&nextAttemptAt, &createdAt, &updatedAt); err != nil {
		return model.OutboxMessage{}, fmt.Errorf("scan outbox: %w", err)
	}
	message.NextAttemptAt = fromMillis(nextAttemptAt)
	message.CreatedAt = fromMillis(createdAt)
	message.UpdatedAt = fromMillis(updatedAt)
	return message, nil
}

func (s *Store) restoreOutbox(ctx context.Context, message model.OutboxMessage) (model.OutboxMessage, error) {
	if s.aead == nil {
		return message, nil
	}
	payload, err := s.aead.Decrypt(ctx, message.Payload, outboxAssociatedData(message))
	if err != nil {
		return model.OutboxMessage{}, fmt.Errorf("decrypt outbox payload: %w", err)
	}
	message.Payload = payload
	return message, nil
}

func outboxAssociatedData(message model.OutboxMessage) []byte {
	return []byte("snw-agent-link:outbox:" + message.SourceAgentID + ":" + message.TargetAgentID + ":" + message.MessageID)
}

func requireOneRow(result sql.Result, action string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows: %w", action, err)
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RecordMessageOnce(ctx context.Context, targetAgentID, messageID, taskID string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO deduplication_records (
		target_agent_id, message_id, task_id, created_at
	) VALUES (?, ?, ?, ?)`, targetAgentID, messageID, taskID, millis(time.Now().UTC()))
	if err != nil {
		return false, fmt.Errorf("record deduplication: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("record deduplication rows: %w", err)
	}
	return rows == 1, nil
}

func (s *Store) GetDeduplication(ctx context.Context, targetAgentID, messageID string) (model.DeduplicationRecord, error) {
	var record model.DeduplicationRecord
	var createdAt int64
	err := s.db.QueryRowContext(ctx, `SELECT target_agent_id, message_id, task_id, created_at
		FROM deduplication_records WHERE target_agent_id = ? AND message_id = ?`, targetAgentID, messageID).Scan(
		&record.TargetAgentID, &record.MessageID, &record.TaskID, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DeduplicationRecord{}, ErrNotFound
	}
	if err != nil {
		return model.DeduplicationRecord{}, fmt.Errorf("get deduplication: %w", err)
	}
	record.CreatedAt = fromMillis(createdAt)
	return record, nil
}

func (s *Store) RecordScopedMessageOnce(ctx context.Context, sourceAgentID, targetAgentID string, epoch uint64, messageID, taskID string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO scoped_deduplication_records (
		source_agent_id, target_agent_id, agent_key_epoch, message_id, task_id, created_at
	) VALUES (?, ?, ?, ?, ?, ?)`, sourceAgentID, targetAgentID, epoch, messageID, taskID, millis(time.Now().UTC()))
	if err != nil {
		return false, fmt.Errorf("record scoped deduplication: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("record scoped deduplication rows: %w", err)
	}
	return rows == 1, nil
}

func (s *Store) GetScopedDeduplication(ctx context.Context, sourceAgentID, targetAgentID string, epoch uint64, messageID string) (model.DeduplicationRecord, error) {
	var record model.DeduplicationRecord
	var createdAt int64
	err := s.db.QueryRowContext(ctx, `SELECT source_agent_id, target_agent_id, agent_key_epoch, message_id, task_id, response_status, response_type, response_body, created_at
		FROM scoped_deduplication_records WHERE source_agent_id = ? AND target_agent_id = ? AND agent_key_epoch = ? AND message_id = ?`,
		sourceAgentID, targetAgentID, epoch, messageID).Scan(&record.SourceAgentID, &record.TargetAgentID, &record.AgentKeyEpoch,
		&record.MessageID, &record.TaskID, &record.ResponseStatus, &record.ResponseType, &record.ResponseBody, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DeduplicationRecord{}, ErrNotFound
	}
	if err != nil {
		return model.DeduplicationRecord{}, fmt.Errorf("get scoped deduplication: %w", err)
	}
	if s.aead != nil && len(record.ResponseBody) > 0 {
		body, decryptErr := s.aead.Decrypt(ctx, record.ResponseBody, scopedDedupAssociatedData(sourceAgentID, targetAgentID, epoch, messageID))
		if decryptErr != nil {
			return model.DeduplicationRecord{}, fmt.Errorf("decrypt scoped dedup response: %w", decryptErr)
		}
		record.ResponseBody = body
	}
	record.CreatedAt = fromMillis(createdAt)
	return record, nil
}

// CompleteScopedMessage stores the canonical response for an accepted inbound
// message. It turns a deduplication reservation into a durable replay result.
func (s *Store) CompleteScopedMessage(ctx context.Context, sourceAgentID, targetAgentID string, epoch uint64, messageID, taskID string, status int, contentType string, body []byte) error {
	storedBody := append([]byte(nil), body...)
	if s.aead != nil && len(storedBody) > 0 {
		var encryptErr error
		storedBody, encryptErr = s.aead.Encrypt(ctx, storedBody, scopedDedupAssociatedData(sourceAgentID, targetAgentID, epoch, messageID))
		if encryptErr != nil {
			return fmt.Errorf("encrypt scoped dedup response: %w", encryptErr)
		}
	}
	result, err := s.db.ExecContext(ctx, `UPDATE scoped_deduplication_records
		SET task_id = ?, response_status = ?, response_type = ?, response_body = ?
		WHERE source_agent_id = ? AND target_agent_id = ? AND agent_key_epoch = ? AND message_id = ?`,
		taskID, status, contentType, storedBody, sourceAgentID, targetAgentID, epoch, messageID)
	if err != nil {
		return fmt.Errorf("complete scoped deduplication: %w", err)
	}
	return requireOneRow(result, "complete scoped deduplication")
}

func scopedDedupAssociatedData(sourceAgentID, targetAgentID string, epoch uint64, messageID string) []byte {
	return []byte(fmt.Sprintf("snw-agent-link:dedup:%s:%s:%d:%s", sourceAgentID, targetAgentID, epoch, messageID))
}

func millis(value time.Time) int64 { return value.UTC().UnixMilli() }

func fromMillis(value int64) time.Time { return time.UnixMilli(value).UTC() }
