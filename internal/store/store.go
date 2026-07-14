// Package store is the SQLite-backed data layer for HTTP (multi-user) mode:
// pintr users, browser sessions, personal access keys, and each user's linked
// Codex accounts. Codex tokens are encrypted at rest with a key derived from
// the server secret.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/giulianoo0/pintr/internal/random"
)

// Store owns the database handle and the master secret. Queries are grouped
// by domain: users.go (users, sessions, access keys, oauth sessions) and
// codex.go (linked Codex accounts).
type Store struct {
	db     *sql.DB
	secret []byte // master secret (from PINTR_SECRET), never stored
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  token_epoch   INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,       -- sha256(cookie value), hex
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS access_keys (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash     TEXT NOT NULL UNIQUE,  -- sha256(key), hex
  prefix       TEXT NOT NULL,
  name         TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_keys_user ON access_keys(user_id);
CREATE TABLE IF NOT EXISTS codex_accounts (
  id               TEXT PRIMARY KEY,
  user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id       TEXT NOT NULL,
  email            TEXT NOT NULL DEFAULT '',
  plan_type        TEXT NOT NULL DEFAULT '',
  fedramp          INTEGER NOT NULL DEFAULT 0,
  tokens_encrypted BLOB NOT NULL,
  last_refresh     TEXT,
  is_default       INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE(user_id, account_id)
);
CREATE INDEX IF NOT EXISTS idx_codex_accounts_user ON codex_accounts(user_id);
CREATE TABLE IF NOT EXISTS oauth_sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_sessions_user ON oauth_sessions(user_id);
`

// New opens (creating if needed) the SQLite database at path and runs the
// idempotent migrations.
func New(path string, secret []byte) (*Store, error) {
	if len(secret) < 32 {
		return nil, errors.New("store: server secret must be at least 32 bytes")
	}
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite is a single file; one writer at a time avoids "database is locked".
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrating: %w", err)
	}
	// Idempotent column adds for upgrades (CREATE TABLE IF NOT EXISTS won't alter
	// an existing table).
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN token_epoch INTEGER NOT NULL DEFAULT 1`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("store: migrating: %w", err)
		}
	}
	return &Store{db: db, secret: secret}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// --- key derivation & crypto ---

func (s *Store) derive(label string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// SigningKey derives the HMAC key used to sign OAuth codes and tokens.
func (s *Store) SigningKey() []byte { return s.derive("oauth-signing-v1") }

// tokenAAD binds a ciphertext to the row it belongs to, so a stored token
// blob can't be authenticated after being moved to another user or account.
func tokenAAD(userID, accountID string) []byte {
	return []byte("codex-token|" + userID + "|" + accountID)
}

func (s *Store) encrypt(plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.derive("token-encryption-v1"))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func (s *Store) decrypt(blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.derive("token-encryption-v1"))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("store: ciphertext too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// --- small helpers ---

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum)
}

func newID(prefix string) string {
	raw, _ := random.Token(12)
	return prefix + "_" + raw
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
