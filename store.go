package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

// store is the SQLite-backed data layer for HTTP (multi-user) mode: pintr
// users, browser sessions, personal access keys, and each user's linked Codex
// accounts. Codex tokens are encrypted at rest with a key derived from the
// server secret.
type store struct {
	db     *sql.DB
	secret []byte // master secret (from PINTR_SECRET), never stored
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
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
`

func openStore(path string, secret []byte) (*store, error) {
	if len(secret) == 0 {
		return nil, errors.New("server secret is required")
	}
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite is a single file; one writer at a time avoids "database is locked".
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating: %w", err)
	}
	return &store{db: db, secret: secret}, nil
}

func (s *store) close() error { return s.db.Close() }

// --- key derivation & crypto ---

func (s *store) derive(label string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

func (s *store) signingKey() []byte { return s.derive("oauth-signing-v1") }

func (s *store) encrypt(plaintext []byte) ([]byte, error) {
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
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *store) decrypt(blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.derive("token-encryption-v1"))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// --- password hashing (argon2id) ---

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("argon2id$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- models ---

type user struct {
	ID    string
	Email string
}

type codexAccountRow struct {
	ID          string
	AccountID   string
	Email       string
	PlanType    string
	Fedramp     bool
	IsDefault   bool
	LastRefresh string
}

type accessKeyRow struct {
	ID         string
	Prefix     string
	Name       string
	CreatedAt  string
	LastUsedAt sql.NullString
}

// --- users ---

func (s *store) createUser(ctx context.Context, email, password string) (user, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") {
		return user{}, errors.New("enter a valid email")
	}
	if len(password) < 8 {
		return user{}, errors.New("password must be at least 8 characters")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return user{}, err
	}
	id := newID("usr")
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, email, hash, nowUTC())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return user{}, errors.New("an account with that email already exists")
		}
		return user{}, err
	}
	return user{ID: id, Email: email}, nil
}

func (s *store) authenticateUser(ctx context.Context, email, password string) (user, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var id, hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE email = ?`, email).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		// Hash anyway to keep timing uniform between unknown-email and wrong-password.
		_, _ = hashPassword(password)
		return user{}, errors.New("wrong email or password")
	}
	if err != nil {
		return user{}, err
	}
	if !verifyPassword(password, hash) {
		return user{}, errors.New("wrong email or password")
	}
	return user{ID: id, Email: email}, nil
}

// --- sessions ---

// createSession returns the raw cookie value; only its hash is stored.
func (s *store) createSession(ctx context.Context, userID string, ttl time.Duration) (cookie, csrf string, err error) {
	cookie, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomToken(16)
	if err != nil {
		return "", "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hashToken(cookie), userID, csrf, nowUTC(), time.Now().UTC().Add(ttl).Format(time.RFC3339))
	if err != nil {
		return "", "", err
	}
	return cookie, csrf, nil
}

type sessionInfo struct {
	User user
	CSRF string
}

func (s *store) lookupSession(ctx context.Context, cookie string) (sessionInfo, bool) {
	if cookie == "" {
		return sessionInfo{}, false
	}
	var (
		userID, email, csrf, expiresAt string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT s.user_id, u.email, s.csrf, s.expires_at
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.id = ?`, hashToken(cookie)).Scan(&userID, &email, &csrf, &expiresAt)
	if err != nil {
		return sessionInfo{}, false
	}
	if expiry, err := time.Parse(time.RFC3339, expiresAt); err != nil || time.Now().After(expiry) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, hashToken(cookie))
		return sessionInfo{}, false
	}
	return sessionInfo{User: user{ID: userID, Email: email}, CSRF: csrf}, true
}

func (s *store) deleteSession(ctx context.Context, cookie string) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, hashToken(cookie))
}

// --- access keys ---

// createAccessKey returns the raw key once; only its hash is stored.
func (s *store) createAccessKey(ctx context.Context, userID, name string) (string, error) {
	raw, err := randomToken(24)
	if err != nil {
		return "", err
	}
	key := "pintr_" + raw
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO access_keys (id, user_id, key_hash, prefix, name, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		newID("key"), userID, hashToken(key), key[:12], strings.TrimSpace(name), nowUTC())
	if err != nil {
		return "", err
	}
	return key, nil
}

func (s *store) userForAccessKey(ctx context.Context, key string) (user, bool) {
	if !strings.HasPrefix(key, "pintr_") {
		return user{}, false
	}
	var userID, email string
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.email FROM access_keys k JOIN users u ON u.id = k.user_id WHERE k.key_hash = ?`,
		hashToken(key)).Scan(&userID, &email)
	if err != nil {
		return user{}, false
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE access_keys SET last_used_at = ? WHERE key_hash = ?`, nowUTC(), hashToken(key))
	return user{ID: userID, Email: email}, true
}

func (s *store) listAccessKeys(ctx context.Context, userID string) ([]accessKeyRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, prefix, name, created_at, last_used_at FROM access_keys WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []accessKeyRow{}
	for rows.Next() {
		var k accessKeyRow
		if err := rows.Scan(&k.ID, &k.Prefix, &k.Name, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *store) deleteAccessKey(ctx context.Context, userID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_keys WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// --- codex accounts ---

// upsertCodexAccount stores/updates a linked Codex account for a user.
func (s *store) upsertCodexAccount(ctx context.Context, userID string, auth *storedAuth) error {
	tokens, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	encrypted, err := s.encrypt(tokens)
	if err != nil {
		return err
	}

	var existingID string
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM codex_accounts WHERE user_id = ? AND account_id = ?`, userID, auth.AccountID).Scan(&existingID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		var count int
		_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM codex_accounts WHERE user_id = ?`, userID).Scan(&count)
		isDefault := 0
		if count == 0 {
			isDefault = 1 // first linked account becomes the default
		}
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO codex_accounts
			 (id, user_id, account_id, email, plan_type, fedramp, tokens_encrypted, last_refresh, is_default, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			newID("cdx"), userID, auth.AccountID, auth.Email, auth.PlanType, boolToInt(auth.Fedramp),
			encrypted, auth.LastRefresh.UTC().Format(time.RFC3339), isDefault, nowUTC(), nowUTC())
		return err
	case err != nil:
		return err
	default:
		_, err = s.db.ExecContext(ctx,
			`UPDATE codex_accounts SET email = ?, plan_type = ?, fedramp = ?, tokens_encrypted = ?, last_refresh = ?, updated_at = ?
			 WHERE id = ?`,
			auth.Email, auth.PlanType, boolToInt(auth.Fedramp), encrypted,
			auth.LastRefresh.UTC().Format(time.RFC3339), nowUTC(), existingID)
		return err
	}
}

func (s *store) listCodexAccounts(ctx context.Context, userID string) ([]codexAccountRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, email, plan_type, fedramp, is_default, COALESCE(last_refresh, '')
		 FROM codex_accounts WHERE user_id = ? ORDER BY is_default DESC, created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := []codexAccountRow{}
	for rows.Next() {
		var (
			a       codexAccountRow
			fedramp int
			def     int
		)
		if err := rows.Scan(&a.ID, &a.AccountID, &a.Email, &a.PlanType, &fedramp, &def, &a.LastRefresh); err != nil {
			return nil, err
		}
		a.Fedramp = fedramp == 1
		a.IsDefault = def == 1
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

// loadCodexAuth decrypts the tokens for one account (scoped to the user).
func (s *store) loadCodexAuth(ctx context.Context, userID, accountRowID string) (storedAuth, error) {
	var encrypted []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT tokens_encrypted FROM codex_accounts WHERE id = ? AND user_id = ?`, accountRowID, userID).Scan(&encrypted)
	if err != nil {
		return storedAuth{}, err
	}
	plaintext, err := s.decrypt(encrypted)
	if err != nil {
		return storedAuth{}, fmt.Errorf("decrypting tokens: %w", err)
	}
	var auth storedAuth
	if err := json.Unmarshal(plaintext, &auth); err != nil {
		return storedAuth{}, err
	}
	return auth, nil
}

// saveCodexAuth re-encrypts tokens after a refresh (scoped to the user).
func (s *store) saveCodexAuth(ctx context.Context, userID, accountRowID string, auth storedAuth) error {
	tokens, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	encrypted, err := s.encrypt(tokens)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE codex_accounts SET tokens_encrypted = ?, email = ?, plan_type = ?, fedramp = ?, last_refresh = ?, updated_at = ?
		 WHERE id = ? AND user_id = ?`,
		encrypted, auth.Email, auth.PlanType, boolToInt(auth.Fedramp),
		auth.LastRefresh.UTC().Format(time.RFC3339), nowUTC(), accountRowID, userID)
	return err
}

func (s *store) deleteCodexAccount(ctx context.Context, userID, accountRowID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM codex_accounts WHERE id = ? AND user_id = ?`, accountRowID, userID)
	return err
}

func (s *store) setDefaultCodexAccount(ctx context.Context, userID, accountRowID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `UPDATE codex_accounts SET is_default = 0 WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
	_ = res
	result, err := tx.ExecContext(ctx,
		`UPDATE codex_accounts SET is_default = 1 WHERE id = ? AND user_id = ?`, accountRowID, userID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return errors.New("account not found")
	}
	return tx.Commit()
}

// --- small helpers ---

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum)
}

func newID(prefix string) string {
	raw, _ := randomToken(12)
	return prefix + "_" + raw
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
