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
	"log"
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
`

func openStore(path string, secret []byte) (*store, error) {
	if len(secret) < 32 {
		return nil, errors.New("server secret must be at least 32 bytes")
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
		return nil, fmt.Errorf("migrating: %w", err)
	}
	// Idempotent column adds for upgrades (CREATE TABLE IF NOT EXISTS won't alter
	// an existing table).
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN token_epoch INTEGER NOT NULL DEFAULT 1`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrating: %w", err)
		}
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

// aad binds a ciphertext to the row it belongs to, so a stored token blob
// can't be authenticated after being moved to another user or account.
func tokenAAD(userID, accountID string) []byte {
	return []byte("codex-token|" + userID + "|" + accountID)
}

func (s *store) encrypt(plaintext, aad []byte) ([]byte, error) {
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

func (s *store) decrypt(blob, aad []byte) ([]byte, error) {
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
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// --- password hashing (argon2id) ---

const (
	argonMemory  = 64 * 1024
	argonTime    = 1
	argonThreads = 4
	argonKeyLen  = 32
)

// hashPassword encodes the parameters into the hash (PHC string format) so they
// can be tuned later without locking out existing users.
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=65536,t=1,p=4", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
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
		log.Printf("createUser: %v", err)
		return user{}, errors.New("could not create account")
	}
	return user{ID: id, Email: email}, nil
}

// tokenEpoch returns the user's current token epoch. Issued OAuth tokens embed
// the epoch at issue time; bumping it (revokeTokens) invalidates them all. It
// also doubles as an existence check — false means the user is gone.
func (s *store) tokenEpoch(ctx context.Context, userID string) (int, bool) {
	var epoch int
	err := s.db.QueryRowContext(ctx, `SELECT token_epoch FROM users WHERE id = ?`, userID).Scan(&epoch)
	if err != nil {
		return 0, false
	}
	return epoch, true
}

func (s *store) revokeTokens(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET token_epoch = token_epoch + 1 WHERE id = ?`, userID)
	return err
}

// deleteUser removes the user and everything owned by them. Sessions, access
// keys, and linked codex accounts are removed by the ON DELETE CASCADE foreign
// keys (foreign_keys pragma is on). Stored S3 assets are deleted separately.
func (s *store) deleteUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
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
		log.Printf("authenticateUser: %v", err)
		return user{}, errors.New("could not sign in")
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

// upsertCodexAccount stores/updates a linked Codex account for a user in a
// single atomic statement. The first account a user links becomes the default;
// re-linking an existing account only refreshes its tokens/metadata and
// preserves the default flag.
func (s *store) upsertCodexAccount(ctx context.Context, userID string, auth *storedAuth) error {
	tokens, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	encrypted, err := s.encrypt(tokens, tokenAAD(userID, auth.AccountID))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO codex_accounts
		 (id, user_id, account_id, email, plan_type, fedramp, tokens_encrypted, last_refresh, is_default, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?,
		   CASE WHEN (SELECT COUNT(*) FROM codex_accounts WHERE user_id = ?) = 0 THEN 1 ELSE 0 END,
		   ?, ?)
		 ON CONFLICT(user_id, account_id) DO UPDATE SET
		   email = excluded.email, plan_type = excluded.plan_type, fedramp = excluded.fedramp,
		   tokens_encrypted = excluded.tokens_encrypted, last_refresh = excluded.last_refresh,
		   updated_at = excluded.updated_at`,
		newID("cdx"), userID, auth.AccountID, auth.Email, auth.PlanType, boolToInt(auth.Fedramp),
		encrypted, auth.LastRefresh.UTC().Format(time.RFC3339), userID, nowUTC(), nowUTC())
	return err
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

// loadCodexAuth decrypts the tokens for one account (scoped to the user). The
// account_id is fetched too so it can be used as the AES-GCM AAD.
func (s *store) loadCodexAuth(ctx context.Context, userID, accountRowID string) (storedAuth, error) {
	var (
		accountID string
		encrypted []byte
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT account_id, tokens_encrypted FROM codex_accounts WHERE id = ? AND user_id = ?`,
		accountRowID, userID).Scan(&accountID, &encrypted)
	if err != nil {
		return storedAuth{}, err
	}
	plaintext, err := s.decrypt(encrypted, tokenAAD(userID, accountID))
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
	encrypted, err := s.encrypt(tokens, tokenAAD(userID, auth.AccountID))
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

// deleteCodexAccount removes an account and, if it was the default, promotes the
// oldest remaining account so the user always has a default.
func (s *store) deleteCodexAccount(ctx context.Context, userID, accountRowID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var wasDefault int
	err = tx.QueryRowContext(ctx,
		`SELECT is_default FROM codex_accounts WHERE id = ? AND user_id = ?`, accountRowID, userID).Scan(&wasDefault)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM codex_accounts WHERE id = ? AND user_id = ?`, accountRowID, userID); err != nil {
		return err
	}
	if wasDefault == 1 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE codex_accounts SET is_default = 1
			 WHERE user_id = ? AND id = (SELECT id FROM codex_accounts WHERE user_id = ? ORDER BY created_at LIMIT 1)`,
			userID, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
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
