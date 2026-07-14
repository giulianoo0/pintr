package store

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/giulianoo0/pintr/internal/random"
)

// User, browser-session, access-key, and OAuth-session queries.

type User struct {
	ID    string
	Email string
}

type AccessKey struct {
	ID         string
	Prefix     string
	Name       string
	CreatedAt  string
	LastUsedAt sql.NullString
}

type OAuthSession struct {
	ID        string
	CreatedAt string
}

// --- users ---

func (s *Store) CreateUser(ctx context.Context, email, password string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") {
		return User{}, errors.New("enter a valid email")
	}
	if len(password) < 8 {
		return User{}, errors.New("password must be at least 8 characters")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	id := newID("usr")
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, email, hash, nowUTC())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, errors.New("an account with that email already exists")
		}
		log.Printf("store: create user: %v", err)
		return User{}, errors.New("could not create account")
	}
	return User{ID: id, Email: email}, nil
}

func (s *Store) AuthenticateUser(ctx context.Context, email, password string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var id, hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE email = ?`, email).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		// Hash anyway to keep timing uniform between unknown-email and wrong-password.
		_, _ = hashPassword(password)
		return User{}, errors.New("wrong email or password")
	}
	if err != nil {
		log.Printf("store: authenticate user: %v", err)
		return User{}, errors.New("could not sign in")
	}
	if !verifyPassword(password, hash) {
		return User{}, errors.New("wrong email or password")
	}
	return User{ID: id, Email: email}, nil
}

// TokenEpoch returns the user's current token epoch. Issued OAuth tokens
// embed the epoch at issue time; bumping it (RevokeTokens) invalidates them
// all. It also doubles as an existence check — false means the user is gone.
func (s *Store) TokenEpoch(ctx context.Context, userID string) (int, bool) {
	var epoch int
	err := s.db.QueryRowContext(ctx, `SELECT token_epoch FROM users WHERE id = ?`, userID).Scan(&epoch)
	if err != nil {
		return 0, false
	}
	return epoch, true
}

func (s *Store) RevokeTokens(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET token_epoch = token_epoch + 1 WHERE id = ?`, userID)
	return err
}

// DeleteUser removes the user and everything owned by them. Sessions, access
// keys, and linked codex accounts are removed by the ON DELETE CASCADE
// foreign keys (foreign_keys pragma is on). Stored S3 assets are deleted
// separately.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
}

// --- browser sessions ---

type SessionInfo struct {
	User User
	CSRF string
}

// CreateSession returns the raw cookie value; only its hash is stored.
func (s *Store) CreateSession(ctx context.Context, userID string, ttl time.Duration) (cookie, csrf string, err error) {
	cookie, err = random.Token(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = random.Token(16)
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

func (s *Store) LookupSession(ctx context.Context, cookie string) (SessionInfo, bool) {
	if cookie == "" {
		return SessionInfo{}, false
	}
	var userID, email, csrf, expiresAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT s.user_id, u.email, s.csrf, s.expires_at
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.id = ?`, hashToken(cookie)).Scan(&userID, &email, &csrf, &expiresAt)
	if err != nil {
		return SessionInfo{}, false
	}
	if expiry, err := time.Parse(time.RFC3339, expiresAt); err != nil || time.Now().After(expiry) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, hashToken(cookie))
		return SessionInfo{}, false
	}
	return SessionInfo{User: User{ID: userID, Email: email}, CSRF: csrf}, true
}

func (s *Store) DeleteSession(ctx context.Context, cookie string) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, hashToken(cookie))
}

// --- access keys ---

// CreateAccessKey returns the raw key once; only its hash is stored.
func (s *Store) CreateAccessKey(ctx context.Context, userID, name string) (string, error) {
	raw, err := random.Token(24)
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

func (s *Store) UserForAccessKey(ctx context.Context, key string) (User, bool) {
	if !strings.HasPrefix(key, "pintr_") {
		return User{}, false
	}
	var userID, email string
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.email FROM access_keys k JOIN users u ON u.id = k.user_id WHERE k.key_hash = ?`,
		hashToken(key)).Scan(&userID, &email)
	if err != nil {
		return User{}, false
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE access_keys SET last_used_at = ? WHERE key_hash = ?`, nowUTC(), hashToken(key))
	return User{ID: userID, Email: email}, true
}

func (s *Store) ListAccessKeys(ctx context.Context, userID string) ([]AccessKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, prefix, name, created_at, last_used_at FROM access_keys WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []AccessKey{}
	for rows.Next() {
		var k AccessKey
		if err := rows.Scan(&k.ID, &k.Prefix, &k.Name, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) DeleteAccessKey(ctx context.Context, userID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_keys WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// --- oauth sessions (issued MCP OAuth grants, individually revocable) ---

func (s *Store) CreateOAuthSession(ctx context.Context, userID string) (string, error) {
	sid := newID("oas")
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth_sessions (id, user_id, created_at) VALUES (?, ?, ?)`, sid, userID, nowUTC())
	return sid, err
}

// OAuthSessionValid reports whether an issued OAuth token is still good: its
// session row exists and the user's token epoch still matches (so both a
// per-session revoke and a global "revoke all" invalidate it).
func (s *Store) OAuthSessionValid(ctx context.Context, sid, userID string, epoch int) bool {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM oauth_sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.id = ? AND s.user_id = ? AND u.token_epoch = ?`, sid, userID, epoch).Scan(&one)
	return err == nil
}

func (s *Store) ListOAuthSessions(ctx context.Context, userID string) ([]OAuthSession, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, created_at FROM oauth_sessions WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := []OAuthSession{}
	for rows.Next() {
		var row OAuthSession
		if err := rows.Scan(&row.ID, &row.CreatedAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, row)
	}
	return sessions, rows.Err()
}

func (s *Store) DeleteOAuthSession(ctx context.Context, userID, sid string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_sessions WHERE id = ? AND user_id = ?`, sid, userID)
	return err
}

func (s *Store) DeleteAllOAuthSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_sessions WHERE user_id = ?`, userID)
	return err
}
