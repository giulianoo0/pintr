package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// The user's connected Runway account. Runway has no OAuth for the endpoints
// pintr uses, so the credential is the browser session's bearer token, pasted
// by the user. It is stored encrypted with AES-GCM, AAD-bound to the owning
// user, exactly like Codex tokens — and, like them, is only ever decrypted to
// make a call, never returned to a page.
//
// One Runway account per pintr user: unlike Codex accounts there is no
// failover story here, so a second row would only be ambiguity.

// RunwayAccount is the plaintext metadata for a connected account.
type RunwayAccount struct {
	ID           string
	RunwayUserID string
	TeamID       int64
	Username     string
	Email        string
	Plan         string
	TokenExpires time.Time // zero when unknown
	CreatedAt    string
	UpdatedAt    string
}

// ErrNoRunwayAccount means the user has not connected Runway yet.
var ErrNoRunwayAccount = errors.New("no runway account connected")

// UpsertRunwayAccount stores (or replaces) the user's Runway credential.
func (s *Store) UpsertRunwayAccount(ctx context.Context, userID string, account RunwayAccount, token string) error {
	encrypted, err := s.encrypt([]byte(token), runwayTokenAAD(userID))
	if err != nil {
		return err
	}
	expires := ""
	if !account.TokenExpires.IsZero() {
		expires = account.TokenExpires.UTC().Format(time.RFC3339)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO runway_accounts
		 (id, user_id, runway_user_id, team_id, username, email, plan, token_encrypted, token_expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET
		   runway_user_id = excluded.runway_user_id, team_id = excluded.team_id,
		   username = excluded.username, email = excluded.email, plan = excluded.plan,
		   token_encrypted = excluded.token_encrypted, token_expires_at = excluded.token_expires_at,
		   updated_at = excluded.updated_at`,
		newID("rwy"), userID, account.RunwayUserID, account.TeamID, account.Username, account.Email,
		account.Plan, encrypted, expires, nowUTC(), nowUTC())
	return err
}

// GetRunwayAccount returns the connected account's metadata, without the
// token. It returns ErrNoRunwayAccount when nothing is connected.
func (s *Store) GetRunwayAccount(ctx context.Context, userID string) (RunwayAccount, error) {
	var (
		account RunwayAccount
		expires string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, runway_user_id, team_id, username, email, plan, COALESCE(token_expires_at, ''), created_at, updated_at
		 FROM runway_accounts WHERE user_id = ?`, userID).
		Scan(&account.ID, &account.RunwayUserID, &account.TeamID, &account.Username, &account.Email,
			&account.Plan, &expires, &account.CreatedAt, &account.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RunwayAccount{}, ErrNoRunwayAccount
	}
	if err != nil {
		return RunwayAccount{}, err
	}
	if expires != "" {
		if parsed, perr := time.Parse(time.RFC3339, expires); perr == nil {
			account.TokenExpires = parsed
		}
	}
	return account, nil
}

// LoadRunwayToken decrypts the user's Runway token for an outgoing API call.
func (s *Store) LoadRunwayToken(ctx context.Context, userID string) (string, RunwayAccount, error) {
	account, err := s.GetRunwayAccount(ctx, userID)
	if err != nil {
		return "", RunwayAccount{}, err
	}
	var encrypted []byte
	if err := s.db.QueryRowContext(ctx,
		`SELECT token_encrypted FROM runway_accounts WHERE user_id = ?`, userID).Scan(&encrypted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", RunwayAccount{}, ErrNoRunwayAccount
		}
		return "", RunwayAccount{}, err
	}
	plaintext, err := s.decrypt(encrypted, runwayTokenAAD(userID))
	if err != nil {
		return "", RunwayAccount{}, fmt.Errorf("store: decrypting runway token: %w", err)
	}
	return string(plaintext), account, nil
}

// DeleteRunwayAccount disconnects Runway for a user.
func (s *Store) DeleteRunwayAccount(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM runway_accounts WHERE user_id = ?`, userID)
	return err
}
