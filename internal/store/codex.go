package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Linked Codex account rows. Token blobs are opaque to this package (the
// codex package marshals them); they are stored encrypted with AES-GCM,
// AAD-bound to the owning user + account so a blob can't be moved between
// rows.

type CodexAccount struct {
	ID          string
	AccountID   string
	Email       string
	PlanType    string
	Fedramp     bool
	IsDefault   bool
	LastRefresh string
}

// CodexAccountMeta is the plaintext metadata stored alongside the encrypted
// token blob.
type CodexAccountMeta struct {
	AccountID   string
	Email       string
	PlanType    string
	Fedramp     bool
	LastRefresh time.Time
}

// UpsertCodexAccount stores/updates a linked Codex account for a user in a
// single atomic statement. The first account a user links becomes the
// default; re-linking an existing account only refreshes its tokens/metadata
// and preserves the default flag.
func (s *Store) UpsertCodexAccount(ctx context.Context, userID string, meta CodexAccountMeta, tokens []byte) error {
	encrypted, err := s.encrypt(tokens, tokenAAD(userID, meta.AccountID))
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
		newID("cdx"), userID, meta.AccountID, meta.Email, meta.PlanType, boolToInt(meta.Fedramp),
		encrypted, meta.LastRefresh.UTC().Format(time.RFC3339), userID, nowUTC(), nowUTC())
	return err
}

func (s *Store) ListCodexAccounts(ctx context.Context, userID string) ([]CodexAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, email, plan_type, fedramp, is_default, COALESCE(last_refresh, '')
		 FROM codex_accounts WHERE user_id = ? ORDER BY is_default DESC, created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := []CodexAccount{}
	for rows.Next() {
		var (
			a       CodexAccount
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

// LoadCodexTokens decrypts and returns the token blob for one account
// (scoped to the user). The account_id is fetched too so it can be used as
// the AES-GCM AAD.
func (s *Store) LoadCodexTokens(ctx context.Context, userID, accountRowID string) ([]byte, error) {
	var (
		accountID string
		encrypted []byte
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT account_id, tokens_encrypted FROM codex_accounts WHERE id = ? AND user_id = ?`,
		accountRowID, userID).Scan(&accountID, &encrypted)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.decrypt(encrypted, tokenAAD(userID, accountID))
	if err != nil {
		return nil, fmt.Errorf("store: decrypting tokens: %w", err)
	}
	return plaintext, nil
}

// SaveCodexTokens re-encrypts a token blob after a refresh (scoped to the user).
func (s *Store) SaveCodexTokens(ctx context.Context, userID, accountRowID string, meta CodexAccountMeta, tokens []byte) error {
	encrypted, err := s.encrypt(tokens, tokenAAD(userID, meta.AccountID))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE codex_accounts SET tokens_encrypted = ?, email = ?, plan_type = ?, fedramp = ?, last_refresh = ?, updated_at = ?
		 WHERE id = ? AND user_id = ?`,
		encrypted, meta.Email, meta.PlanType, boolToInt(meta.Fedramp),
		meta.LastRefresh.UTC().Format(time.RFC3339), nowUTC(), accountRowID, userID)
	return err
}

// DeleteCodexAccount removes an account and, if it was the default, promotes
// the oldest remaining account so the user always has a default.
func (s *Store) DeleteCodexAccount(ctx context.Context, userID, accountRowID string) error {
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

func (s *Store) SetDefaultCodexAccount(ctx context.Context, userID, accountRowID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `UPDATE codex_accounts SET is_default = 0 WHERE user_id = ?`, userID); err != nil {
		return err
	}
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
