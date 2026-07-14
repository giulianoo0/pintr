package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Linked Codex account rows. Tokens are stored encrypted (AES-GCM, AAD-bound
// to the owning user + account so a blob can't be moved between rows).

type codexAccountRow struct {
	ID          string
	AccountID   string
	Email       string
	PlanType    string
	Fedramp     bool
	IsDefault   bool
	LastRefresh string
}

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
