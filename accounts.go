package main

import (
	"context"
	"time"
)

// fileAccount adapts the local file-based authStore (stdio mode) to the
// codexAccount interface. There is exactly one such account.
type fileAccount struct {
	store *authStore
}

func (f fileAccount) fresh(ctx context.Context) (codexAuth, error) {
	auth, err := f.store.fresh(ctx)
	if err != nil {
		return codexAuth{}, err
	}
	return toCodexAuth(auth), nil
}

func (f fileAccount) forceRefresh(ctx context.Context) (codexAuth, error) {
	auth, err := f.store.forceRefresh(ctx)
	if err != nil {
		return codexAuth{}, err
	}
	return toCodexAuth(auth), nil
}

func (f fileAccount) label() string    { return "local" }
func (f fileAccount) cacheKey() string { return "local" }

// dbAccount adapts one codex_accounts row (HTTP mode) to codexAccount. All
// reads and writes are scoped to (userID, rowID) so users can only ever touch
// their own accounts.
type dbAccount struct {
	store   *store
	userID  string
	rowID   string
	display string
}

func (d dbAccount) fresh(ctx context.Context) (codexAuth, error) {
	auth, err := d.store.loadCodexAuth(ctx, d.userID, d.rowID)
	if err != nil {
		return codexAuth{}, err
	}
	if needsRefresh(&auth, time.Now()) {
		refreshed, err := refreshStoredAuth(ctx, auth)
		if err != nil {
			return codexAuth{}, err
		}
		if err := d.store.saveCodexAuth(ctx, d.userID, d.rowID, refreshed); err != nil {
			return codexAuth{}, err
		}
		auth = refreshed
	}
	return toCodexAuth(auth), nil
}

func (d dbAccount) forceRefresh(ctx context.Context) (codexAuth, error) {
	auth, err := d.store.loadCodexAuth(ctx, d.userID, d.rowID)
	if err != nil {
		return codexAuth{}, err
	}
	refreshed, err := refreshStoredAuth(ctx, auth)
	if err != nil {
		return codexAuth{}, err
	}
	if err := d.store.saveCodexAuth(ctx, d.userID, d.rowID, refreshed); err != nil {
		return codexAuth{}, err
	}
	return toCodexAuth(refreshed), nil
}

func (d dbAccount) label() string {
	if d.display != "" {
		return d.display
	}
	return d.rowID
}

func (d dbAccount) cacheKey() string { return d.userID + ":" + d.rowID }

// userCodexAccounts returns a user's linked accounts as codexAccounts, default
// first (listCodexAccounts already orders by is_default DESC).
func userCodexAccounts(ctx context.Context, st *store, userID string) ([]codexAccount, error) {
	rows, err := st.listCodexAccounts(ctx, userID)
	if err != nil {
		return nil, err
	}
	accounts := make([]codexAccount, 0, len(rows))
	for _, row := range rows {
		accounts = append(accounts, dbAccount{
			store:   st,
			userID:  userID,
			rowID:   row.ID,
			display: orUnknown(row.Email),
		})
	}
	return accounts, nil
}
