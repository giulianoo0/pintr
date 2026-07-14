package codex

import (
	"context"
	"encoding/json"
	"time"

	"github.com/giulianoo0/pintr/internal/store"
)

// Account implementations: the local auth file (stdio mode) and per-user
// database rows (hosted mode), plus the glue that persists Auth blobs through
// the store without the store knowing their shape.

// FileAccount adapts the file-based AuthStore (stdio mode) to the Account
// interface. There is exactly one such account.
type FileAccount struct {
	store *AuthStore
}

func NewFileAccount(store *AuthStore) FileAccount { return FileAccount{store: store} }

func (f FileAccount) Fresh(ctx context.Context) (Credentials, error) {
	auth, err := f.store.fresh(ctx)
	if err != nil {
		return Credentials{}, err
	}
	return credentialsOf(auth), nil
}

func (f FileAccount) ForceRefresh(ctx context.Context) (Credentials, error) {
	auth, err := f.store.forceRefresh(ctx)
	if err != nil {
		return Credentials{}, err
	}
	return credentialsOf(auth), nil
}

func (f FileAccount) Label() string    { return "local" }
func (f FileAccount) CacheKey() string { return "local" }

// metaOf extracts the plaintext row metadata the store keeps next to the
// encrypted token blob.
func metaOf(auth *Auth) store.CodexAccountMeta {
	return store.CodexAccountMeta{
		AccountID:   auth.AccountID,
		Email:       auth.Email,
		PlanType:    auth.PlanType,
		Fedramp:     auth.Fedramp,
		LastRefresh: auth.LastRefresh,
	}
}

// UpsertAccount saves a freshly linked ChatGPT account for a user.
func UpsertAccount(ctx context.Context, st *store.Store, userID string, auth *Auth) error {
	tokens, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	return st.UpsertCodexAccount(ctx, userID, metaOf(auth), tokens)
}

// DBAccount adapts one codex_accounts row (HTTP mode) to Account. All reads
// and writes are scoped to (userID, rowID) so users can only ever touch their
// own accounts.
type DBAccount struct {
	store   *store.Store
	userID  string
	rowID   string
	display string
}

func NewDBAccount(st *store.Store, userID, rowID, display string) DBAccount {
	return DBAccount{store: st, userID: userID, rowID: rowID, display: display}
}

func (d DBAccount) load(ctx context.Context) (Auth, error) {
	plaintext, err := d.store.LoadCodexTokens(ctx, d.userID, d.rowID)
	if err != nil {
		return Auth{}, err
	}
	var auth Auth
	if err := json.Unmarshal(plaintext, &auth); err != nil {
		return Auth{}, err
	}
	return auth, nil
}

func (d DBAccount) save(ctx context.Context, auth Auth) error {
	tokens, err := json.Marshal(&auth)
	if err != nil {
		return err
	}
	return d.store.SaveCodexTokens(ctx, d.userID, d.rowID, metaOf(&auth), tokens)
}

func (d DBAccount) Fresh(ctx context.Context) (Credentials, error) {
	auth, err := d.load(ctx)
	if err != nil {
		return Credentials{}, err
	}
	if needsRefresh(&auth, time.Now()) {
		refreshed, err := refreshAuth(ctx, auth)
		if err != nil {
			return Credentials{}, err
		}
		if err := d.save(ctx, refreshed); err != nil {
			return Credentials{}, err
		}
		auth = refreshed
	}
	return credentialsOf(auth), nil
}

func (d DBAccount) ForceRefresh(ctx context.Context) (Credentials, error) {
	auth, err := d.load(ctx)
	if err != nil {
		return Credentials{}, err
	}
	refreshed, err := refreshAuth(ctx, auth)
	if err != nil {
		return Credentials{}, err
	}
	if err := d.save(ctx, refreshed); err != nil {
		return Credentials{}, err
	}
	return credentialsOf(refreshed), nil
}

func (d DBAccount) Label() string {
	if d.display != "" {
		return d.display
	}
	return d.rowID
}

func (d DBAccount) CacheKey() string { return d.userID + ":" + d.rowID }

// UserAccounts returns a user's linked accounts, default first
// (ListCodexAccounts already orders by is_default DESC).
func UserAccounts(ctx context.Context, st *store.Store, userID string) ([]Account, error) {
	rows, err := st.ListCodexAccounts(ctx, userID)
	if err != nil {
		return nil, err
	}
	accounts := make([]Account, 0, len(rows))
	for _, row := range rows {
		accounts = append(accounts, NewDBAccount(st, userID, row.ID, orUnknown(row.Email)))
	}
	return accounts, nil
}
