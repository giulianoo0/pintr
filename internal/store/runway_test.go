package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := New(filepath.Join(t.TempDir(), "test.db"), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testUser(t *testing.T, st *Store, email string) string {
	t.Helper()
	u, err := st.CreateUser(context.Background(), email, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestRunwayAccountRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	userID := testUser(t, st, "a@example.test")

	if _, err := st.GetRunwayAccount(ctx, userID); !errors.Is(err, ErrNoRunwayAccount) {
		t.Fatalf("err = %v, want ErrNoRunwayAccount", err)
	}

	expires := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	account := RunwayAccount{
		RunwayUserID: "58179174", TeamID: 58179174, Username: "someone",
		Email: "someone@example.test", Plan: "unlimited", TokenExpires: expires,
	}
	if err := st.UpsertRunwayAccount(ctx, userID, account, "jwt-token-value"); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetRunwayAccount(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TeamID != 58179174 || got.Username != "someone" || got.Plan != "unlimited" {
		t.Errorf("account = %+v", got)
	}
	if !got.TokenExpires.Equal(expires) {
		t.Errorf("expires = %v, want %v", got.TokenExpires, expires)
	}

	token, _, err := st.LoadRunwayToken(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if token != "jwt-token-value" {
		t.Errorf("token = %q", token)
	}
}

// The token must be encrypted at rest, not merely stored in a BLOB column.
func TestRunwayTokenIsEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	userID := testUser(t, st, "a@example.test")
	if err := st.UpsertRunwayAccount(ctx, userID, RunwayAccount{TeamID: 1}, "super-secret-jwt"); err != nil {
		t.Fatal(err)
	}

	var stored []byte
	if err := st.db.QueryRowContext(ctx, `SELECT token_encrypted FROM runway_accounts WHERE user_id = ?`, userID).
		Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "super-secret-jwt") {
		t.Fatal("the token is stored in the clear")
	}
}

// The ciphertext is AAD-bound to its owner, so a blob lifted into another
// user's row must fail to authenticate rather than decrypt.
func TestRunwayTokenIsBoundToItsUser(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	owner := testUser(t, st, "owner@example.test")
	other := testUser(t, st, "other@example.test")

	if err := st.UpsertRunwayAccount(ctx, owner, RunwayAccount{TeamID: 1}, "owner-token"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRunwayAccount(ctx, other, RunwayAccount{TeamID: 2}, "other-token"); err != nil {
		t.Fatal(err)
	}
	var ownerBlob []byte
	if err := st.db.QueryRowContext(ctx, `SELECT token_encrypted FROM runway_accounts WHERE user_id = ?`, owner).
		Scan(&ownerBlob); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE runway_accounts SET token_encrypted = ? WHERE user_id = ?`,
		ownerBlob, other); err != nil {
		t.Fatal(err)
	}

	if _, _, err := st.LoadRunwayToken(ctx, other); err == nil {
		t.Fatal("a token blob moved between users decrypted successfully")
	}
}

// Reconnecting replaces the token in place rather than creating a second row.
func TestRunwayAccountUpsertReplaces(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	userID := testUser(t, st, "a@example.test")

	if err := st.UpsertRunwayAccount(ctx, userID, RunwayAccount{TeamID: 1, Username: "old"}, "old-token"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRunwayAccount(ctx, userID, RunwayAccount{TeamID: 2, Username: "new"}, "new-token"); err != nil {
		t.Fatal(err)
	}

	var rows int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runway_accounts WHERE user_id = ?`, userID).
		Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("rows = %d, want 1", rows)
	}
	token, account, err := st.LoadRunwayToken(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if token != "new-token" || account.TeamID != 2 || account.Username != "new" {
		t.Errorf("token = %q, account = %+v", token, account)
	}
}

func TestDeleteRunwayAccount(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	userID := testUser(t, st, "a@example.test")
	if err := st.UpsertRunwayAccount(ctx, userID, RunwayAccount{TeamID: 1}, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteRunwayAccount(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetRunwayAccount(ctx, userID); !errors.Is(err, ErrNoRunwayAccount) {
		t.Fatalf("err = %v, want ErrNoRunwayAccount", err)
	}
	// Deleting when nothing is connected is a no-op, not an error.
	if err := st.DeleteRunwayAccount(ctx, userID); err != nil {
		t.Fatal(err)
	}
}

// Deleting the pintr account must take the Runway credential with it.
func TestDeleteUserRemovesRunwayAccount(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	userID := testUser(t, st, "a@example.test")
	if err := st.UpsertRunwayAccount(ctx, userID, RunwayAccount{TeamID: 1}, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(ctx, userID); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runway_accounts WHERE user_id = ?`, userID).
		Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("%d runway row(s) survived account deletion", rows)
	}
}
