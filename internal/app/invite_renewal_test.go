package app

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRedeemInviteExtendsFromCurrentUserExpiry(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := store.CreateUser("admin-renew", "password123")
	user, _ := store.CreateUser("user-renew", "password123")
	_, codes, err := store.CreateInvites("续期", admin.ID, 2, 1, 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RedeemInvite(codes[0], user.ID, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	first, _ := store.UserByID(user.ID)
	if _, err = store.RedeemInvite(codes[1], user.ID, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	second, _ := store.UserByID(user.ID)
	want := first.ExpiresAt.AddDate(0, 0, 30)
	if delta := second.ExpiresAt.Sub(want); delta < -time.Second || delta > time.Second {
		t.Fatalf("expiry = %v, want %v", second.ExpiresAt, want)
	}
}
