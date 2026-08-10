package app

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func TestAdminCreateAndUpdateUserExpiry(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser("admin", "Admin-pass-123"); err != nil {
		t.Fatal(err)
	}
	want := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Second)
	user, err := store.CreateUserByAdmin("member", "Member-pass-123", want)
	if err != nil {
		t.Fatal(err)
	}
	if user.IsAdmin || !user.ExpiresAt.Equal(want) {
		t.Fatalf("created user = %+v", user)
	}
	updated, err := store.UpdateUserExpiry(user.ID, time.Time{})
	if err != nil || !updated.ExpiresAt.IsZero() {
		t.Fatalf("clear expiry user=%+v err=%v", updated, err)
	}
}

func TestInactiveCleanupProtectsAdminAndDeletesOldMember(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := store.CreateUser("admin", "Admin-pass-123")
	member, _ := store.CreateUserByAdmin("old-member", "Member-pass-123", time.Time{})
	store.mu.Lock()
	for i := range store.state.Users {
		store.state.Users[i].CreatedAt = time.Now().Add(-31 * 24 * time.Hour)
		store.state.Users[i].LastLoginAt = time.Time{}
	}
	store.mu.Unlock()
	server := NewServer(Config{}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).(*Server)
	if got := server.cleanupInactiveUsers(time.Now()); got != 1 {
		t.Fatalf("deleted users = %d, want 1", got)
	}
	if _, ok := store.UserByID(admin.ID); !ok {
		t.Fatal("admin was deleted")
	}
	if _, ok := store.UserByID(member.ID); ok {
		t.Fatal("inactive member was not deleted")
	}
}
