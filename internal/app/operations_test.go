package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJSONMigratesToSQLiteAndSQLiteWinsOnRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	original := State{NextID: 7, Users: []User{{ID: "usr_1", Username: "admin", IsAdmin: true, Status: StatusActive, CreatedAt: time.Now()}}}
	data, _ := json.Marshal(original)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Users()) != 1 {
		t.Fatalf("migrated users=%d", len(store.Users()))
	}
	if _, err := os.Stat(filepath.Join(dir, "state.db")); err != nil {
		t.Fatal("sqlite database not created", err)
	}
	if err := os.WriteFile(path, []byte(`{"users":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Users()) != 1 {
		t.Fatalf("restart did not prefer sqlite: %+v", reopened.Users())
	}
}

func TestRecycleBinRestoresOwnedData(t *testing.T) {
	store := newTestStore(t)
	_, _ = store.CreateUser("admin", "admin123")
	user, _ := store.CreateUserByAdmin("member", "member123", time.Time{})
	account, _ := store.AddAccountForOwner(user.ID, "main", "member@example.com", "")
	mailbox, _ := store.AddMailboxForOwner(user.ID, account.ID, "alias", "alias@icloud.com")
	_, _ = store.AddMessage(mailbox.ID, "code", "sender", "123456", time.Now())
	if _, err := store.DeleteUserWithReason(user.ID, "test"); err != nil {
		t.Fatal(err)
	}
	items := store.RecycleBin()
	if len(items) != 1 {
		t.Fatalf("recycle items=%d", len(items))
	}
	restored, err := store.RestoreUserFromRecycleBin(items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if restored.ID != user.ID || len(state.Accounts) != 1 || len(state.Mailboxes) != 1 || len(state.Messages) != 1 || len(state.RecycleBin) != 0 {
		t.Fatalf("restored state=%+v", state)
	}
}

func TestBackupRestoreReturnsPreviousSQLiteState(t *testing.T) {
	store := newTestStore(t)
	_, _ = store.CreateUser("admin", "admin123")
	backup, err := store.CreateBackup("test")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.CreateUserByAdmin("later", "later123", time.Time{})
	if len(store.Users()) != 2 {
		t.Fatal("second user missing")
	}
	if err := store.RestoreBackup(backup.Name); err != nil {
		t.Fatal(err)
	}
	if users := store.Users(); len(users) != 1 || users[0].Username != "admin" {
		t.Fatalf("restored users=%+v", users)
	}
}
