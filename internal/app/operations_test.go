package app

import (
	"context"
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

func TestRuntimeMetricsPersistRatesAndLatency(t *testing.T) {
	store := newTestStore(t)
	if err := store.RecordRuntimeMetric("imap", true, 120*time.Millisecond, "正常"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordRuntimeMetric("imap", false, 380*time.Millisecond, "连接失败"); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := reopened.RuntimeMetrics()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Total != 2 || rows[0].Success != 1 || rows[0].Failure != 1 || rows[0].SuccessRate != 50 || rows[0].FailureRate != 50 || rows[0].AverageMS != 250 || rows[0].MaxMS != 380 || rows[0].LastOK {
		t.Fatalf("metric=%+v", rows)
	}
}

func TestStartPlusAliasCreateJobRunsInBackground(t *testing.T) {
	store := newTestStore(t)
	owner := "owner-alias-job"
	parent, err := store.AddMailboxForOwner(owner, "acc-job", "主邮箱", "hake_tellers6w@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	job, err := server.startPlusAliasCreateJob(owner, "acc-job", []Mailbox{parent}, 2, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if job.Target != 2 {
		t.Fatalf("target=%d", job.Target)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		server.aliasJobMu.Lock()
		status, created := job.Status, job.Created
		server.aliasJobMu.Unlock()
		if status == "success" && created == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	server.aliasJobMu.Lock()
	defer server.aliasJobMu.Unlock()
	if job.Status != "success" || job.Created != 2 {
		t.Fatalf("job=%+v", job)
	}
}

func TestCreatePlusAliasMailboxesSkipsParentsAlreadyAtTarget(t *testing.T) {
	store := newTestStore(t)
	owner := "owner-skip-alias"
	parent, err := store.AddMailboxForOwner(owner, "acc-skip", "主邮箱", "hake_tellers6w@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddPlusAliasMailbox(owner, parent.ID, "hake_tellers6w+awds@icloud.com", "已有别名", ""); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	created, _, _, err := server.createPlusAliasMailboxes(context.Background(), owner, []Mailbox{parent}, 1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 0 {
		t.Fatalf("expected skip, created=%d", len(created))
	}
	if store.MailboxCountForAccount(owner, "acc-skip") != 1 {
		t.Fatalf("privacy mailbox count should ignore aliases, got %d", store.MailboxCountForAccount(owner, "acc-skip"))
	}
}
