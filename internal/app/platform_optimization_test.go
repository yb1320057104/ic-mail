package app

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizedSQLiteStateAndTaskPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("normalized-user", "password123")
	if err != nil {
		t.Fatal(err)
	}
	store.SaveTaskRun(operationTask{ID: "task-1", Kind: "测试", Status: "success", Message: "完成", StartedAt: formatTime(time.Now()), FinishedAt: formatTime(time.Now())})
	db, err := sql.Open("sqlite", store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version string
	if err = db.QueryRow(`SELECT value FROM state_meta WHERE key='schema_version'`).Scan(&version); err != nil || version != "2" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM users WHERE id=?`, user.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("user row=%d err=%v", count, err)
	}
	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.UserByID(user.ID); !ok {
		t.Fatal("normalized user was not reloaded")
	}
	tasks, err := reopened.TaskRuns(10)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("tasks=%#v err=%v", tasks, err)
	}
}

func TestMailRetentionAndPerMailboxLimit(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.AddMailboxForOwner("u", "a", "mail", "limit@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err = store.AddMessage(m.ID, fmt.Sprintf("m%d", i), "sender", "body", time.Now().Add(-time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = store.AddMessage(m.ID, "old", "sender", "body", time.Now().Add(-90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	removed, err := store.PruneMessages(60, 3)
	if err != nil || removed != 3 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if got := len(store.MessagesForMailbox(m.ID)); got != 3 {
		t.Fatalf("messages=%d", got)
	}
}

func TestLegacyPasswordHashUpgradesOnLogin(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := store.CreateUser("legacy-user", "password123")
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("0123456789abcdef")
	key := pbkdf2SHA256([]byte("password123"), salt, 120000, passwordKeyBytes)
	legacy := fmt.Sprintf("%s$120000$%s$%s", legacyPasswordHashVersion, base64.RawURLEncoding.EncodeToString(salt), base64.RawURLEncoding.EncodeToString(key))
	store.mu.Lock()
	for i := range store.state.Users {
		if store.state.Users[i].ID == u.ID {
			store.state.Users[i].PasswordHash = legacy
		}
	}
	_ = store.saveLocked()
	store.mu.Unlock()
	if _, err = store.AuthenticateUser("legacy-user", "password123"); err != nil {
		t.Fatal(err)
	}
	updated, _ := store.UserByID(u.ID)
	if !strings.HasPrefix(updated.PasswordHash, passwordHashVersion+"$") {
		t.Fatal("legacy hash was not upgraded")
	}
}

func TestExpiredMailboxTokenIsRejected(t *testing.T) {
	s := &Server{cfg: Config{}}
	m := Mailbox{APIToken: "secret", APITokenExpiresAt: time.Now().Add(-time.Minute)}
	req := httptest.NewRequest("GET", "/?key=secret", nil)
	if s.authorized(req, m) {
		t.Fatal("expired mailbox token was accepted")
	}
}
