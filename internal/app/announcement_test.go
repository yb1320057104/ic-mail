package app

import (
	"path/filepath"
	"testing"
)

func TestAnnouncementUnreadIsTrackedPerUser(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.CreateUser("admin", "admin123")
	if err != nil {
		t.Fatal(err)
	}
	userA, err := store.CreateUser("user-a", "password123")
	if err != nil {
		t.Fatal(err)
	}
	userB, err := store.CreateUser("user-b", "password123")
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.CreateAnnouncement("维护通知", "今晚进行系统维护。", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(store.UnreadAnnouncements(userA.ID)); got != 1 {
		t.Fatalf("user A unread = %d, want 1", got)
	}
	if got := len(store.UnreadAnnouncements(userB.ID)); got != 1 {
		t.Fatalf("user B unread = %d, want 1", got)
	}
	if err := store.MarkAnnouncementRead(userA.ID, item.ID); err != nil {
		t.Fatal(err)
	}
	if got := len(store.UnreadAnnouncements(userA.ID)); got != 0 {
		t.Fatalf("user A unread after read = %d, want 0", got)
	}
	if got := len(store.UnreadAnnouncements(userB.ID)); got != 1 {
		t.Fatalf("user B unread after A read = %d, want 1", got)
	}
	if err := store.MarkAnnouncementRead(userA.ID, item.ID); err != nil {
		t.Fatalf("marking read twice should be idempotent: %v", err)
	}
	if got := len(store.Snapshot().AnnouncementReads); got != 1 {
		t.Fatalf("read records = %d, want 1", got)
	}
}

func TestAnnouncementValidation(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAnnouncement("", "内容", "admin"); err == nil {
		t.Fatal("expected empty title error")
	}
	if _, err := store.CreateAnnouncement("标题", "", "admin"); err == nil {
		t.Fatal("expected empty content error")
	}
}
