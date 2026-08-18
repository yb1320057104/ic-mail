package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminIMAPMessageSearchUsesPersistentTrigramIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	account, err := store.AddAccountForOwner("owner-a", "主账号", "apple@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner("owner-a", account.ID, "测试邮箱", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	message, created, err := store.UpsertMessageContent(mailbox.ID, "imap:101", "imap", "Your temporary code", "sender@example.com", "Authentication code ZX9-72Q", "<b>ZX9-72Q</b>", time.Now())
	if err != nil || !created {
		t.Fatalf("create message: created=%v err=%v", created, err)
	}
	eligible := map[string]struct{}{mailbox.ID: {}}
	result, err := store.AdminSearchIMAPMessages(context.Background(), AdminMessageSearchQuery{Keyword: "ZX9-72Q", Page: 1, PageSize: 20}, eligible)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Rows[0].Message.ID != message.ID {
		t.Fatalf("unexpected search result: %+v", result)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err = reopened.AdminSearchIMAPMessages(context.Background(), AdminMessageSearchQuery{Keyword: "72Q", Page: 1, PageSize: 20}, eligible)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Rows[0].Message.ID != message.ID {
		t.Fatalf("persistent index result: %+v", result)
	}
}

func TestAdminIMAPMessageSearchSupportsTwoCharacterContains(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("owner-short", "account-short", "短词", "short@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertMessage(mailbox.ID, "imap:202", "imap", "登录验证", "安全中心", "验证码 654321", time.Now()); err != nil {
		t.Fatal(err)
	}
	result, err := store.AdminSearchIMAPMessages(context.Background(), AdminMessageSearchQuery{Keyword: "验证", Page: 1, PageSize: 10}, map[string]struct{}{mailbox.ID: {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("short keyword result: %+v", result)
	}
}

func TestAdminIMAPMessageSearchSupportsCJKPhrase(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("owner-cjk", "account-cjk", "多语言", "cjk@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertMessage(mailbox.ID, "imap:203", "imap", "临时身份验证码", "安全中心", "请使用验证码 778899 完成登录", time.Now()); err != nil {
		t.Fatal(err)
	}
	result, err := store.AdminSearchIMAPMessages(context.Background(), AdminMessageSearchQuery{Keyword: "身份验证", Page: 1, PageSize: 10}, map[string]struct{}{mailbox.ID: {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("CJK phrase result: %+v", result)
	}
}

func TestMailboxOwnerNameParticipatesInAdminFuzzySearch(t *testing.T) {
	mailbox := Mailbox{ID: "mailbox-a", OwnerID: "owner-a", MailboxType: "alias", Status: StatusAvailable}
	got := filterMailboxesForListWithOwners([]Mailbox{mailbox}, nil, map[string]string{"owner-a": "Alice Team"}, url.Values{"mailbox_type": {"alias"}, "search": {"alice"}})
	if len(got) != 1 || got[0].ID != mailbox.ID {
		t.Fatalf("owner search result: %+v", got)
	}
}

func TestAdminIMAPMessageEndpointRequiresAdminAndHealthySession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{ConfigPath: "test", RegistrationEnabled: true}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "secret1")
	userCookie, user := registerTestUser(t, handler, "reader", "secret1")
	account, err := store.AddAccountForOwner(user.ID, "Reader Apple", "reader@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, account.ID, "Reader Mailbox", "reader-alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, testIMAPSession(user.ID, account.ID, "reader@example.com")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertMessage(mailbox.ID, "imap:303", "imap", "Security notice", "sender@example.com", "code A1B-2C3", time.Now()); err != nil {
		t.Fatal(err)
	}

	userRecorder := httptest.NewRecorder()
	userRequest := httptest.NewRequest(http.MethodGet, "/api/admin/imap-messages?q=A1B-2C3", nil)
	userRequest.AddCookie(userCookie)
	handler.ServeHTTP(userRecorder, userRequest)
	if userRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary user status=%d body=%s", userRecorder.Code, userRecorder.Body.String())
	}

	adminRecorder := httptest.NewRecorder()
	adminRequest := httptest.NewRequest(http.MethodGet, "/api/admin/imap-messages?q=A1B-2C3", nil)
	adminRequest.AddCookie(adminCookie)
	handler.ServeHTTP(adminRecorder, adminRequest)
	if adminRecorder.Code != http.StatusOK || !strings.Contains(adminRecorder.Body.String(), "reader-alias@icloud.com") {
		t.Fatalf("admin status=%d body=%s", adminRecorder.Code, adminRecorder.Body.String())
	}
}
