package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMailboxVisualMessageContentRendersHTMLInSandbox(t *testing.T) {
	got := mailboxVisualMessageContent(Message{
		Body:     "plain fallback",
		HTMLBody: `<html><style>strong{color:red}</style><body><strong>691288</strong><script>alert(1)</script></body></html>`,
	})
	for _, want := range []string{`<iframe`, `sandbox=""`, `srcdoc="`, `&lt;style&gt;`, `&lt;strong&gt;691288&lt;/strong&gt;`} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered content missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "plain fallback") {
		t.Fatalf("HTML message unexpectedly used plain fallback: %s", got)
	}
}

func TestMailboxVisualPageReturnsCachedMailWithoutWaitingForSync(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("owner", "account", "Alias", "visual-fast@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AddMessage(mailbox.ID, "Cached code", "sender@example.com", "Your code is 691288", time.Now()); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	started := time.Now()
	rr := httptest.NewRecorder()
	path := "/api/v1/access/" + url.PathEscape(mailbox.APIToken) + "/mailboxes/" + url.PathEscape(mailbox.Email) + "/view"
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("cached visual page took %s", elapsed)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	for _, want := range []string{"Cached code", "691288", "页面自动刷新", "setTimeout(refresh,350)"} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("visual page missing %q", want)
		}
	}
}

func TestMailboxVisualRefreshKeepsBackgroundSyncAliveAfterFastResponse(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("owner-visual-bg", "account-visual-bg", "Alias", "visual-background@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-visual-bg", testIMAPSession("owner-visual-bg", "account-visual-bg", "receiver@example.com")); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	started := make(chan struct{})
	release := make(chan struct{})
	server.syncCodeMailboxBatchWithCursor = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return iCloudIMAPSyncResult{}, ctx.Err()
		}
		return iCloudIMAPSyncResult{MessagesByMailbox: map[string][]ICloudSyncedMessage{
			mailbox.ID: {{RemoteID: "imap:9901", UID: "9901", Subject: "Late result", Body: "验证码 691288", ReceivedAt: time.Now()}},
		}, LastUID: "9901"}, nil
	}
	previousWait := mailboxVisualSyncResponseWait
	mailboxVisualSyncResponseWait = 20 * time.Millisecond
	t.Cleanup(func() { mailboxVisualSyncResponseWait = previousWait })

	recorder := httptest.NewRecorder()
	path := "/api/v1/access/" + url.PathEscape(mailbox.APIToken) + "/mailboxes/" + url.PathEscape(mailbox.Email) + "/view?refresh=1"
	requestStarted := time.Now()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if elapsed := time.Since(requestStarted); elapsed > 300*time.Millisecond {
		t.Fatalf("visual refresh blocked for %s", elapsed)
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["sync_pending"] != true {
		t.Fatalf("response=%v, want sync_pending=true", response)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background sync did not start")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if messages := store.MessagesForMailbox(mailbox.ID); len(messages) == 1 && messages[0].Subject == "Late result" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background sync was canceled with the visual response")
}

func TestMailboxVisualCardsRespectLimitAndRevision(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("owner", "account", "Alias", "visual-limit@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AddMessage(mailbox.ID, "Older", "sender@example.com", "first", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AddMessage(mailbox.ID, "Newest", "sender@example.com", "second", time.Now()); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	html, count, revision := server.mailboxVisualCards(mailbox, 1)
	if count != 1 || revision == "" || !strings.Contains(html, "Newest") || strings.Contains(html, "Older") {
		t.Fatalf("count=%d revision=%q html=%s", count, revision, html)
	}
}

func TestMailboxVisualMessageContentFallsBackToEscapedPlainText(t *testing.T) {
	got := mailboxVisualMessageContent(Message{Body: `<b>plain & safe</b>`})
	if got != `<div class="mail-plain"><div class="mail-text">&lt;b&gt;plain &amp; safe&lt;/b&gt;</div></div>` {
		t.Fatalf("plain message rendered as %s", got)
	}
}

func TestMailboxVisualMessageContentRemovesEmbeddedCSSNoise(t *testing.T) {
	got := mailboxVisualMessageContent(Message{Body: `Title @font-face { font-family: broken; } table { width:100% } Enter this temporary verification code to continue: 691288 Didn't request a verification code?`})
	if strings.Contains(got, "@font-face") || strings.Contains(got, "table {") {
		t.Fatalf("CSS noise was not removed: %s", got)
	}
	for _, want := range []string{`class="mail-code">691288`, "Enter this temporary verification code"} {
		if !strings.Contains(got, want) {
			t.Fatalf("clean fallback missing %q: %s", want, got)
		}
	}
}
