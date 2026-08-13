package app

import (
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
	for _, want := range []string{`<iframe`, `sandbox="allow-same-origin"`, `srcdoc="`, `&lt;style&gt;`, `&lt;strong&gt;691288&lt;/strong&gt;`} {
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
	for _, want := range []string{"Cached code", "691288", "15 秒自动同步", "setTimeout(refresh,350)"} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("visual page missing %q", want)
		}
	}
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
