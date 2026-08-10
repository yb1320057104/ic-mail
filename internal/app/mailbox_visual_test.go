package app

import (
	"strings"
	"testing"
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
