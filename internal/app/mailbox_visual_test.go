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
	if got != `<pre>&lt;b&gt;plain &amp; safe&lt;/b&gt;</pre>` {
		t.Fatalf("plain message rendered as %s", got)
	}
}
