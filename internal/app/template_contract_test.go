package app

import (
	"strings"
	"testing"
)

func TestIndexDefinesAdminDataViewsBeforeUse(t *testing.T) {
	content, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	definitionAt := strings.Index(source, "const ADMIN_DATA_VIEWS")
	firstUseAt := strings.Index(source, "ADMIN_DATA_VIEWS.has")
	if definitionAt < 0 || firstUseAt < 0 || definitionAt > firstUseAt {
		t.Fatalf("ADMIN_DATA_VIEWS must be defined before use: definition=%d use=%d", definitionAt, firstUseAt)
	}
	for _, view := range []string{
		"data-accountManage", "data-users", "data-mailboxes", "data-accounts",
		"data-sessions", "data-invites", "data-announcements", "data-audit",
		"data-operations", "data-logs",
	} {
		if !strings.Contains(source[definitionAt:firstUseAt], "'"+view+"'") {
			t.Fatalf("ADMIN_DATA_VIEWS missing %q", view)
		}
	}
}
