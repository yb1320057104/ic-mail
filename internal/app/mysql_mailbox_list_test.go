package app

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMySQLMailboxListWhereMirrorsCommonFilters(t *testing.T) {
	query := mysqlMailboxListQuery{
		ScopedOwnerID: "owner-1",
		AccountKey:    "account-1",
		MailboxType:   "privacy",
		APIStatus:     "active",
		ICloudStatus:  "disabled",
		MinReceive:    2,
		MaxReceive:    9,
		Keyword:       "Example.COM",
	}
	where, args, ok := mysqlMailboxListWhere(query, true)
	if !ok {
		t.Fatal("common filters should use mysql fast path")
	}
	for _, want := range []string{"m.list_owner_id=?", "m.list_account_id", "m.list_mailbox_type", "m.list_api_active", "m.list_icloud_active", "m.list_receive_count", "LOCATE"} {
		if !strings.Contains(where, want) {
			t.Fatalf("where clause missing %q: %s", want, where)
		}
	}
	if len(args) != 8 {
		t.Fatalf("args=%#v, want owner/account/min/max and four keyword args", args)
	}
	if got := args[len(args)-1]; got != "example.com" {
		t.Fatalf("normalized keyword=%v", got)
	}
}

func TestMySQLMailboxListIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("IPM_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("IPM_TEST_MYSQL_DSN is not set")
	}
	store := &FileStore{storageDriver: "mysql", mysqlDSN: dsn}
	if err := store.openMySQL(); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, used, err := store.listMailboxesPageMySQL(context.Background(), mysqlMailboxListQuery{
		Admin:       true,
		MailboxType: "privacy",
		MaxReceive:  1_000_000,
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !used || result.Total <= 0 || result.TotalAll <= 0 || len(result.Mailboxes) == 0 || len(result.Mailboxes) > 10 {
		t.Fatalf("unexpected mysql page: used=%v result=%+v", used, result)
	}
	t.Logf("mysql mailbox page: total=%d groups=%d rows=%d duration=%s", result.Total, len(result.GroupCounts), len(result.Mailboxes), time.Since(started))
}

func TestMySQLMailboxGroupWhereIgnoresAccountTab(t *testing.T) {
	query := mysqlMailboxListQuery{Admin: true, OwnerFilter: "owner-2", AccountKey: "account-2", MailboxType: "alias", MaxReceive: 1_000_000}
	where, args, _ := mysqlMailboxListWhere(query, false)
	if strings.Contains(where, "m.list_account_id") {
		t.Fatalf("group query must ignore account tab: %s", where)
	}
	if !strings.Contains(where, "m.list_owner_id=?") || len(args) != 1 || args[0] != "owner-2" {
		t.Fatalf("owner filter missing: where=%s args=%#v", where, args)
	}
}

func TestMySQLMailboxListRejectsCrossOwnerFilter(t *testing.T) {
	where, _, _ := mysqlMailboxListWhere(mysqlMailboxListQuery{ScopedOwnerID: "owner-1", OwnerFilter: "owner-2"}, true)
	if where != " WHERE 1=0" {
		t.Fatalf("cross-owner query=%q", where)
	}
}
