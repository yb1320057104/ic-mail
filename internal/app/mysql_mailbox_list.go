package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// mysqlMailboxListQuery describes the filters used by the mailbox pool. The
// MySQL implementation deliberately mirrors filterMailboxesForList so the
// fast path can be enabled without changing the HTTP contract.
type mysqlMailboxListQuery struct {
	ScopedOwnerID string
	OwnerFilter   string
	Admin         bool
	AccountKey    string
	Keyword       string
	Status        string
	APIStatus     string
	ICloudStatus  string
	ExportStatus  string
	MailboxType   string
	MinReceive    int
	MaxReceive    int
	Page          int
	PageSize      int
	ReceiveStatus string
}

type mysqlMailboxListResult struct {
	Mailboxes   []Mailbox
	GroupCounts map[string]int
	Total       int
	TotalAll    int
}

const (
	mysqlMailboxDocument = "CONVERT(m.payload USING utf8mb4)"
	mysqlAccountDocument = "CONVERT(a.payload USING utf8mb4)"
	mysqlUserDocument    = "CONVERT(u.payload USING utf8mb4)"
	mysqlParentDocument  = "CONVERT(parent.payload USING utf8mb4)"
)

func mysqlJSONText(document, path string) string {
	return fmt.Sprintf("JSON_UNQUOTE(JSON_EXTRACT(%s, '%s'))", document, path)
}

func (q mysqlMailboxListQuery) effectiveOwner() (string, bool) {
	scoped := strings.TrimSpace(q.ScopedOwnerID)
	filter := strings.TrimSpace(q.OwnerFilter)
	if filter == "all" {
		filter = ""
	}
	if !q.Admin {
		if filter != "" && (scoped == "" || !constantTimeEqual(scoped, filter)) {
			return "", false
		}
		return scoped, true
	}
	if filter != "" {
		return filter, true
	}
	return scoped, true
}

func mysqlMailboxListFrom() string {
	return " FROM ipm_mailboxes m" +
		" LEFT JOIN ipm_accounts a ON a.id=m.list_account_id" +
		" LEFT JOIN ipm_users u ON u.id=m.list_owner_id" +
		" LEFT JOIN ipm_mailboxes parent ON parent.id=m.list_parent_mailbox_id"
}

// mysqlMailboxListWhere returns the WHERE clause and arguments. accountFilter
// is false for the account-tab group query, matching the legacy handler which
// removes account_key/account_id before calculating groups.
func mysqlMailboxListWhere(q mysqlMailboxListQuery, accountFilter bool) (string, []any, bool) {
	ownerID, allowed := q.effectiveOwner()
	if !allowed {
		return " WHERE 1=0", nil, true
	}
	conditions := make([]string, 0, 12)
	args := make([]any, 0, 16)
	if ownerID != "" {
		conditions = append(conditions, "m.list_owner_id=?")
		args = append(args, ownerID)
	}

	accountID := "m.list_account_id"
	if accountFilter {
		accountKey := strings.TrimSpace(q.AccountKey)
		if accountKey != "" && accountKey != "all" {
			if accountKey == "unbound" {
				conditions = append(conditions, "COALESCE("+accountID+",'')=''")
			} else {
				conditions = append(conditions, accountID+"=?")
				args = append(args, accountKey)
			}
		}
	}

	mailboxType := "m.list_mailbox_type"
	switch strings.ToLower(strings.TrimSpace(q.MailboxType)) {
	case "alias":
		conditions = append(conditions, mailboxType+"='alias'")
	case "privacy", "normal":
		conditions = append(conditions, mailboxType+"<>'alias'")
	}
	if value := strings.ToLower(strings.TrimSpace(q.Status)); value != "" {
		conditions = append(conditions, "LOWER(m.list_status)=?")
		args = append(args, value)
	}
	switch strings.ToLower(strings.TrimSpace(q.APIStatus)) {
	case "active":
		conditions = append(conditions, "m.list_api_active=1")
	case "disabled":
		conditions = append(conditions, "m.list_api_active=0")
	}
	switch strings.ToLower(strings.TrimSpace(q.ICloudStatus)) {
	case "active":
		conditions = append(conditions, "m.list_icloud_active=1")
	case "disabled":
		conditions = append(conditions, "m.list_icloud_active=0")
	}
	exportedAt := "m.list_exported_at"
	switch strings.ToLower(strings.TrimSpace(q.ExportStatus)) {
	case "exported":
		conditions = append(conditions, exportedAt+"<>''", exportedAt+" NOT LIKE '0001-%'")
	case "unexported":
		conditions = append(conditions, "("+exportedAt+"='' OR "+exportedAt+" LIKE '0001-%')")
	}
	receiveCount := "m.list_receive_count"
	if q.MinReceive > 0 {
		conditions = append(conditions, receiveCount+">=?")
		args = append(args, q.MinReceive)
	}
	if q.MaxReceive >= 0 && q.MaxReceive < 1_000_000 {
		conditions = append(conditions, receiveCount+"<=?")
		args = append(args, q.MaxReceive)
	}
	if keyword := strings.ToLower(strings.TrimSpace(q.Keyword)); keyword != "" {
		conditions = append(conditions, "(LOCATE(?,LOWER("+mysqlMailboxDocument+"))>0"+
			" OR LOCATE(?,LOWER("+mysqlAccountDocument+"))>0"+
			" OR LOCATE(?,LOWER("+mysqlUserDocument+"))>0"+
			" OR LOCATE(?,LOWER("+mysqlParentDocument+"))>0)")
		args = append(args, keyword, keyword, keyword, keyword)
	}
	if len(conditions) == 0 {
		return "", args, true
	}
	return " WHERE " + strings.Join(conditions, " AND "), args, true
}

// listMailboxesPageMySQL bypasses the process-wide state mutex and lets
// InnoDB perform filtering/counting/pagination. It returns used=false for
// SQLite and for receive-code health filtering, whose semantics currently
// depend on the live in-memory IMAP resolver.
func (s *FileStore) listMailboxesPageMySQL(ctx context.Context, q mysqlMailboxListQuery) (result mysqlMailboxListResult, used bool, err error) {
	if s.storageDriver != "mysql" || strings.TrimSpace(q.ReceiveStatus) != "" {
		return result, false, nil
	}
	result.GroupCounts = make(map[string]int)
	result.Mailboxes = []Mailbox{}
	if _, allowed := q.effectiveOwner(); !allowed {
		return result, true, nil
	}
	db, err := s.mysqlConnection()
	if err != nil {
		return result, true, err
	}
	defer db.Close()

	from := mysqlMailboxListFrom()
	groupWhere, groupArgs, _ := mysqlMailboxListWhere(q, false)
	accountID := "m.list_account_id"
	groupRows, err := db.QueryContext(ctx, "SELECT "+accountID+",COUNT(*)"+from+groupWhere+" GROUP BY "+accountID, groupArgs...)
	if err != nil {
		return result, true, fmt.Errorf("query mysql mailbox groups: %w", err)
	}
	for groupRows.Next() {
		var key string
		var count int
		if err := groupRows.Scan(&key, &count); err != nil {
			_ = groupRows.Close()
			return result, true, err
		}
		if strings.TrimSpace(key) == "" {
			key = "unbound"
		}
		result.GroupCounts[key] = count
		result.TotalAll += count
	}
	if err := groupRows.Err(); err != nil {
		_ = groupRows.Close()
		return result, true, err
	}
	_ = groupRows.Close()

	where, args, _ := mysqlMailboxListWhere(q, true)
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*)"+from+where, args...).Scan(&result.Total); err != nil {
		return result, true, fmt.Errorf("count mysql mailboxes: %w", err)
	}
	page, pageSize := q.Page, q.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = mailboxListDefaultPageSize
	}
	offset := (page - 1) * pageSize
	if offset >= result.Total {
		return result, true, nil
	}
	accountLabel := mysqlJSONText(mysqlAccountDocument, "$.label")
	accountAppleID := mysqlJSONText(mysqlAccountDocument, "$.apple_id")
	email := "m.list_email"
	orderBy := " ORDER BY LOWER(COALESCE(NULLIF(" + accountLabel + ",''),NULLIF(" + accountAppleID + ",''),NULLIF(" + accountID + ",''),'~'))," +
		" LOWER(COALESCE(" + email + ",'')),m.id"
	pageArgs := append(append([]any(nil), args...), pageSize, offset)
	rows, err := db.QueryContext(ctx, "SELECT m.payload"+from+where+orderBy+" LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		return result, true, fmt.Errorf("query mysql mailboxes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return result, true, err
		}
		var mailbox Mailbox
		if err := json.Unmarshal(raw, &mailbox); err != nil {
			return result, true, fmt.Errorf("decode mysql mailbox: %w", err)
		}
		result.Mailboxes = append(result.Mailboxes, mailbox)
	}
	if err := rows.Err(); err != nil {
		return result, true, err
	}
	return result, true, nil
}

// ensureMySQLMailboxListSchema adds generated columns derived from the JSON
// payload. Generated columns keep all existing writers compatible while
// allowing the mailbox pool to use normal B-tree indexes.
func ensureMySQLMailboxListSchema(db *sql.DB) error {
	rows, err := db.Query(`SELECT column_name FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='ipm_mailboxes'`)
	if err != nil {
		return err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	doc := "CONVERT(payload USING utf8mb4)"
	definitions := []struct {
		name string
		sql  string
	}{
		{"list_owner_id", "VARCHAR(255) GENERATED ALWAYS AS (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.owner_id')),'')) STORED"},
		{"list_account_id", "VARCHAR(255) GENERATED ALWAYS AS (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.account_id')),'')) STORED"},
		{"list_email", "VARCHAR(320) GENERATED ALWAYS AS (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.email')),'')) STORED"},
		{"list_mailbox_type", "VARCHAR(32) GENERATED ALWAYS AS (COALESCE(NULLIF(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.mailbox_type')),''),'privacy')) STORED"},
		{"list_status", "VARCHAR(64) GENERATED ALWAYS AS (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.status')),'')) STORED"},
		{"list_api_active", "TINYINT GENERATED ALWAYS AS (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.api_active')),'false')='true') STORED"},
		{"list_icloud_active", "TINYINT GENERATED ALWAYS AS (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.icloud_active')),'false')='true') STORED"},
		{"list_receive_count", "BIGINT GENERATED ALWAYS AS (CAST(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.receive_count')),'0') AS UNSIGNED)) STORED"},
		{"list_exported_at", "VARCHAR(64) GENERATED ALWAYS AS (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.exported_at')),'')) STORED"},
		{"list_parent_mailbox_id", "VARCHAR(255) GENERATED ALWAYS AS (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(" + doc + ", '$.parent_mailbox_id')),'')) STORED"},
	}
	additions := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		if !columns[definition.name] {
			additions = append(additions, "ADD COLUMN `"+definition.name+"` "+definition.sql)
		}
	}
	if len(additions) > 0 {
		if _, err := db.Exec("ALTER TABLE ipm_mailboxes " + strings.Join(additions, ", ")); err != nil {
			return fmt.Errorf("add mysql mailbox list columns: %w", err)
		}
	}

	indexRows, err := db.Query(`SELECT DISTINCT index_name FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='ipm_mailboxes'`)
	if err != nil {
		return err
	}
	indexes := make(map[string]bool)
	for indexRows.Next() {
		var name string
		if err := indexRows.Scan(&name); err != nil {
			_ = indexRows.Close()
			return err
		}
		indexes[name] = true
	}
	if err := indexRows.Err(); err != nil {
		_ = indexRows.Close()
		return err
	}
	_ = indexRows.Close()
	indexDefinitions := []struct {
		name    string
		columns string
	}{
		{"idx_ipm_mailboxes_list_type_account_email", "list_mailbox_type,list_account_id,list_email"},
		{"idx_ipm_mailboxes_list_owner_type_account", "list_owner_id,list_mailbox_type,list_account_id"},
		{"idx_ipm_mailboxes_list_status", "list_status,list_api_active,list_icloud_active,list_receive_count"},
	}
	for _, index := range indexDefinitions {
		if indexes[index.name] {
			continue
		}
		if _, err := db.Exec("CREATE INDEX `" + index.name + "` ON ipm_mailboxes(" + index.columns + ")"); err != nil {
			return fmt.Errorf("create mysql mailbox index %s: %w", index.name, err)
		}
	}
	return nil
}
