package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const adminMessageSearchIndexVersion = "3"
const adminMessageSearchSyncBuildLimit = 500

type AdminMessageSearchQuery struct {
	Keyword   string
	OwnerID   string
	MailboxID string
	After     time.Time
	Before    time.Time
	Page      int
	PageSize  int
}

type AdminMessageSearchRow struct {
	Message Message `json:"message"`
}

type AdminMessageSearchResult struct {
	Rows     []AdminMessageSearchRow `json:"rows"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"page_size"`
	HasMore  bool                    `json:"has_more"`
	Scanned  int                     `json:"scanned"`
}

func initializeMessageSearch(db *sql.DB) error {
	if db == nil {
		return errors.New("sqlite connection is nil")
	}
	_, err := db.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS message_search_v3 USING fts5(
		message_id UNINDEXED,
		owner_id UNINDEXED,
		mailbox_id UNINDEXED,
		source UNINDEXED,
		received_unix UNINDEXED,
		subject,
		sender,
		body,
		cjk,
		tokenize='unicode61'
	)`)
	if err != nil {
		return fmt.Errorf("initialize message search index: %w", err)
	}
	return nil
}

func upsertMessageSearchTx(tx *sql.Tx, message Message) error {
	if tx == nil || strings.TrimSpace(message.ID) == "" {
		return nil
	}
	if _, err := tx.Exec(`DELETE FROM message_search_v3 WHERE message_id=?`, message.ID); err != nil {
		return err
	}
	searchBody := message.Body + "\n" + visibleEmailHTMLText(message.HTMLBody)
	_, err := tx.Exec(`INSERT INTO message_search_v3(message_id,owner_id,mailbox_id,source,received_unix,subject,sender,body,cjk)
		VALUES(?,?,?,?,?,?,?,?,?)`, message.ID, message.OwnerID, message.MailboxID, strings.ToLower(strings.TrimSpace(message.Source)),
		message.ReceivedAt.Unix(), message.Subject, message.From, searchBody, messageSearchCJK(message.Subject+"\n"+message.From+"\n"+searchBody))
	return err
}

func deleteMessageSearchTx(tx *sql.Tx, id string) error {
	if tx == nil || strings.TrimSpace(id) == "" {
		return nil
	}
	_, err := tx.Exec(`DELETE FROM message_search_v3 WHERE message_id=?`, id)
	return err
}

// ensureMessageSearchIndexLocked performs a one-time rebuild after upgrades.
// Normal message writes update the FTS row in the same transaction as the
// message payload, so later starts do not rescan the complete mail archive.
func (s *FileStore) ensureMessageSearchIndexLocked() error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	var version string
	err = db.QueryRow(`SELECT value FROM state_meta WHERE key='message_search_version'`).Scan(&version)
	if err == nil && version == adminMessageSearchIndexVersion {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	messages := append([]Message(nil), s.state.Messages...)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM message_search_v3`); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err = tx.Exec(`INSERT INTO state_meta(key,value) VALUES('message_search_version',?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "building:"+adminMessageSearchIndexVersion); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	// Small stores finish synchronously (also keeping tests deterministic). A
	// production archive is rebuilt in committed batches so HTTP startup is not
	// held hostage by HTML-to-text extraction and FTS tokenization.
	if len(messages) <= adminMessageSearchSyncBuildLimit {
		return s.rebuildMessageSearchIndex(messages)
	}
	go func() {
		_ = s.rebuildMessageSearchIndex(messages)
	}()
	return nil
}

func (s *FileStore) rebuildMessageSearchIndex(messages []Message) error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	const batchSize = 100
	for start := 0; start < len(messages); start += batchSize {
		end := min(start+batchSize, len(messages))
		tx, beginErr := db.Begin()
		if beginErr != nil {
			return beginErr
		}
		for _, message := range messages[start:end] {
			if err = upsertMessageSearchTx(tx, message); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	_, err = db.Exec(`INSERT INTO state_meta(key,value) VALUES('message_search_version',?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, adminMessageSearchIndexVersion)
	return err
}

func normalizeFTSQuery(keyword string) string {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return ""
	}
	// A quoted trigram query treats punctuation as ordinary searchable text and
	// avoids exposing the FTS query language to the HTTP caller.
	escaped := strings.ReplaceAll(keyword, `"`, `""`)
	if cjk := messageSearchCJK(keyword); cjk != "" {
		return `cjk : "` + strings.ReplaceAll(cjk, `"`, `""`) + `"`
	}
	return `"` + escaped + `"`
}

func messageSearchCJK(value string) string {
	parts := make([]string, 0, len(value)/3)
	for _, r := range strings.ToLower(value) {
		if (r >= 0x3400 && r <= 0x9fff) || (r >= 0x3040 && r <= 0x30ff) || (r >= 0xac00 && r <= 0xd7af) {
			parts = append(parts, string(r))
		}
	}
	return strings.Join(parts, " ")
}

func ftsSearchableKeyword(keyword string) bool {
	return len([]rune(strings.TrimSpace(keyword))) >= 3
}

func (s *FileStore) AdminSearchIMAPMessages(ctx context.Context, query AdminMessageSearchQuery, eligibleMailboxIDs map[string]struct{}) (AdminMessageSearchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	query.Page = max(1, query.Page)
	query.PageSize = max(1, min(query.PageSize, 100))
	result := AdminMessageSearchResult{Rows: []AdminMessageSearchRow{}, Page: query.Page, PageSize: query.PageSize}
	wantedStart := (query.Page - 1) * query.PageSize
	wantedEnd := wantedStart + query.PageSize + 1
	if len(eligibleMailboxIDs) == 0 {
		return result, nil
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return result, err
	}
	defer db.Close()

	const batchSize = 250
	const maxScanned = 20000
	offset := 0
	matched := 0
	ftsQuery := ""
	shortKeyword := strings.ToLower(strings.TrimSpace(query.Keyword))
	if ftsSearchableKeyword(query.Keyword) {
		ftsQuery = normalizeFTSQuery(query.Keyword)
		shortKeyword = ""
	}
	for result.Scanned < maxScanned && matched < wantedEnd {
		args := []any{"imap"}
		where := []string{"ms.source=?"}
		if ftsQuery != "" {
			where = append(where, "message_search_v3 MATCH ?")
			args = append(args, ftsQuery)
		}
		if query.OwnerID != "" && query.OwnerID != "all" {
			where = append(where, "ms.owner_id=?")
			args = append(args, query.OwnerID)
		}
		if query.MailboxID != "" {
			where = append(where, "ms.mailbox_id=?")
			args = append(args, query.MailboxID)
		}
		if !query.After.IsZero() {
			where = append(where, "CAST(ms.received_unix AS INTEGER)>=?")
			args = append(args, query.After.Unix())
		}
		if !query.Before.IsZero() {
			where = append(where, "CAST(ms.received_unix AS INTEGER)<=?")
			args = append(args, query.Before.Unix())
		}
		args = append(args, batchSize, offset)
		statement := `SELECT m.payload,ms.mailbox_id FROM message_search_v3 ms JOIN messages m ON m.id=ms.message_id WHERE ` +
			strings.Join(where, " AND ") + ` ORDER BY CAST(ms.received_unix AS INTEGER) DESC LIMIT ? OFFSET ?`
		rows, queryErr := db.QueryContext(ctx, statement, args...)
		if queryErr != nil {
			return result, queryErr
		}
		batchCount := 0
		for rows.Next() {
			batchCount++
			result.Scanned++
			var raw []byte
			var mailboxID string
			if err := rows.Scan(&raw, &mailboxID); err != nil {
				_ = rows.Close()
				return result, err
			}
			if _, ok := eligibleMailboxIDs[mailboxID]; !ok {
				continue
			}
			var message Message
			if err := json.Unmarshal(raw, &message); err != nil {
				_ = rows.Close()
				return result, err
			}
			if shortKeyword != "" {
				haystack := strings.ToLower(strings.Join([]string{message.Subject, message.From, message.Body, visibleEmailHTMLText(message.HTMLBody)}, "\n"))
				if !strings.Contains(haystack, shortKeyword) {
					continue
				}
			}
			if matched >= wantedStart && matched < wantedEnd {
				result.Rows = append(result.Rows, AdminMessageSearchRow{Message: message})
			}
			matched++
			if matched >= wantedEnd {
				break
			}
		}
		if err := rows.Close(); err != nil {
			return result, err
		}
		if batchCount < batchSize {
			break
		}
		offset += batchCount
	}
	if len(result.Rows) > query.PageSize {
		result.HasMore = true
		result.Rows = result.Rows[:query.PageSize]
	}
	return result, nil
}

func (s *FileStore) MessageByIDFromSQLite(ctx context.Context, id string) (Message, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return Message{}, false, err
	}
	defer db.Close()
	var raw []byte
	err = db.QueryRowContext(ctx, `SELECT payload FROM messages WHERE id=?`, strings.TrimSpace(id)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, nil
	}
	if err != nil {
		return Message{}, false, err
	}
	var message Message
	if err := json.Unmarshal(raw, &message); err != nil {
		return Message{}, false, err
	}
	return message, true, nil
}
