package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

func (s *FileStore) openStorage() error {
	if s.storageDriver == "mysql" {
		return s.openMySQL()
	}
	return s.openSQLite()
}

func (s *FileStore) openSQLite() error {
	if err := os.MkdirAll(filepath.Dir(s.dbPath), 0o755); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	for _, statement := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=FULL`,
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS backups (id TEXT PRIMARY KEY, kind TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, note TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS task_runs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS runtime_metrics (kind TEXT PRIMARY KEY, total INTEGER NOT NULL DEFAULT 0, success INTEGER NOT NULL DEFAULT 0, failure INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER NOT NULL DEFAULT 0, max_duration_ms INTEGER NOT NULL DEFAULT 0, last_duration_ms INTEGER NOT NULL DEFAULT 0, last_ok INTEGER NOT NULL DEFAULT 0, last_message TEXT NOT NULL DEFAULT '', last_at TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS runtime_metric_events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, ok INTEGER NOT NULL, duration_ms INTEGER NOT NULL, message TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_metric_events_kind_time ON runtime_metric_events(kind,created_at)`,
		`CREATE TABLE IF NOT EXISTS state_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS web_sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_accounts_owner ON accounts(owner_id)`,
		`CREATE TABLE IF NOT EXISTS mailboxes (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_mailboxes_owner ON mailboxes(owner_id)`,
		`CREATE TABLE IF NOT EXISTS icloud_sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS create_settings (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS invites (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS invite_uses (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS announcements (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS announcement_reads (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS auto_login_bindings (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS auto_login_logs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS user_proxy_configs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS redemption_pools (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS redemption_codes (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS redemption_items (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS redemption_orders (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS recycle_bin (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return fmt.Errorf("initialize sqlite: %w", err)
		}
	}
	if err := initializeMessageSearch(db); err != nil {
		return err
	}
	return nil
}

func (s *FileStore) sqliteConnection() (*sql.DB, error) {
	if s.storageDriver == "mysql" {
		return s.mysqlConnection()
	}
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func (s *FileStore) mysqlConnection() (*sql.DB, error) {
	if strings.TrimSpace(s.mysqlDSN) == "" {
		return nil, errors.New("mysql_dsn is required when storage_driver=mysql")
	}
	db, err := sql.Open("mysql", s.mysqlDSN)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect mysql: %w", err)
	}
	return db, nil
}

func (s *FileStore) openMySQL() error {
	db, err := s.mysqlConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	// MySQL does not support SQLite's FTS5 virtual table. The application
	// keeps message payloads in the regular table; search fallback is handled
	// by the caller until a FULLTEXT index is provisioned.
	statements := []string{
		`CREATE TABLE IF NOT EXISTS ipm_app_state (id BIGINT PRIMARY KEY, payload LONGBLOB NOT NULL, updated_at VARCHAR(64) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS ipm_messages (id VARCHAR(255) PRIMARY KEY, payload LONGBLOB NOT NULL, updated_at VARCHAR(64) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS ipm_backups (id VARCHAR(255) PRIMARY KEY, kind VARCHAR(64) NOT NULL, path VARCHAR(1024) NOT NULL, size BIGINT NOT NULL DEFAULT 0, created_at VARCHAR(64) NOT NULL, note TEXT NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS ipm_task_runs (id VARCHAR(255) PRIMARY KEY, kind VARCHAR(255) NOT NULL, status VARCHAR(64) NOT NULL, progress BIGINT NOT NULL DEFAULT 0, message TEXT NOT NULL, started_at VARCHAR(64) NOT NULL, finished_at VARCHAR(64) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS ipm_runtime_metrics (kind VARCHAR(255) PRIMARY KEY, total BIGINT NOT NULL DEFAULT 0, success BIGINT NOT NULL DEFAULT 0, failure BIGINT NOT NULL DEFAULT 0, duration_ms BIGINT NOT NULL DEFAULT 0, max_duration_ms BIGINT NOT NULL DEFAULT 0, last_duration_ms BIGINT NOT NULL DEFAULT 0, last_ok BIGINT NOT NULL DEFAULT 0, last_message TEXT NOT NULL, last_at VARCHAR(64) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS ipm_runtime_metric_events (id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, kind VARCHAR(255) NOT NULL, ok BIGINT NOT NULL, duration_ms BIGINT NOT NULL, message TEXT NOT NULL, created_at VARCHAR(64) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS ipm_state_meta (` + "`key`" + ` VARCHAR(255) PRIMARY KEY, value TEXT NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS ipm_message_search_v3 (message_id VARCHAR(255) PRIMARY KEY, owner_id VARCHAR(255) NOT NULL, mailbox_id VARCHAR(255) NOT NULL, source VARCHAR(32) NOT NULL, received_unix BIGINT NOT NULL, subject TEXT NOT NULL, sender TEXT NOT NULL, body LONGTEXT NOT NULL, cjk TEXT NOT NULL, KEY idx_ipm_search_mailbox (mailbox_id), KEY idx_ipm_search_received (received_unix)) ENGINE=InnoDB`,
	}
	for _, q := range statements {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("initialize mysql: %w", err)
		}
	}
	// Migration-created databases may have copied SQLite's AUTOINCREMENT
	// column as a plain BIGINT. Make new metric events writable in MySQL.
	if _, err := db.Exec(`ALTER TABLE ipm_runtime_metric_events MODIFY id BIGINT NOT NULL AUTO_INCREMENT`); err != nil {
		return fmt.Errorf("initialize mysql metric sequence: %w", err)
	}
	for _, name := range []string{"users", "web_sessions", "accounts", "mailboxes", "icloud_sessions", "create_settings", "invites", "invite_uses", "audit_events", "announcements", "announcement_reads", "auto_login_bindings", "auto_login_logs", "user_proxy_configs", "redemption_pools", "redemption_codes", "redemption_items", "redemption_orders", "recycle_bin"} {
		q := fmt.Sprintf("CREATE TABLE IF NOT EXISTS ipm_%s (id VARCHAR(255) PRIMARY KEY, owner_id VARCHAR(255) NOT NULL DEFAULT '', payload LONGBLOB NOT NULL, updated_at VARCHAR(64) NOT NULL) ENGINE=InnoDB", name)
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("initialize mysql %s: %w", name, err)
		}
	}
	if err := ensureMySQLMailboxListSchema(db); err != nil {
		return fmt.Errorf("initialize mysql mailbox list schema: %w", err)
	}
	// Keep the existing store SQL readable by exposing compatibility views.
	for _, name := range []string{"app_state", "messages", "backups", "task_runs", "runtime_metrics", "runtime_metric_events", "state_meta", "users", "web_sessions", "accounts", "mailboxes", "icloud_sessions", "create_settings", "invites", "invite_uses", "audit_events", "announcements", "announcement_reads", "auto_login_bindings", "auto_login_logs", "user_proxy_configs", "redemption_pools", "redemption_codes", "redemption_items", "redemption_orders", "recycle_bin"} {
		// Views are only created when the name is not already occupied. A
		// migrated installation has ipm_ tables and no unprefixed names.
		q := fmt.Sprintf("CREATE OR REPLACE VIEW `%s` AS SELECT * FROM `ipm_%s`", name, name)
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("initialize mysql view %s: %w", name, err)
		}
	}
	if _, err := db.Exec("CREATE OR REPLACE VIEW message_search_v3 AS SELECT * FROM ipm_message_search_v3"); err != nil {
		return fmt.Errorf("initialize mysql search view: %w", err)
	}
	return nil
}

func (s *FileStore) loadSQLiteLocked() (bool, error) {
	if s.storageDriver != "mysql" {
		if _, err := os.Stat(s.dbPath); errors.Is(err, os.ErrNotExist) {
			return false, nil
		} else if err != nil {
			return false, err
		}
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return false, err
	}
	defer db.Close()
	if found, err := s.loadNormalizedStateLocked(db); err != nil {
		return false, err
	} else if found {
		return s.loadNormalizedMessagesLocked(db)
	}
	var payload []byte
	err = db.QueryRow(`SELECT payload FROM app_state WHERE id=1`).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read sqlite state: %w", err)
	}
	if err := json.Unmarshal(payload, &s.state); err != nil {
		return false, fmt.Errorf("decode sqlite state: %w", err)
	}
	rows, err := db.Query(`SELECT id,payload FROM messages ORDER BY id`)
	if err != nil {
		return false, fmt.Errorf("read sqlite messages: %w", err)
	}
	defer rows.Close()
	var stored []Message
	persisted := make(map[string]string)
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return false, err
		}
		var message Message
		if err := json.Unmarshal(raw, &message); err != nil {
			return false, err
		}
		stored = append(stored, message)
		persisted[id] = string(raw)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	// Release the read cursor before the one-time FTS rebuild opens a write
	// transaction on a separate SQLite connection. Keeping this cursor open
	// can hold a read lock indefinitely and prevent the HTTP server starting.
	if err := rows.Close(); err != nil {
		return false, err
	}
	if len(stored) > 0 {
		s.state.Messages = stored
		s.needsMessageMigration = false
	} else if len(s.state.Messages) > 0 {
		s.needsMessageMigration = true
	}
	s.persistedMessages = persisted
	if err := s.ensureMessageSearchIndexLocked(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *FileStore) loadNormalizedMessagesLocked(db *sql.DB) (bool, error) {
	rows, err := db.Query(`SELECT id,payload FROM messages ORDER BY id`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	s.state.Messages = nil
	s.persistedMessages = map[string]string{}
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return false, err
		}
		var m Message
		if err := json.Unmarshal(raw, &m); err != nil {
			return false, err
		}
		s.state.Messages = append(s.state.Messages, m)
		s.persistedMessages[id] = string(raw)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	// The search index rebuild uses its own connection. Close this cursor first
	// so WAL/SQLite can grant the writer immediately during an upgrade.
	if err := rows.Close(); err != nil {
		return false, err
	}
	if err := s.ensureMessageSearchIndexLocked(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *FileStore) saveSQLiteLocked() error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	now := normalizedNow()
	if err = s.saveNormalizedStateTx(tx, now); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save sqlite state: %w", err)
	}
	next := make(map[string]string, len(s.state.Messages))
	for _, message := range s.state.Messages {
		raw, err := json.Marshal(message)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		encoded := string(raw)
		next[message.ID] = encoded
		if s.persistedMessages[message.ID] == encoded {
			continue
		}
		messageSQL := `INSERT INTO messages(id,payload,updated_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at`
		if s.storageDriver == "mysql" {
			messageSQL = `INSERT INTO messages(id,payload,updated_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),updated_at=VALUES(updated_at)`
		}
		if _, err := tx.Exec(messageSQL, message.ID, raw, now); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := upsertMessageSearchTx(tx, message); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	for id := range s.persistedMessages {
		if _, ok := next[id]; ok {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM messages WHERE id=?`, id); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := deleteMessageSearchTx(tx, id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.persistedMessages = next
	s.needsMessageMigration = false
	return nil
}

// saveMailboxLocked persists one mailbox without rewriting every normalized
// table. Public code retrieval only changes the last-served marker, so a full
// state save here is both unnecessarily slow and more likely to contend with
// background IMAP/keepalive writes.
func (s *FileStore) saveMailboxLocked(mailbox Mailbox) error {
	raw, err := json.Marshal(mailbox)
	if err != nil {
		return err
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	q := `INSERT INTO mailboxes(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,payload=excluded.payload,updated_at=excluded.updated_at`
	if s.storageDriver == "mysql" {
		q = `INSERT INTO mailboxes(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE owner_id=VALUES(owner_id),payload=VALUES(payload),updated_at=VALUES(updated_at)`
	}
	_, err = db.Exec(q,
		mailbox.ID, mailbox.OwnerID, raw, normalizedNow())
	if err != nil {
		return fmt.Errorf("save mailbox: %w", err)
	}
	return nil
}

func (s *FileStore) saveMailboxMessageLocked(mailbox Mailbox, message Message) error {
	mailboxRaw, err := json.Marshal(mailbox)
	if err != nil {
		return err
	}
	messageRaw, err := json.Marshal(message)
	if err != nil {
		return err
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	now := normalizedNow()
	q := `INSERT INTO mailboxes(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,payload=excluded.payload,updated_at=excluded.updated_at`
	if s.storageDriver == "mysql" {
		q = `INSERT INTO mailboxes(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE owner_id=VALUES(owner_id),payload=VALUES(payload),updated_at=VALUES(updated_at)`
	}
	if _, err = tx.Exec(q,
		mailbox.ID, mailbox.OwnerID, mailboxRaw, now); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save message mailbox: %w", err)
	}
	messageSQL := `INSERT INTO messages(id,payload,updated_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at`
	if s.storageDriver == "mysql" {
		messageSQL = `INSERT INTO messages(id,payload,updated_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),updated_at=VALUES(updated_at)`
	}
	if _, err = tx.Exec(messageSQL, message.ID, messageRaw, now); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save message: %w", err)
	}
	if err = upsertMessageSearchTx(tx, message); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save message search index: %w", err)
	}
	nextSQL := "INSERT INTO state_meta(`key`,value) VALUES('next_id',?) ON CONFLICT(`key`) DO UPDATE SET value=excluded.value"
	if s.storageDriver == "mysql" {
		nextSQL = "INSERT INTO state_meta(`key`,value) VALUES('next_id',?) ON DUPLICATE KEY UPDATE value=VALUES(value)"
	}
	if _, err = tx.Exec(nextSQL, strconv.Itoa(s.state.NextID)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save next id: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if s.persistedMessages == nil {
		s.persistedMessages = make(map[string]string)
	}
	s.persistedMessages[message.ID] = string(messageRaw)
	return nil
}

func (s *FileStore) saveICloudSessionRowLocked(session ICloudSession) error {
	ownerID, accountID := strings.TrimSpace(session.OwnerID), strings.TrimSpace(session.AccountID)
	if ownerID == "" || accountID == "" {
		return s.saveLocked()
	}
	raw, err := json.Marshal(session)
	if err != nil {
		return err
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	q := `INSERT INTO icloud_sessions(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,payload=excluded.payload,updated_at=excluded.updated_at`
	if s.storageDriver == "mysql" {
		q = `INSERT INTO icloud_sessions(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE owner_id=VALUES(owner_id),payload=VALUES(payload),updated_at=VALUES(updated_at)`
	}
	_, err = db.Exec(q,
		ownerID+":"+accountID, ownerID, raw, normalizedNow())
	if err != nil {
		return fmt.Errorf("save icloud session: %w", err)
	}
	return nil
}

// saveAccountAndICloudSessionRowLocked persists only the account/session being
// refreshed. Keepalive and health-check updates are frequent and concurrent;
// replacing even the complete account/session collections created excessive
// binlog volume and could fill a small MySQL system disk.
func (s *FileStore) saveAccountAndICloudSessionRowLocked(account Account, session ICloudSession) error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	now := normalizedNow()
	if strings.TrimSpace(account.ID) != "" {
		raw, marshalErr := json.Marshal(account)
		if marshalErr != nil {
			_ = tx.Rollback()
			return marshalErr
		}
		query := `INSERT INTO accounts(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,payload=excluded.payload,updated_at=excluded.updated_at`
		if s.storageDriver == "mysql" {
			query = `INSERT INTO accounts(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE owner_id=VALUES(owner_id),payload=VALUES(payload),updated_at=VALUES(updated_at)`
		}
		if _, err = tx.Exec(query, account.ID, account.OwnerID, raw, now); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("save account row: %w", err)
		}
	}
	raw, err := json.Marshal(session)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	query := `INSERT INTO icloud_sessions(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,payload=excluded.payload,updated_at=excluded.updated_at`
	if s.storageDriver == "mysql" {
		query = `INSERT INTO icloud_sessions(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE owner_id=VALUES(owner_id),payload=VALUES(payload),updated_at=VALUES(updated_at)`
	}
	if _, err = tx.Exec(query, session.OwnerID+":"+session.AccountID, session.OwnerID, raw, now); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save icloud session row: %w", err)
	}
	nextSQL := "INSERT INTO state_meta(`key`,value) VALUES('next_id',?) ON CONFLICT(`key`) DO UPDATE SET value=excluded.value"
	if s.storageDriver == "mysql" {
		nextSQL = "INSERT INTO state_meta(`key`,value) VALUES('next_id',?) ON DUPLICATE KEY UPDATE value=VALUES(value)"
	}
	if _, err = tx.Exec(nextSQL, strconv.Itoa(s.state.NextID)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save account next id: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *FileStore) saveAuditEventRowLocked(event AuditEvent, removed []AuditEvent) error {
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	now := normalizedNow()
	query := `INSERT INTO audit_events(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,payload=excluded.payload,updated_at=excluded.updated_at`
	if s.storageDriver == "mysql" {
		query = `INSERT INTO audit_events(id,owner_id,payload,updated_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE owner_id=VALUES(owner_id),payload=VALUES(payload),updated_at=VALUES(updated_at)`
	}
	if _, err = tx.Exec(query, event.ID, event.ActorID, raw, now); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save audit event: %w", err)
	}
	for _, old := range removed {
		if _, err = tx.Exec("DELETE FROM audit_events WHERE id=?", old.ID); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("delete old audit event: %w", err)
		}
	}
	nextSQL := "INSERT INTO state_meta(`key`,value) VALUES('next_id',?) ON CONFLICT(`key`) DO UPDATE SET value=excluded.value"
	if s.storageDriver == "mysql" {
		nextSQL = "INSERT INTO state_meta(`key`,value) VALUES('next_id',?) ON DUPLICATE KEY UPDATE value=VALUES(value)"
	}
	if _, err = tx.Exec(nextSQL, strconv.Itoa(s.state.NextID)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// deleteMailboxRowsLocked removes only the mailbox and its message/search
// rows. A mailbox delete used to call saveLocked, which scanned and compared
// every normalized collection while holding the store write lock. On a pool
// with tens of thousands of mailboxes that made each delete block readers for
// more than a second.
func (s *FileStore) deleteMailboxRowsLocked(mailboxID string, removedMessages []Message) error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, message := range removedMessages {
		if err = deleteMessageSearchTx(tx, message.ID); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("delete mailbox search row: %w", err)
		}
		if _, err = tx.Exec(`DELETE FROM messages WHERE id=?`, message.ID); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("delete mailbox message row: %w", err)
		}
	}
	if _, err = tx.Exec(`DELETE FROM mailboxes WHERE id=?`, mailboxID); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("delete mailbox row: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	for _, message := range removedMessages {
		delete(s.persistedMessages, message.ID)
	}
	return nil
}

func (s *FileStore) DatabasePath() string { return s.dbPath }
