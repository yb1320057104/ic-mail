package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

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
		`CREATE TABLE IF NOT EXISTS user_proxy_configs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS redemption_pools (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS redemption_codes (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS redemption_items (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS recycle_bin (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '', payload BLOB NOT NULL, updated_at TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return fmt.Errorf("initialize sqlite: %w", err)
		}
	}
	return nil
}

func (s *FileStore) sqliteConnection() (*sql.DB, error) {
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

func (s *FileStore) loadSQLiteLocked() (bool, error) {
	if _, err := os.Stat(s.dbPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
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
	if len(stored) > 0 {
		s.state.Messages = stored
		s.needsMessageMigration = false
	} else if len(s.state.Messages) > 0 {
		s.needsMessageMigration = true
	}
	s.persistedMessages = persisted
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
	return true, rows.Err()
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
		if _, err := tx.Exec(`INSERT INTO messages(id,payload,updated_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at`, message.ID, raw, now); err != nil {
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
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.persistedMessages = next
	s.needsMessageMigration = false
	return nil
}

func (s *FileStore) DatabasePath() string { return s.dbPath }
