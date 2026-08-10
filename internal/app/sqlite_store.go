package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return fmt.Errorf("initialize sqlite: %w", err)
		}
	}
	return nil
}

func (s *FileStore) loadSQLiteLocked() (bool, error) {
	if _, err := os.Stat(s.dbPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return false, err
	}
	defer db.Close()
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

func (s *FileStore) saveSQLiteLocked() error {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	metadata := s.state
	metadata.Messages = nil
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO app_state(id,payload,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at`, payload, time.Now().Format(time.RFC3339Nano)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("save sqlite state: %w", err)
	}
	next := make(map[string]string, len(s.state.Messages))
	now := time.Now().Format(time.RFC3339Nano)
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
