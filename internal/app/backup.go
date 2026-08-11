package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type BackupInfo struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

func (s *FileStore) backupDir() string { return filepath.Join(filepath.Dir(s.dbPath), "backups") }

func (s *FileStore) CreateBackup(label string) (BackupInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.saveSQLiteLocked(); err != nil {
		return BackupInfo{}, err
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return BackupInfo{}, err
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = db.Close()
		return BackupInfo{}, err
	}
	_ = db.Close()
	if err := os.MkdirAll(s.backupDir(), 0o700); err != nil {
		return BackupInfo{}, err
	}
	label = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, strings.TrimSpace(label))
	if label == "" {
		label = "manual"
	}
	name := fmt.Sprintf("state-%s-%s.db", time.Now().Format("20060102-150405"), label)
	data, err := os.ReadFile(s.dbPath)
	if err != nil {
		return BackupInfo{}, err
	}
	path := filepath.Join(s.backupDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return BackupInfo{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return BackupInfo{}, err
	}
	return BackupInfo{Name: name, Size: info.Size(), CreatedAt: formatTime(info.ModTime())}, nil
}

func (s *FileStore) Backups() ([]BackupInfo, error) {
	entries, err := os.ReadDir(s.backupDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".db") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{Name: entry.Name(), Size: info.Size(), CreatedAt: formatTime(info.ModTime())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

func (s *FileStore) BackupPath(name string) (string, error) {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || !strings.HasSuffix(strings.ToLower(name), ".db") {
		return "", errCode("invalid_backup", "备份名称无效", false)
	}
	path := filepath.Join(s.backupDir(), name)
	if _, err := os.Stat(path); err != nil {
		return "", errCode("backup_not_found", "备份不存在", false)
	}
	return path, nil
}

func (s *FileStore) RestoreBackup(name string) error {
	path, err := s.BackupPath(name)
	if err != nil {
		return err
	}
	if _, err := s.CreateBackup("before-restore"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tmp := s.dbPath + ".restore.tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	rollback := s.dbPath + ".restore.rollback"
	_ = os.Remove(rollback)
	if err := os.Rename(s.dbPath, rollback); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.dbPath); err != nil {
		_ = os.Rename(rollback, s.dbPath)
		return err
	}
	_ = os.Remove(rollback)
	_ = os.Remove(s.dbPath + "-wal")
	_ = os.Remove(s.dbPath + "-shm")
	found, err := s.loadSQLiteLocked()
	if err != nil {
		return err
	}
	if !found {
		return errCode("invalid_backup", "备份中没有有效状态", false)
	}
	s.state.WebSessions = nil
	return s.saveSQLiteLocked()
}

func (s *FileStore) PruneBackups(keep int) int {
	if keep < 1 {
		keep = 1
	}
	rows, _ := s.Backups()
	removed := 0
	for _, row := range rows[keep:] {
		if os.Remove(filepath.Join(s.backupDir(), row.Name)) == nil {
			removed++
		}
	}
	return removed
}
