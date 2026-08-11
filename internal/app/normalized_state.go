package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type normalizedRow struct {
	id, owner string
	value     any
}

func replaceNormalizedRows(tx *sql.Tx, table string, rows []normalizedRow, now string) error {
	if _, err := tx.Exec("DELETE FROM " + table); err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO " + table + "(id,owner_id,payload,updated_at) VALUES(?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, row := range rows {
		raw, err := json.Marshal(row.value)
		if err != nil {
			return err
		}
		if _, err = stmt.Exec(row.id, row.owner, raw, now); err != nil {
			return err
		}
	}
	return nil
}

func loadNormalizedRows[T any](db *sql.DB, table string) ([]T, error) {
	rows, err := db.Query("SELECT payload FROM " + table + " ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var value T
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("decode %s: %w", table, err)
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *FileStore) loadNormalizedStateLocked(db *sql.DB) (bool, error) {
	var version string
	if err := db.QueryRow(`SELECT value FROM state_meta WHERE key='schema_version'`).Scan(&version); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if version != "2" {
		return false, nil
	}
	var next string
	if err := db.QueryRow(`SELECT value FROM state_meta WHERE key='next_id'`).Scan(&next); err != nil {
		return false, err
	}
	n, _ := strconv.Atoi(next)
	s.state = State{NextID: max(1, n)}
	var err error
	if s.state.Users, err = loadNormalizedRows[User](db, "users"); err != nil {
		return false, err
	}
	if s.state.WebSessions, err = loadNormalizedRows[WebSession](db, "web_sessions"); err != nil {
		return false, err
	}
	if s.state.Accounts, err = loadNormalizedRows[Account](db, "accounts"); err != nil {
		return false, err
	}
	if s.state.Mailboxes, err = loadNormalizedRows[Mailbox](db, "mailboxes"); err != nil {
		return false, err
	}
	if s.state.ICloudSessions, err = loadNormalizedRows[ICloudSession](db, "icloud_sessions"); err != nil {
		return false, err
	}
	if s.state.CreateSettings, err = loadNormalizedRows[CreateSettings](db, "create_settings"); err != nil {
		return false, err
	}
	if s.state.Invites, err = loadNormalizedRows[InviteCode](db, "invites"); err != nil {
		return false, err
	}
	if s.state.InviteUses, err = loadNormalizedRows[InviteUse](db, "invite_uses"); err != nil {
		return false, err
	}
	if s.state.AuditEvents, err = loadNormalizedRows[AuditEvent](db, "audit_events"); err != nil {
		return false, err
	}
	if s.state.Announcements, err = loadNormalizedRows[Announcement](db, "announcements"); err != nil {
		return false, err
	}
	if s.state.AnnouncementReads, err = loadNormalizedRows[AnnouncementRead](db, "announcement_reads"); err != nil {
		return false, err
	}
	if s.state.AutoLoginBindings, err = loadNormalizedRows[AutoLoginBinding](db, "auto_login_bindings"); err != nil {
		return false, err
	}
	if s.state.RedemptionPools, err = loadNormalizedRows[RedemptionPool](db, "redemption_pools"); err != nil {
		return false, err
	}
	if s.state.RedemptionCodes, err = loadNormalizedRows[RedemptionCode](db, "redemption_codes"); err != nil {
		return false, err
	}
	if s.state.RedemptionItems, err = loadNormalizedRows[RedemptionItem](db, "redemption_items"); err != nil {
		return false, err
	}
	if s.state.RecycleBin, err = loadNormalizedRows[RecycleBinItem](db, "recycle_bin"); err != nil {
		return false, err
	}
	return true, nil
}

func (s *FileStore) saveNormalizedStateTx(tx *sql.Tx, now string) error {
	rows := func(values ...normalizedRow) []normalizedRow { return values }
	_ = rows
	sets := []struct {
		table string
		rows  []normalizedRow
	}{
		{"users", mapRows(s.state.Users, func(v User) (string, string) { return v.ID, v.ID })}, {"web_sessions", mapRows(s.state.WebSessions, func(v WebSession) (string, string) { return v.TokenHash, v.UserID })},
		{"accounts", mapRows(s.state.Accounts, func(v Account) (string, string) { return v.ID, v.OwnerID })}, {"mailboxes", mapRows(s.state.Mailboxes, func(v Mailbox) (string, string) { return v.ID, v.OwnerID })},
		{"icloud_sessions", mapRows(s.state.ICloudSessions, func(v ICloudSession) (string, string) { return v.OwnerID + ":" + v.AccountID, v.OwnerID })}, {"create_settings", mapRows(s.state.CreateSettings, func(v CreateSettings) (string, string) { return v.OwnerID, v.OwnerID })},
		{"invites", mapRows(s.state.Invites, func(v InviteCode) (string, string) { return v.ID, v.CreatedBy })}, {"invite_uses", mapRows(s.state.InviteUses, func(v InviteUse) (string, string) { return v.InviteID + ":" + v.UserID, v.UserID })},
		{"audit_events", mapRows(s.state.AuditEvents, func(v AuditEvent) (string, string) { return v.ID, v.ActorID })}, {"announcements", mapRows(s.state.Announcements, func(v Announcement) (string, string) { return v.ID, v.CreatedBy })},
		{"announcement_reads", mapRows(s.state.AnnouncementReads, func(v AnnouncementRead) (string, string) { return v.AnnouncementID + ":" + v.UserID, v.UserID })}, {"auto_login_bindings", mapRows(s.state.AutoLoginBindings, func(v AutoLoginBinding) (string, string) { return v.OwnerID + ":" + v.AccountID, v.OwnerID })},
		{"redemption_pools", mapRows(s.state.RedemptionPools, func(v RedemptionPool) (string, string) { return v.ID, v.OwnerID })}, {"redemption_codes", mapRows(s.state.RedemptionCodes, func(v RedemptionCode) (string, string) { return v.ID, v.OwnerID })},
		{"redemption_items", mapRows(s.state.RedemptionItems, func(v RedemptionItem) (string, string) { return v.PoolID + ":" + v.MailboxID, v.OwnerID })}, {"recycle_bin", mapRows(s.state.RecycleBin, func(v RecycleBinItem) (string, string) { return v.ID, v.UserID })},
	}
	for _, set := range sets {
		if err := replaceNormalizedRows(tx, set.table, set.rows, now); err != nil {
			return fmt.Errorf("save %s: %w", set.table, err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO state_meta(key,value) VALUES('schema_version','2') ON CONFLICT(key) DO UPDATE SET value='2'`); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO state_meta(key,value) VALUES('next_id',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, strconv.Itoa(s.state.NextID))
	return err
}

func mapRows[T any](values []T, key func(T) (string, string)) []normalizedRow {
	out := make([]normalizedRow, 0, len(values))
	for _, v := range values {
		id, owner := key(v)
		out = append(out, normalizedRow{id: id, owner: owner, value: v})
	}
	return out
}

func normalizedNow() string { return time.Now().Format(time.RFC3339Nano) }
