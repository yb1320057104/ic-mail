// migrate-mysql copies the application's SQLite database to MySQL without
// interpreting payloads. It is intentionally resumable and never deletes
// destination rows. Run it while the application is stopped.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	_ "modernc.org/sqlite"
	"strings"
)

var tables = []string{"app_state", "messages", "backups", "task_runs", "runtime_metrics", "runtime_metric_events", "state_meta", "users", "web_sessions", "accounts", "mailboxes", "icloud_sessions", "create_settings", "invites", "invite_uses", "audit_events", "announcements", "announcement_reads", "auto_login_bindings", "auto_login_logs", "user_proxy_configs", "redemption_pools", "redemption_codes", "redemption_items", "redemption_orders", "recycle_bin"}

const tablePrefix = "ipm_"

func main() {
	src := flag.String("sqlite", "data/state.db", "SQLite database path")
	dsn := flag.String("mysql", "", "MySQL DSN (user:pass@tcp(host:3306)/db?parseTime=true)")
	replace := flag.Bool("replace", false, "truncate only ipm_ target tables before copying")
	flag.Parse()
	if strings.TrimSpace(*dsn) == "" {
		log.Fatal("-mysql is required")
	}
	s, err := sql.Open("sqlite", *src)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	d, err := sql.Open("mysql", *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer d.Close()
	if err = d.Ping(); err != nil {
		log.Fatal(err)
	}
	if err = ensureSchema(s, d); err != nil {
		log.Fatal(err)
	}
	if *replace {
		if err = truncateTarget(d); err != nil {
			log.Fatal(err)
		}
	}
	for _, t := range tables {
		if err = copyTable(s, d, t); err != nil {
			log.Fatalf("%s: %v", t, err)
		}
	}
	log.Println("SQLite to MySQL migration completed")
}

func truncateTarget(d *sql.DB) error {
	for _, t := range append(append([]string(nil), tables...), "message_search_v3") {
		if _, err := d.Exec("TRUNCATE TABLE `" + tablePrefix + t + "`"); err != nil {
			// message_search_v3 belongs to the MySQL runtime and may not exist on
			// a first migration. Every source-backed table must exist.
			if t == "message_search_v3" {
				continue
			}
			return fmt.Errorf("truncate %s: %w", t, err)
		}
	}
	log.Println("target ipm_ tables truncated")
	return nil
}

func ensureSchema(s, d *sql.DB) error {
	for _, t := range tables {
		rows, err := s.Query("PRAGMA table_info(`" + t + "`)")
		if err != nil {
			return err
		}
		var defs []string
		for rows.Next() {
			var cid int
			var name, typ string
			var notnull, pk int
			var def any
			if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
				rows.Close()
				return err
			}
			mt := "LONGBLOB"
			u := strings.ToUpper(typ)
			if strings.Contains(u, "INT") {
				mt = "BIGINT"
			} else if strings.Contains(u, "CHAR") || strings.Contains(u, "TEXT") {
				mt = "LONGTEXT"
			}
			// MySQL requires a key length for TEXT/BLOB columns. SQLite uses
			// TEXT primary keys throughout this application, so map key columns
			// to a bounded VARCHAR while leaving non-key payloads lossless.
			if pk != 0 && mt == "LONGTEXT" {
				mt = "VARCHAR(255)"
			}
			null := ""
			if notnull != 0 || pk != 0 {
				null = " NOT NULL"
			}
			defs = append(defs, fmt.Sprintf("`%s` %s%s", name, mt, null))
		}
		rows.Close()
		if len(defs) == 0 {
			continue
		}
		pk := ""
		if len(defs) > 0 {
			pk = ", PRIMARY KEY (`" + strings.Split(defs[0], "`")[1] + "`)"
		}
		q := fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s%s` (%s%s) ENGINE=InnoDB", tablePrefix, t, strings.Join(defs, ","), pk)
		if _, err := d.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func copyTable(s, d *sql.DB, t string) error {
	rows, err := s.Query("SELECT * FROM `" + t + "`")
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	marks := make([]string, len(cols))
	for i := range marks {
		marks[i] = "?"
	}
	rowSQL := "(" + strings.Join(marks, ",") + ")"
	columnSQL := "`" + tablePrefix + t + "` (`" + strings.Join(cols, "`,`") + "`)"
	const batchSize = 200
	batchArgs := make([]any, 0, batchSize*len(cols))
	batchRows := 0
	n := 0
	flush := func() error {
		if batchRows == 0 {
			return nil
		}
		rowsSQL := make([]string, batchRows)
		for i := range rowsSQL {
			rowsSQL[i] = rowSQL
		}
		q := "INSERT IGNORE INTO " + columnSQL + " VALUES " + strings.Join(rowsSQL, ",")
		if _, err := d.Exec(q, batchArgs...); err != nil {
			return err
		}
		batchArgs = batchArgs[:0]
		batchRows = 0
		return nil
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptr := make([]any, len(cols))
		for i := range vals {
			ptr[i] = &vals[i]
		}
		if err = rows.Scan(ptr...); err != nil {
			return err
		}
		batchArgs = append(batchArgs, vals...)
		batchRows++
		n++
		if batchRows >= batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}
	log.Printf("%s: %d rows", t, n)
	return nil
}
