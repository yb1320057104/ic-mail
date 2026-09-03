package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"icloud-privacy-mail/internal/app"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: storage-smoke /path/to/config.json")
	}
	cfg, err := app.LoadConfig(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if cfg.StorageDriver != "mysql" || cfg.MySQLDSN == "" {
		log.Fatal("config must select mysql and provide mysql_dsn")
	}
	store, err := app.NewConfiguredFileStore(cfg)
	if err != nil {
		log.Fatal(err)
	}
	state := store.Snapshot()
	if len(state.Users) == 0 || len(state.Mailboxes) == 0 {
		log.Fatalf("unexpected empty state: users=%d mailboxes=%d messages=%d", len(state.Users), len(state.Mailboxes), len(state.Messages))
	}
	if err := store.RecordRuntimeMetric("mysql_storage_smoke", true, time.Millisecond, "storage smoke test"); err != nil {
		log.Fatal(err)
	}
	metrics, err := store.RuntimeMetrics()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("MYSQL_STORAGE_OK users=%d accounts=%d mailboxes=%d messages=%d metrics=%d\n", len(state.Users), len(state.Accounts), len(state.Mailboxes), len(state.Messages), len(metrics))
}
