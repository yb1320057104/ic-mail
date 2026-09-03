#!/usr/bin/env bash
set -Eeuo pipefail

project=${PROJECT_DIR:-/data/iCloud-Privacy-Mail}
service=${SERVICE_NAME:-icloud-privacy-mail}
mysql_cnf=${MYSQL_CNF:-$project/private/mysql-cutover.cnf}
mysql_env=${MYSQL_ENV:-$project/private/mysql.env}
panel_new=${PANEL_NEW:-/tmp/panel-latest}
migrator=${MIGRATOR:-/tmp/migrate-mysql-final}
dropin_dir=/etc/systemd/system/${service}.service.d
dropin=$dropin_dir/mysql.conf
stamp=$(date +%Y%m%d-%H%M%S)
backup=$project/backups/mysql-cutover-$stamp
success=0

rollback() {
  rc=$?
  if [[ $success -eq 0 ]]; then
    echo "CUTOVER_FAILED rc=$rc; restoring SQLite service" >&2
    rm -f "$dropin"
    if [[ -f $backup/panel ]]; then
      install -o icmail -g icmail -m 0750 "$backup/panel" "$project/panel"
    fi
    systemctl daemon-reload || true
    systemctl restart "$service" || true
  fi
  exit "$rc"
}
trap rollback ERR

test -x "$panel_new"
test -x "$migrator"
test -r "$mysql_cnf"
test -r "$mysql_env"
mkdir -p "$backup" "$dropin_dir"

# Preserve the pre-cutover MySQL snapshot and the authoritative SQLite files.
mysqldump --defaults-extra-file="$mysql_cnf" --single-transaction --quick --no-tablespaces mail \
  ipm_app_state ipm_messages ipm_backups ipm_task_runs ipm_runtime_metrics \
  ipm_runtime_metric_events ipm_state_meta ipm_users ipm_web_sessions \
  ipm_accounts ipm_mailboxes ipm_icloud_sessions ipm_create_settings \
  ipm_invites ipm_invite_uses ipm_audit_events ipm_announcements \
  ipm_announcement_reads ipm_auto_login_bindings ipm_auto_login_logs \
  ipm_user_proxy_configs ipm_redemption_pools ipm_redemption_codes \
  ipm_redemption_items ipm_redemption_orders ipm_recycle_bin \
  ipm_message_search_v3 | gzip -1 >"$backup/mysql-before.sql.gz"

systemctl stop "$service"
cp --reflink=auto "$project/data/state.db" "$backup/state.db"
cp --reflink=auto "$project/data/state.json" "$backup/state.json"
cp "$project/config.json" "$backup/config.json"
cp "$project/panel" "$backup/panel"

dsn=$(sed -n 's/^IPM_MYSQL_DSN=//p' "$mysql_env")
test -n "$dsn"
"$migrator" -replace -sqlite "$project/data/state.db" -mysql "$dsn"

# The SQLite FTS table is not portable. Force a clean asynchronous rebuild.
mysql --defaults-extra-file="$mysql_cnf" mail -e \
  "DELETE FROM ipm_state_meta WHERE \`key\`='message_search_version'; TRUNCATE TABLE ipm_message_search_v3;"

sqlite3 "$project/data/state.db" \
  "SELECT 'sqlite', (SELECT count(*) FROM users), (SELECT count(*) FROM accounts), (SELECT count(*) FROM mailboxes), (SELECT count(*) FROM messages);"
mysql --defaults-extra-file="$mysql_cnf" -N mail -e \
  "SELECT 'mysql',(SELECT count(*) FROM ipm_users),(SELECT count(*) FROM ipm_accounts),(SELECT count(*) FROM ipm_mailboxes),(SELECT count(*) FROM ipm_messages);"

install -o icmail -g icmail -m 0750 "$panel_new" "$project/panel"
printf '[Service]\nEnvironmentFile=%s\n' "$mysql_env" >"$dropin"
systemctl daemon-reload
systemctl start "$service"

for _ in $(seq 1 60); do
  if systemctl is-active --quiet "$service" && curl -fsS http://127.0.0.1:8787/login >/dev/null; then
    success=1
    echo "MYSQL_CUTOVER_OK backup=$backup"
    break
  fi
  sleep 1
done
test "$success" -eq 1
trap - ERR
