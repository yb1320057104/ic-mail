# MySQL 存储与回滚

服务默认继续支持 SQLite。通过环境变量启用 MySQL：

```ini
IPM_STORAGE_DRIVER=mysql
IPM_MYSQL_DSN=user:password@tcp(127.0.0.1:3306)/database?charset=utf8mb4&parseTime=true
```

MySQL 业务表统一使用 `ipm_` 前缀。服务会创建同名兼容视图，以便存量 SQL 访问这些前缀表。SQLite 的 FTS5 索引不会迁移；首次切换后由服务在 MySQL 中异步重建邮件搜索索引。

## 迁移

迁移期间应停止服务，以保证 SQLite 快照一致：

```bash
go run ./cmd/migrate-mysql \
  -replace \
  -sqlite /path/to/state.db \
  -mysql 'user:password@tcp(host:3306)/database?charset=utf8mb4&parseTime=true'
```

`-replace` 只清空工具内置白名单中的 `ipm_` 表，不会修改同一数据库中的其它业务表。没有 `-replace` 时迁移使用 `INSERT IGNORE`，适合首次预迁移，不适合最终同步更新。

## 回滚

1. 停止服务。
2. 移除或覆盖 systemd 中的 MySQL 环境变量，将 `IPM_STORAGE_DRIVER` 改回 `sqlite`。
3. 恢复切换前的二进制（如需要）。
4. 确认 `data_path` 对应的 `state.db` 未被覆盖。
5. 执行 `systemctl daemon-reload` 并重新启动服务。

MySQL 模式不会继续写入 SQLite 文件，因此切换前保存的 `state.db` 是稳定的回滚点。MySQL 模式下，面板内的 SQLite 备份/恢复操作会返回明确提示；数据库备份应使用 MySQL 原生备份工具。
