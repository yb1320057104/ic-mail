package app

import (
	"database/sql"
	"time"
)

type RuntimeMetric struct {
	Kind        string       `json:"kind"`
	Total       int64        `json:"total"`
	Success     int64        `json:"success"`
	Failure     int64        `json:"failure"`
	SuccessRate float64      `json:"success_rate"`
	FailureRate float64      `json:"failure_rate"`
	AverageMS   int64        `json:"average_ms"`
	MaxMS       int64        `json:"max_ms"`
	LastMS      int64        `json:"last_ms"`
	LastOK      bool         `json:"last_ok"`
	LastMessage string       `json:"last_message"`
	LastAt      string       `json:"last_at"`
	Last5M      MetricWindow `json:"last_5m"`
	Last1H      MetricWindow `json:"last_1h"`
	Last24H     MetricWindow `json:"last_24h"`
}

type MetricWindow struct {
	Total       int64   `json:"total"`
	SuccessRate float64 `json:"success_rate"`
	FailureRate float64 `json:"failure_rate"`
	AverageMS   int64   `json:"average_ms"`
	P95MS       int64   `json:"p95_ms"`
}

func (s *FileStore) RecordRuntimeMetric(kind string, ok bool, duration time.Duration, message string) error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	success, failure := 0, 1
	if ok {
		success, failure = 1, 0
	}
	ms := duration.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	lastOK := 0
	if ok {
		lastOK = 1
	}
	now := time.Now().Format(time.RFC3339Nano)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO runtime_metrics(kind,total,success,failure,duration_ms,max_duration_ms,last_duration_ms,last_ok,last_message,last_at) VALUES(?,1,?,?,?, ?,?,?,?,?) ON CONFLICT(kind) DO UPDATE SET total=total+1,success=success+excluded.success,failure=failure+excluded.failure,duration_ms=duration_ms+excluded.duration_ms,max_duration_ms=max(max_duration_ms,excluded.max_duration_ms),last_duration_ms=excluded.last_duration_ms,last_ok=excluded.last_ok,last_message=excluded.last_message,last_at=excluded.last_at`, kind, success, failure, ms, ms, ms, lastOK, message, now); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err = tx.Exec(`INSERT INTO runtime_metric_events(kind,ok,duration_ms,message,created_at) VALUES(?,?,?,?,?)`, kind, lastOK, ms, message, now); err != nil {
		_ = tx.Rollback()
		return err
	}
	_, _ = tx.Exec(`DELETE FROM runtime_metric_events WHERE created_at < ?`, time.Now().Add(-30*24*time.Hour).Format(time.RFC3339Nano))
	return tx.Commit()
}

func (s *FileStore) RuntimeMetrics() ([]RuntimeMetric, error) {
	db, err := s.sqliteConnection()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT kind,total,success,failure,duration_ms,max_duration_ms,last_duration_ms,last_ok,last_message,last_at FROM runtime_metrics ORDER BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuntimeMetric
	for rows.Next() {
		var row RuntimeMetric
		var duration, lastOK int64
		if err := rows.Scan(&row.Kind, &row.Total, &row.Success, &row.Failure, &duration, &row.MaxMS, &row.LastMS, &lastOK, &row.LastMessage, &row.LastAt); err != nil {
			return nil, err
		}
		row.LastOK = lastOK == 1
		if row.Total > 0 {
			row.SuccessRate = float64(row.Success) * 100 / float64(row.Total)
			row.FailureRate = float64(row.Failure) * 100 / float64(row.Total)
			row.AverageMS = duration / row.Total
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()
	for i := range out {
		out[i].Last5M = metricWindow(db, out[i].Kind, 5*time.Minute)
		out[i].Last1H = metricWindow(db, out[i].Kind, time.Hour)
		out[i].Last24H = metricWindow(db, out[i].Kind, 24*time.Hour)
	}
	return out, nil
}

func metricWindow(db interface {
	Query(string, ...any) (*sql.Rows, error)
}, kind string, d time.Duration) MetricWindow {
	rows, err := db.Query(`SELECT ok,duration_ms FROM runtime_metric_events WHERE kind=? AND created_at>=? ORDER BY duration_ms`, kind, time.Now().Add(-d).Format(time.RFC3339Nano))
	if err != nil {
		return MetricWindow{}
	}
	defer rows.Close()
	var durations []int64
	var success int64
	for rows.Next() {
		var ok, ms int64
		if rows.Scan(&ok, &ms) == nil {
			durations = append(durations, ms)
			success += ok
		}
	}
	w := MetricWindow{Total: int64(len(durations))}
	if w.Total == 0 {
		return w
	}
	var sum int64
	for _, v := range durations {
		sum += v
	}
	w.AverageMS = sum / w.Total
	w.SuccessRate = float64(success) * 100 / float64(w.Total)
	w.FailureRate = 100 - w.SuccessRate
	idx := int(float64(len(durations)-1) * .95)
	w.P95MS = durations[idx]
	return w
}
