package app

import "time"

type RuntimeMetric struct {
	Kind        string  `json:"kind"`
	Total       int64   `json:"total"`
	Success     int64   `json:"success"`
	Failure     int64   `json:"failure"`
	SuccessRate float64 `json:"success_rate"`
	FailureRate float64 `json:"failure_rate"`
	AverageMS   int64   `json:"average_ms"`
	MaxMS       int64   `json:"max_ms"`
	LastMS      int64   `json:"last_ms"`
	LastOK      bool    `json:"last_ok"`
	LastMessage string  `json:"last_message"`
	LastAt      string  `json:"last_at"`
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
	_, err = db.Exec(`INSERT INTO runtime_metrics(kind,total,success,failure,duration_ms,max_duration_ms,last_duration_ms,last_ok,last_message,last_at) VALUES(?,1,?,?,?, ?,?,?,?,?) ON CONFLICT(kind) DO UPDATE SET total=total+1,success=success+excluded.success,failure=failure+excluded.failure,duration_ms=duration_ms+excluded.duration_ms,max_duration_ms=max(max_duration_ms,excluded.max_duration_ms),last_duration_ms=excluded.last_duration_ms,last_ok=excluded.last_ok,last_message=excluded.last_message,last_at=excluded.last_at`, kind, success, failure, ms, ms, ms, lastOK, message, time.Now().Format(time.RFC3339Nano))
	return err
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
	return out, rows.Err()
}
