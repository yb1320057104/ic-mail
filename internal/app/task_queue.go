package app

import (
	"time"
)

func (s *FileStore) SaveTaskRun(task operationTask) error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO task_runs(id,kind,status,progress,message,started_at,finished_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,progress=excluded.progress,message=excluded.message,finished_at=excluded.finished_at`, task.ID, task.Kind, task.Status, 100, task.Message, task.StartedAt, task.FinishedAt)
	return err
}

func (s *FileStore) TaskRuns(limit int) ([]operationTask, error) {
	if limit < 1 {
		limit = 100
	}
	db, err := s.sqliteConnection()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id,kind,status,message,started_at,finished_at FROM task_runs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []operationTask{}
	for rows.Next() {
		var v operationTask
		if err := rows.Scan(&v.ID, &v.Kind, &v.Status, &v.Message, &v.StartedAt, &v.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *FileStore) RecoverInterruptedTasks() error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`UPDATE task_runs SET status='interrupted',message=CASE WHEN message='' THEN '服务重启，任务已中断' ELSE message||'；服务重启，任务已中断' END,finished_at=? WHERE status IN ('running','queued')`, formatTime(time.Now()))
	return err
}
