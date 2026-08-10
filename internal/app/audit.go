package app

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status != http.StatusOK {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (s *Server) auditRequest(r *http.Request, status int, elapsed time.Duration) {
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		return
	}
	isAuth := r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/register" || r.URL.Path == "/api/auth/logout"
	isPermissionOperation := r.Method != http.MethodGet || strings.HasPrefix(r.URL.Path, "/api/runtime/export")
	if !isAuth && !isPermissionOperation {
		return
	}

	actorID, actorName, actorRole := "", "", "anonymous"
	if _, user, ok := s.currentWebSession(r); ok {
		actorID, actorName = user.ID, user.Username
		if user.IsAdmin {
			actorRole = "admin"
		} else {
			actorRole = "user"
		}
	}
	level := slog.LevelInfo
	if status >= 400 {
		level = slog.LevelWarn
	}
	s.logger.Log(r.Context(), level, "security audit",
		"audit", true,
		"event", auditEventName(r),
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"success", status < 400,
		"actor_id", actorID,
		"actor", actorName,
		"role", actorRole,
		"client_ip", requestClientIP(r),
		"duration_ms", elapsed.Milliseconds(),
	)
	s.store.AddAuditEvent(AuditEvent{Event: auditEventName(r), Method: r.Method, Path: r.URL.Path, Status: status, Success: status < 400, ActorID: actorID, Actor: actorName, Role: actorRole, ClientIP: requestClientIP(r)})
}

func auditEventName(r *http.Request) string {
	switch r.URL.Path {
	case "/api/auth/login":
		return "login"
	case "/api/auth/register":
		return "register"
	case "/api/auth/logout":
		return "logout"
	case "/api/update/apply":
		return "update_apply"
	case "/api/runtime/export":
		return "runtime_export"
	}
	if strings.HasPrefix(r.URL.Path, "/api/admin/") {
		return "admin_operation"
	}
	return "permission_operation"
}
