package app

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginGuardUsesUsernameAndIPDimensionsWithBackoff(t *testing.T) {
	g := newLoginGuard(Config{LoginRateLimitPerIP: 5, LoginRateLimitPerUsername: 5, LoginRateLimitWindowSeconds: 600, LoginBackoffMaxSeconds: 600})
	now := time.Unix(100, 0)
	g.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		if retry := g.failure("192.0.2.1", "Alice"); retry != 0 {
			t.Fatalf("failure %d retry=%s", i+1, retry)
		}
	}
	if retry := g.failure("192.0.2.1", "Alice"); retry != 10*time.Minute {
		t.Fatalf("fifth failure retry=%s", retry)
	}
	if allowed, retry := g.allow("192.0.2.99", "alice"); allowed || retry <= 0 {
		t.Fatalf("username dimension allowed=%v retry=%s", allowed, retry)
	}
	if allowed, retry := g.allow("192.0.2.1", "bob"); allowed || retry <= 0 {
		t.Fatalf("IP dimension allowed=%v retry=%s", allowed, retry)
	}
	now = now.Add(10 * time.Minute)
	g.success("192.0.2.99", "alice")
	if allowed, _ := g.allow("192.0.2.99", "alice"); !allowed {
		t.Fatal("successful login did not clear username backoff")
	}
}

func TestRegistrationCanBeDisabledAndFirstUserCanBootstrap(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{ConfigPath: "test", RegistrationEnabled: false}, store, discardLogger())
	firstCookie, _ := registerTestUser(t, handler, "admin", "secret1")
	if firstCookie == nil {
		t.Fatal("first administrator was not registered")
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`{"username":"alice","password":"secret1"}`))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("registration status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRegistrationInviteCode(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{ConfigPath: "test", RegistrationEnabled: true, RegistrationInviteCode: "invite-secret"}, store, discardLogger())
	registerTestUser(t, handler, "admin", "secret1")
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"username":"alice","password":"secret1","invite_code":"wrong"}`, http.StatusForbidden},
		{`{"username":"alice","password":"secret1","invite_code":"invite-secret"}`, http.StatusCreated},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(tc.body))
		handler.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.want, rr.Body.String())
		}
	}
}

func TestSecurityAuditDoesNotLogCredentials(t *testing.T) {
	store := newTestStore(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := NewServer(Config{ConfigPath: "test"}, store, logger)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`{"username":"admin","password":"very-secret"}`))
	handler.ServeHTTP(rr, req)
	if strings.Contains(logs.String(), "very-secret") {
		t.Fatal("audit log contains password")
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["event"] != "register" || entry["audit"] != true {
		t.Fatalf("audit entry=%v", entry)
	}
}

func TestNormalUserCannotCreateInvite(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	registerTestUser(t, handler, "admin", "secret1")
	userCookie, _ := registerTestUser(t, handler, "alice", "secret1")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/invites", strings.NewReader(`{"name":"forbidden","max_uses":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusForbidden {
		t.Fatalf("normal user create invite status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(store.Snapshot().Invites) != 0 {
		t.Fatal("normal user created an invite")
	}
}

func TestExpiredUserCanLoginAndRenewWithNewInvite(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	_, admin := registerTestUser(t, handler, "admin", "secret1")
	userCookie, user := registerTestUser(t, handler, "alice", "secret1")

	store.mu.Lock()
	for i := range store.state.Users {
		if store.state.Users[i].ID == user.ID {
			store.state.Users[i].ExpiresAt = time.Now().Add(-time.Hour)
		}
	}
	if err := store.saveLocked(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"alice","password":"secret1"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expired login status=%d body=%s", rr.Code, rr.Body.String())
	}
	if cookies := rr.Result().Cookies(); len(cookies) > 0 {
		userCookie = cookies[0]
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "account_expired") {
		t.Fatalf("expired status=%d body=%s", rr.Code, rr.Body.String())
	}

	_, codes, err := store.CreateInvites("renew", admin.ID, 1, 1, 30)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/renew-invite", strings.NewReader(`{"invite_code":"`+codes[0]+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("renew status=%d body=%s", rr.Code, rr.Body.String())
	}
	renewed, ok := store.UserByID(user.ID)
	if !ok || !renewed.ExpiresAt.After(time.Now().AddDate(0, 0, 29)) {
		t.Fatalf("renewed user=%+v ok=%v", renewed, ok)
	}
}
