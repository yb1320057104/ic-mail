package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAutoLoginLogsAreAccountScopedEncryptedAndLimited(t *testing.T) {
	store := newTestStore(t)
	secret := "auto-login-log-test-secret"
	handler := NewServer(Config{PublicBaseURL: "https://mail.example", AutoLoginSecret: secret}, store, discardLogger())
	server := handler.(*Server)
	_, _ = registerTestUser(t, handler, "admin", "admin123")
	ownerCookie, owner := registerTestUser(t, handler, "log-owner", "log-owner-123")
	otherCookie, _ := registerTestUser(t, handler, "log-other", "log-other-123")
	account, err := store.AddAccountForOwner(owner.ID, "Log Apple", "log@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(owner.ID, ICloudSession{
		OwnerID: owner.ID, AccountID: account.ID, AppleID: "log@example.com", SavedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	codeCipher, err := encryptAutoSecret(secret, "691288")
	if err != nil {
		t.Fatal(err)
	}
	binding := AutoLoginBinding{
		OwnerID: owner.ID, AccountID: account.ID, AppleID: "log@example.com", Enabled: true,
		Logs: []AutoLoginAttemptLog{{
			ID: "attempt-1", Trigger: "新接口登录态失效", Status: "success", StartedAt: time.Now(), FinishedAt: time.Now(),
			Steps: []AutoLoginLogStep{{
				At: time.Now(), Stage: "收到验证码", Level: "success", Message: "已获得短信验证码",
				CodeMasked: "69****", CodeCipher: codeCipher,
			}},
		}},
	}
	if err := store.SaveAutoLoginBinding(binding); err != nil {
		t.Fatal(err)
	}

	requestLogs := func(cookie *http.Cookie, reveal bool) *httptest.ResponseRecorder {
		revealValue := "false"
		if reveal {
			revealValue = "true"
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/icloud/auto-login/logs", strings.NewReader(
			`{"account_id":"`+account.ID+`","reveal_codes":`+revealValue+`}`,
		))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		return rr
	}

	masked := requestLogs(ownerCookie, false)
	if masked.Code != http.StatusOK || !strings.Contains(masked.Body.String(), "69****") ||
		strings.Contains(masked.Body.String(), "691288") || strings.Contains(masked.Body.String(), codeCipher) {
		t.Fatalf("masked logs=%d body=%s", masked.Code, masked.Body.String())
	}
	revealed := requestLogs(ownerCookie, true)
	if revealed.Code != http.StatusOK || !strings.Contains(revealed.Body.String(), "691288") ||
		strings.Contains(revealed.Body.String(), codeCipher) {
		t.Fatalf("revealed logs=%d body=%s", revealed.Code, revealed.Body.String())
	}
	denied := requestLogs(otherCookie, true)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("other user logs=%d body=%s", denied.Code, denied.Body.String())
	}

	limited := AutoLoginBinding{OwnerID: owner.ID, AccountID: account.ID, AppleID: "log@example.com"}
	for i := 0; i < 12; i++ {
		server.startAutoLoginAttemptLog(&limited, "测试触发")
	}
	if len(limited.Logs) != maxAutoLoginAttemptsPerAccount {
		t.Fatalf("logs=%d want=%d", len(limited.Logs), maxAutoLoginAttemptsPerAccount)
	}
}

func TestAutoLoginLogRedactsURLs(t *testing.T) {
	message := safeAutoLoginLogError(assertLogError(`Get "https://codes.example/path?token=secret": timeout`))
	if strings.Contains(message, "secret") || strings.Contains(message, "codes.example") {
		t.Fatalf("URL not redacted: %s", message)
	}
}

type assertLogError string

func (e assertLogError) Error() string { return string(e) }
