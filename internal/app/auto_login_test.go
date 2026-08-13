package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAutoLoginSecretRoundTrip(t *testing.T) {
	ciphertext, err := encryptAutoSecret("server-secret", "apple-password")
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == "apple-password" {
		t.Fatal("password was not encrypted")
	}
	plain, err := decryptAutoSecret("server-secret", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "apple-password" {
		t.Fatalf("plain = %q", plain)
	}
	if _, err := decryptAutoSecret("wrong-secret", ciphertext); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestValidateAutoCodeURLRejectsUnsafeTargets(t *testing.T) {
	for _, raw := range []string{"http://example.com/code", "https://127.0.0.1/code", "https://localhost/code"} {
		if _, err := validateAutoCodeURL(raw); err == nil {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}

func TestSMSCodePattern(t *testing.T) {
	code, err := extractAppleVerificationCode([]byte("【Apple】验证码为 691288，请勿泄露"))
	if err != nil || code != "691288" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}

func TestAppleCodeExtractionIgnoresEarlierFourDigitNumber(t *testing.T) {
	code, err := extractAppleVerificationCode([]byte("短信编号 2026；【Apple】您的验证码是 691288，请勿泄露"))
	if err != nil || code != "691288" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}

func TestAppleCodeExtractionSupportsNestedJSONAndFullWidthDigits(t *testing.T) {
	for _, test := range []struct {
		body string
		want string
	}{
		{`{"status":200,"data":{"verification_code":"042817"}}`, "042817"},
		{`{"code":200,"message":"Apple verification code: 817204"}`, "817204"},
		{`{"data":[{"message":"old"},{"message":"验证码：６９１２８８"}]}`, "691288"},
		{`【Apple】Your verification code is 123-456.`, "123456"},
	} {
		code, err := extractAppleVerificationCode([]byte(test.body))
		if err != nil || code != test.want {
			t.Errorf("body=%q code=%q err=%v want=%q", test.body, code, err, test.want)
		}
	}
}

func TestAppleCodeExtractionRejectsFourDigitAndAmbiguousResponses(t *testing.T) {
	for _, body := range []string{
		`【Apple】验证码是 1234`,
		`{"code":"1234"}`,
		`候选记录 123456，另一条 654321`,
	} {
		if code, err := extractAppleVerificationCode([]byte(body)); err == nil {
			t.Errorf("body=%q unexpectedly returned %q", body, code)
		}
	}
}

func TestDisableAutoLoginAllowsBlankBinding(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{AutoLoginSecret: "test-secret"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "auto-pause-user", "secret1")
	session := ICloudSession{OwnerID: user.ID, AccountID: "account-1", AppleID: "apple@example.com"}
	if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
		t.Fatal(err)
	}
	original := AutoLoginBinding{
		OwnerID:        user.ID,
		AccountID:      session.AccountID,
		AppleID:        session.AppleID,
		PasswordCipher: "saved-password",
		PhoneCipher:    "saved-phone",
		URLCipher:      "saved-url",
		Enabled:        true,
		Status:         "自动登录中",
		UpdatedAt:      time.Now(),
	}
	if err := store.SaveAutoLoginBinding(original); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/auto-login/bind", strings.NewReader(`{"account_id":"account-1","binding":"","password":"","enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got, ok := store.AutoLoginBinding(user.ID, session.AccountID)
	if !ok || got.Enabled {
		t.Fatalf("binding=%+v found=%t, want paused", got, ok)
	}
	if got.Status != "已暂停自动接码登录" || got.PasswordCipher != original.PasswordCipher || got.URLCipher != original.URLCipher {
		t.Fatalf("paused binding=%+v", got)
	}
}

func TestAutoLoginProgressCannotReenablePausedBinding(t *testing.T) {
	store := newTestStore(t)
	binding := AutoLoginBinding{OwnerID: "owner", AccountID: "account", Enabled: true, Status: "自动登录中"}
	if err := store.SaveAutoLoginBinding(binding); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.SetAutoLoginBindingEnabled(binding.OwnerID, binding.AccountID, false); err != nil || !found {
		t.Fatalf("pause found=%t err=%v", found, err)
	}
	binding.Status = "自动登录失败"
	binding.LastError = "stale attempt"
	if saved, err := store.SaveAutoLoginProgress(binding); err != nil || saved {
		t.Fatalf("progress saved=%t err=%v, want ignored", saved, err)
	}
	got, _ := store.AutoLoginBinding(binding.OwnerID, binding.AccountID)
	if got.Enabled || got.Status != "已暂停自动接码登录" || got.LastError != "" {
		t.Fatalf("paused binding overwritten: %+v", got)
	}
}

func TestICloudWebTemporaryErrorsDoNotTriggerAutoLogin(t *testing.T) {
	for _, status := range []string{"429", "423", "502", "503", "504"} {
		err := errCode("icloud_validate_failed", "iCloud 登录态校验失败，HTTP "+status, true)
		if shouldTriggerICloudWebAutoLogin(err) {
			t.Fatalf("HTTP %s must not trigger automatic login", status)
		}
	}
	for _, err := range []error{
		errCode("icloud_validate_failed", "iCloud 登录态校验失败，HTTP 401", true),
		errCode("icloud_session_missing", "missing", true),
	} {
		if !shouldTriggerICloudWebAutoLogin(err) {
			t.Fatalf("explicit session failure should trigger automatic login: %v", err)
		}
	}
}
