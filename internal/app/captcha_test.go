package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestCaptchaIsOneTimeAndExpiresFromStoreAfterVerify(t *testing.T) {
	store := newCaptchaStore()
	id, svg, err := store.create()
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`>([23456789A-Z]{5})</text>`).FindStringSubmatch(svg)
	if len(match) != 2 {
		t.Fatalf("captcha code not rendered in svg")
	}
	if !store.verify(id, match[1]) {
		t.Fatal("valid captcha rejected")
	}
	if store.verify(id, match[1]) {
		t.Fatal("captcha could be reused")
	}
}

func TestCaptchaHTTPLoginFlow(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.CreateUser("admin", "secret1"); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{LoginCaptchaEnabled: true}, store, discardLogger())
	challengeRR := httptest.NewRecorder()
	handler.ServeHTTP(challengeRR, httptest.NewRequest(http.MethodGet, "/api/auth/captcha", nil))
	var challenge struct {
		CaptchaID string `json:"captcha_id"`
		ImageURL  string `json:"image_url"`
	}
	if err := json.Unmarshal(challengeRR.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	imageRR := httptest.NewRecorder()
	handler.ServeHTTP(imageRR, httptest.NewRequest(http.MethodGet, challenge.ImageURL, nil))
	match := regexp.MustCompile(`>([23456789A-Z]{5})</text>`).FindStringSubmatch(imageRR.Body.String())
	if len(match) != 2 {
		t.Fatal("captcha not found in image")
	}
	body := `{"username":"admin","password":"secret1","captcha_id":"` + challenge.CaptchaID + `","captcha_code":"` + match[1] + `"}`
	loginRR := httptest.NewRecorder()
	handler.ServeHTTP(loginRR, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body)))
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login=%d body=%s id=%q code=%q", loginRR.Code, loginRR.Body.String(), challenge.CaptchaID, match[1])
	}
}
