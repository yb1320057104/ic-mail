package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var autoLoginLocks sync.Map
var smsCodePattern = regexp.MustCompile(`(?:^|\D)(\d{4,8})(?:\D|$)`)

func encryptAutoSecret(master, plain string) (string, error) {
	if strings.TrimSpace(master) == "" {
		return "", errCode("auto_login_secret_missing", "服务器未配置自动接码加密密钥", false)
	}
	key := sha256.Sum256([]byte(master))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plain), nil)
	return base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func decryptAutoSecret(master, encoded string) (string, error) {
	key := sha256.Sum256([]byte(master))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("自动接码密文损坏")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("自动接码密文无法解密")
	}
	return string(plain), nil
}

func validateAutoCodeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, errCode("auto_code_url_invalid", "接码地址必须是有效的 HTTPS 公网地址", false)
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return nil, errCode("auto_code_url_dns_failed", "接码地址域名解析失败", true)
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return nil, errCode("auto_code_url_private", "接码地址不能指向本机或内网", false)
		}
	}
	return u, nil
}

func fetchAutoCode(ctx context.Context, rawURL string) (string, error) {
	u, err := validateAutoCodeURL(rawURL)
	if err != nil {
		return "", err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				return nil, fmt.Errorf("禁止访问内网地址")
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Accept", "application/json,text/plain")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("接码地址 HTTP %d", resp.StatusCode)
	}
	var object map[string]any
	if json.Unmarshal(data, &object) == nil {
		if value, ok := object["code"]; ok {
			code := strings.TrimSpace(fmt.Sprint(value))
			if regexp.MustCompile(`^\d{4,8}$`).MatchString(code) {
				return code, nil
			}
		}
	}
	if match := smsCodePattern.FindSubmatch(data); len(match) > 1 {
		return string(match[1]), nil
	}
	return "", fmt.Errorf("响应中未找到 4 至 8 位验证码")
}

func maskPhone(value string) string {
	r := []rune(strings.TrimSpace(value))
	if len(r) <= 4 {
		return "****"
	}
	return string(r[:3]) + "****" + string(r[len(r)-2:])
}
func maskAutoURL(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return "已绑定"
	}
	return u.Scheme + "://" + u.Host + "/***"
}

func (s *Server) handleBindAutoLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
		Binding   string `json:"binding"`
		Password  string `json:"password"`
		Enabled   bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ownerID := requestOwnerID(r, s.store)
	session, ok := s.sessionForOwnerAccount(ownerID, payload.AccountID)
	if !ok {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	parts := strings.SplitN(strings.TrimSpace(payload.Binding), "----", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		writeError(w, http.StatusBadRequest, errCode("auto_binding_invalid", "绑定格式必须是：手机号----接码地址", false))
		return
	}
	phone, rawURL := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if _, err := validateAutoCodeURL(rawURL); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	previous, _ := s.store.AutoLoginBinding(ownerID, payload.AccountID)
	passwordCipher := previous.PasswordCipher
	if strings.TrimSpace(payload.Password) != "" {
		var err error
		passwordCipher, err = encryptAutoSecret(s.cfg.AutoLoginSecret, payload.Password)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
	}
	if passwordCipher == "" {
		writeError(w, http.StatusBadRequest, errCode("auto_password_required", "首次绑定必须输入 Apple ID 密码", false))
		return
	}
	phoneCipher, err := encryptAutoSecret(s.cfg.AutoLoginSecret, phone)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	urlCipher, err := encryptAutoSecret(s.cfg.AutoLoginSecret, rawURL)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	binding := AutoLoginBinding{OwnerID: ownerID, AccountID: payload.AccountID, AppleID: session.AppleID, PhoneMasked: maskPhone(phone), PhoneCipher: phoneCipher, URLMasked: maskAutoURL(rawURL), URLCipher: urlCipher, PasswordCipher: passwordCipher, Enabled: payload.Enabled, Status: "等待登录态异常时自动登录", UpdatedAt: time.Now()}
	if err := s.store.SaveAutoLoginBinding(binding); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "自动接码登录配置已加密保存"})
}

func (s *Server) tryAutoLogin(session ICloudSession) {
	binding, ok := s.store.AutoLoginBinding(session.OwnerID, session.AccountID)
	if !ok || !binding.Enabled || (!binding.NextAttemptAt.IsZero() && time.Now().Before(binding.NextAttemptAt)) {
		return
	}
	lockValue, _ := autoLoginLocks.LoadOrStore(session.OwnerID+"|"+session.AccountID, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	if !lock.TryLock() {
		return
	}
	defer lock.Unlock()
	binding.Status = "自动登录中"
	binding.LastError = ""
	binding.LastAttemptAt = time.Now()
	binding.NextAttemptAt = time.Now().Add(10 * time.Minute)
	_ = s.store.SaveAutoLoginBinding(binding)
	password, err := decryptAutoSecret(s.cfg.AutoLoginSecret, binding.PasswordCipher)
	if err != nil {
		s.autoLoginFailed(binding, err)
		return
	}
	codeURL, err := decryptAutoSecret(s.cfg.AutoLoginSecret, binding.URLCipher)
	if err != nil {
		s.autoLoginFailed(binding, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := NewAppleAuthClient()
	var successes []string
	if state, saved := appleAccountLoginState(session); saved && state.LastCheckedAt.IsZero() == false && !state.LastCheckOK {
		store := newAppleAuthPendingStore()
		result, e := client.StartAppleAccountManageLogin(ctx, session.AppleID, password, store, "phone")
		if e == nil && !result.Needs2FA {
			refreshed := result.Session
			refreshed.OwnerID = session.OwnerID
			refreshed.AccountID = session.AccountID
			e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
		}
		if e == nil && result.Needs2FA {
			if code, ce := pollAutoCode(ctx, codeURL); ce == nil {
				if pending, found := store.get(result.PendingID); found {
					var refreshed ICloudSession
					refreshed, e = client.SubmitAppleAccountManage2FA(ctx, pending, code, nil)
					if e == nil {
						refreshed.OwnerID = session.OwnerID
						refreshed.AccountID = session.AccountID
						e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
					}
				}
			} else {
				e = ce
			}
		}
		if e == nil {
			successes = append(successes, "新接口")
		} else {
			err = e
		}
	}
	if state, saved := iCloudWebLoginState(session); saved && !state.LastCheckedAt.IsZero() && !state.LastCheckOK {
		store := newAppleAuthPendingStore()
		result, e := client.StartLogin(ctx, session.AppleID, password, s.cfg.ICloudDefaultHost, s.cfg.ICloudClientID, store, "phone")
		if e == nil && !result.Needs2FA {
			refreshed := result.Session
			refreshed.OwnerID = session.OwnerID
			refreshed.AccountID = session.AccountID
			e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
		}
		if e == nil && result.Needs2FA {
			if code, ce := pollAutoCode(ctx, codeURL); ce == nil {
				if pending, found := store.get(result.PendingID); found {
					var refreshed ICloudSession
					refreshed, e = client.Submit2FA(ctx, pending, code)
					if e == nil {
						refreshed.OwnerID = session.OwnerID
						refreshed.AccountID = session.AccountID
						e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
					}
				}
			} else {
				e = ce
			}
		}
		if e == nil {
			successes = append(successes, "旧接口")
		} else {
			err = e
		}
	}
	if len(successes) > 0 {
		binding.Status = "自动登录成功：" + strings.Join(successes, "、")
		binding.LastSuccessAt = time.Now()
		binding.LastError = ""
		binding.NextAttemptAt = time.Time{}
		_ = s.store.SaveAutoLoginBinding(binding)
		return
	}
	if err == nil {
		err = fmt.Errorf("没有需要自动登录的异常接口")
	}
	s.autoLoginFailed(binding, err)
}

func pollAutoCode(ctx context.Context, rawURL string) (string, error) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		code, err := fetchAutoCode(ctx, rawURL)
		if err == nil {
			return code, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("等待短信验证码超时")
		case <-ticker.C:
		}
	}
}
func (s *Server) autoLoginFailed(binding AutoLoginBinding, err error) {
	binding.Status = "自动登录失败"
	binding.LastError = keepAliveChineseError(err)
	binding.NextAttemptAt = time.Now().Add(30 * time.Minute)
	_ = s.store.SaveAutoLoginBinding(binding)
}
