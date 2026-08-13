package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
var appleSixDigitCodePattern = regexp.MustCompile(`(?:^|\D)(\d{6})(?:\D|$)`)
var appleSplitSixDigitCodePattern = regexp.MustCompile(`(?:^|\D)(\d{3})[\s-]+(\d{3})(?:\D|$)`)
var appleCodeKeywordPattern = regexp.MustCompile(`(?i)(?:验证码|驗證碼|校验码|校驗碼|动态码|動態碼|verification\s*code|security\s*code|passcode|one[ -]?time\s*(?:code|password)|otp)[^0-9]{0,40}(\d{6})(?:\D|$)`)
var appleCodeJSONKeys = map[string]bool{
	"code": true, "smscode": true, "verificationcode": true, "securitycode": true,
	"passcode": true, "otp": true, "verifycode": true, "captcha": true,
}

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
	return extractAppleVerificationCode(data)
}

func normalizeVerificationText(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= '０' && r <= '９' {
			return '0' + (r - '０')
		}
		return r
	}, value)
}

func normalizedCodeKey(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= 'a' && r <= 'z':
			return r
		default:
			return -1
		}
	}, value)
}

func exactAppleCode(value any) (string, bool) {
	text := strings.TrimSpace(normalizeVerificationText(fmt.Sprint(value)))
	if len(text) == 6 {
		for _, r := range text {
			if r < '0' || r > '9' {
				return "", false
			}
		}
		return text, true
	}
	return "", false
}

func codeFromJSON(value any) (string, bool) {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if appleCodeJSONKeys[normalizedCodeKey(key)] {
				if code, ok := exactAppleCode(child); ok {
					return code, true
				}
				if text, ok := child.(string); ok {
					if code, ok := codeNearKeyword(normalizeVerificationText(text)); ok {
						return code, true
					}
				}
			}
		}
		for _, child := range current {
			if code, ok := codeFromJSON(child); ok {
				return code, true
			}
		}
	case []any:
		for i := len(current) - 1; i >= 0; i-- {
			if code, ok := codeFromJSON(current[i]); ok {
				return code, true
			}
		}
	case string:
		return codeNearKeyword(normalizeVerificationText(current))
	}
	return "", false
}

func codeNearKeyword(text string) (string, bool) {
	if match := appleCodeKeywordPattern.FindStringSubmatch(text); len(match) > 1 {
		return match[1], true
	}
	return "", false
}

func uniqueAppleCode(text string) (string, int) {
	candidates := map[string]struct{}{}
	for _, match := range appleSixDigitCodePattern.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 {
			candidates[match[1]] = struct{}{}
		}
	}
	for _, match := range appleSplitSixDigitCodePattern.FindAllStringSubmatch(text, -1) {
		if len(match) > 2 {
			candidates[match[1]+match[2]] = struct{}{}
		}
	}
	if len(candidates) == 1 {
		for code := range candidates {
			return code, 1
		}
	}
	return "", len(candidates)
}

func extractAppleVerificationCode(data []byte) (string, error) {
	text := normalizeVerificationText(string(data))
	var payload any
	if json.Unmarshal(data, &payload) == nil {
		if code, ok := codeFromJSON(payload); ok {
			return code, nil
		}
	}
	if code, ok := codeNearKeyword(text); ok {
		return code, nil
	}
	if code, count := uniqueAppleCode(text); count == 1 {
		return code, nil
	} else if count > 1 {
		return "", fmt.Errorf("接码响应中有 %d 个六位数候选，无法安全确定 Apple 验证码", count)
	}
	return "", fmt.Errorf("接码响应中未找到六位 Apple 验证码")
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
	if !payload.Enabled {
		_, found, err := s.store.SetAutoLoginBindingEnabled(ownerID, payload.AccountID, false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, errCode("auto_binding_not_found", "尚未绑定自动接码登录", false))
			return
		}
		s.cancelAutoLogin(ownerID, payload.AccountID)
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "已暂停自动接码登录"})
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

func (s *Server) handleAutoLoginLogs(w http.ResponseWriter, r *http.Request) {
	ownerID := requestOwnerID(r, s.store)
	accountID := strings.TrimSpace(r.URL.Query().Get("account_id"))
	if ownerID == "" || accountID == "" {
		writeError(w, http.StatusBadRequest, errCode("account_required", "请选择要查看日志的账号", false))
		return
	}
	if !s.canAccessAccountIDForOwner(ownerID, accountID) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "logs": s.store.AutoLoginAttempts(ownerID, accountID, 10)})
}

func autoLoginKey(ownerID, accountID string) string {
	return ownerID + "|" + accountID
}

func (s *Server) cancelAutoLogin(ownerID, accountID string) {
	s.autoLoginMu.Lock()
	cancel := s.autoLoginCancels[autoLoginKey(ownerID, accountID)]
	s.autoLoginMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) registerAutoLoginCancel(ownerID, accountID string, cancel context.CancelFunc) func() {
	key := autoLoginKey(ownerID, accountID)
	s.autoLoginMu.Lock()
	s.autoLoginCancels[key] = cancel
	s.autoLoginMu.Unlock()
	return func() {
		s.autoLoginMu.Lock()
		delete(s.autoLoginCancels, key)
		s.autoLoginMu.Unlock()
	}
}

func (s *Server) autoLoginEnabled(ownerID, accountID string) bool {
	binding, ok := s.store.AutoLoginBinding(ownerID, accountID)
	return ok && binding.Enabled
}

func (s *Server) tryAutoLogin(session ICloudSession) {
	binding, ok := s.store.AutoLoginBinding(session.OwnerID, session.AccountID)
	if !ok || !binding.Enabled || (!binding.NextAttemptAt.IsZero() && time.Now().Before(binding.NextAttemptAt)) {
		return
	}
	lockValue, _ := autoLoginLocks.LoadOrStore(autoLoginKey(session.OwnerID, session.AccountID), &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	if !lock.TryLock() {
		return
	}
	defer lock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	unregister := s.registerAutoLoginCancel(session.OwnerID, session.AccountID, cancel)
	defer func() {
		cancel()
		unregister()
	}()
	binding, ok = s.store.AutoLoginBinding(session.OwnerID, session.AccountID)
	if !ok || !binding.Enabled || (!binding.NextAttemptAt.IsZero() && time.Now().Before(binding.NextAttemptAt)) {
		return
	}
	binding.Status = "自动登录中"
	binding.LastError = ""
	binding.LastAttemptAt = time.Now()
	binding.NextAttemptAt = time.Now().Add(10 * time.Minute)
	if saved, err := s.store.SaveAutoLoginProgress(binding); err != nil || !saved {
		return
	}
	attempt, attemptErr := s.store.StartAutoLoginAttempt(session.OwnerID, session.AccountID, session.AppleID)
	if attemptErr != nil {
		if s.logger != nil {
			s.logger.Warn("自动登录日志创建失败", "account_id", session.AccountID, "err", attemptErr)
		}
	}
	metricStarted := time.Now()
	finished := false
	step := func(stage, message, code string, ok bool) {
		if attempt.ID != "" {
			_ = s.store.AppendAutoLoginStep(attempt.ID, stage, message, code, ok)
		}
	}
	finish := func(status string, finishErr error) {
		if finished {
			return
		}
		finished = true
		message := ""
		if finishErr != nil {
			message = keepAliveChineseError(finishErr)
		}
		if attempt.ID != "" {
			_ = s.store.FinishAutoLoginAttempt(attempt.ID, status, message)
		}
		_ = s.store.RecordRuntimeMetric("auto_login", finishErr == nil, time.Since(metricStarted), firstNonEmpty(message, status))
	}
	defer func() {
		if !finished {
			finish("cancelled", fmt.Errorf("自动接码登录已暂停或任务被取消"))
		}
	}()
	if s.logger != nil {
		s.logger.Info("自动接码登录开始", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID)
	}
	password, err := decryptAutoSecret(s.cfg.AutoLoginSecret, binding.PasswordCipher)
	if err != nil {
		step("decrypt_password", "登录密码解密失败", "", false)
		finish("failed", err)
		s.autoLoginFailed(binding, err)
		return
	}
	step("decrypt_password", "登录密码读取成功", "", true)
	codeURL, err := decryptAutoSecret(s.cfg.AutoLoginSecret, binding.URLCipher)
	if err != nil {
		step("decrypt_code_url", "接码地址解密失败", "", false)
		finish("failed", err)
		s.autoLoginFailed(binding, err)
		return
	}
	step("decrypt_code_url", "接码地址读取成功", "", true)
	client, clientErr := s.appleAuthClientForAccount(ctx, session.OwnerID, session.AccountID)
	if clientErr != nil {
		step("prepare_client", "Apple 登录客户端初始化失败", "", false)
		finish("failed", clientErr)
		s.autoLoginFailed(binding, clientErr)
		return
	}
	step("prepare_client", "Apple 登录客户端初始化成功，已应用账号代理配置", "", true)
	var successes []string
	if state, saved := appleAccountLoginState(session); saved && state.LastCheckedAt.IsZero() == false && !state.LastCheckOK {
		if ctx.Err() != nil || !s.autoLoginEnabled(session.OwnerID, session.AccountID) {
			return
		}
		store := newAppleAuthPendingStore()
		step("apple_account_start", "开始新接口自动登录", "", true)
		result, e := client.StartAppleAccountManageLogin(ctx, session.AppleID, password, store, "phone")
		if e == nil && !result.Needs2FA {
			refreshed := result.Session
			refreshed.OwnerID = session.OwnerID
			refreshed.AccountID = session.AccountID
			e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
		}
		if e == nil && result.Needs2FA {
			step("apple_account_wait_code", "新接口已请求验证码，开始轮询六位验证码", "", true)
			if code, ce := pollAutoCode(ctx, codeURL); ce == nil {
				step("apple_account_code", "新接口提取到六位验证码", code, true)
				if s.logger != nil {
					s.logger.Info("自动接码已识别六位验证码", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "interface", "apple_account")
				}
				if pending, found := store.get(result.PendingID); found {
					step("apple_account_submit_code", "正在向新接口提交验证码", code, true)
					var refreshed ICloudSession
					refreshed, e = client.SubmitAppleAccountManage2FA(ctx, pending, code, nil)
					if e == nil {
						refreshed.OwnerID = session.OwnerID
						refreshed.AccountID = session.AccountID
						e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
					}
				}
			} else {
				step("apple_account_wait_code", keepAliveChineseError(ce), "", false)
				e = ce
			}
		}
		if e == nil {
			step("apple_account_done", "新接口登录态保存成功", "", true)
			successes = append(successes, "新接口")
		} else {
			step("apple_account_failed", keepAliveChineseError(e), "", false)
			err = e
		}
	}
	if state, saved := iCloudWebLoginState(session); saved && !state.LastCheckedAt.IsZero() && !state.LastCheckOK {
		if ctx.Err() != nil || !s.autoLoginEnabled(session.OwnerID, session.AccountID) {
			return
		}
		store := newAppleAuthPendingStore()
		step("icloud_web_start", "开始旧接口自动登录", "", true)
		result, e := client.StartLogin(ctx, session.AppleID, password, s.cfg.ICloudDefaultHost, s.cfg.ICloudClientID, store, "phone")
		if e == nil && !result.Needs2FA {
			refreshed := result.Session
			refreshed.OwnerID = session.OwnerID
			refreshed.AccountID = session.AccountID
			e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
		}
		if e == nil && result.Needs2FA {
			step("icloud_web_wait_code", "旧接口已请求验证码，开始轮询六位验证码", "", true)
			if code, ce := pollAutoCode(ctx, codeURL); ce == nil {
				step("icloud_web_code", "旧接口提取到六位验证码", code, true)
				if s.logger != nil {
					s.logger.Info("自动接码已识别六位验证码", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "interface", "icloud_web")
				}
				if pending, found := store.get(result.PendingID); found {
					step("icloud_web_submit_code", "正在向旧接口提交验证码", code, true)
					var refreshed ICloudSession
					refreshed, e = client.Submit2FA(ctx, pending, code)
					if e == nil {
						refreshed.OwnerID = session.OwnerID
						refreshed.AccountID = session.AccountID
						e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
					}
				}
			} else {
				step("icloud_web_wait_code", keepAliveChineseError(ce), "", false)
				e = ce
			}
		}
		if e == nil {
			step("icloud_web_done", "旧接口登录态保存成功", "", true)
			successes = append(successes, "旧接口")
		} else {
			step("icloud_web_failed", keepAliveChineseError(e), "", false)
			err = e
		}
	}
	if len(successes) > 0 {
		binding.Status = "自动登录成功：" + strings.Join(successes, "、")
		binding.LastSuccessAt = time.Now()
		binding.LastError = ""
		binding.NextAttemptAt = time.Time{}
		_, _ = s.store.SaveAutoLoginProgress(binding)
		if s.logger != nil {
			s.logger.Info("自动接码登录成功", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "interfaces", strings.Join(successes, ","))
		}
		step("done", binding.Status, "", true)
		finish("success", nil)
		return
	}
	if err == nil {
		err = fmt.Errorf("没有需要自动登录的异常接口")
	}
	step("failed", keepAliveChineseError(err), "", false)
	finish("failed", err)
	s.autoLoginFailed(binding, err)
}

func pollAutoCode(ctx context.Context, rawURL string) (string, error) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var lastErr error
	for {
		code, err := fetchAutoCode(ctx, rawURL)
		if err == nil {
			return code, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return "", fmt.Errorf("自动接码登录已暂停")
			}
			if lastErr != nil {
				return "", fmt.Errorf("等待六位短信验证码超时：%w", lastErr)
			}
			return "", fmt.Errorf("等待短信验证码超时")
		case <-ticker.C:
		}
	}
}
func (s *Server) autoLoginFailed(binding AutoLoginBinding, err error) {
	binding.Status = "自动登录失败"
	binding.LastError = keepAliveChineseError(err)
	binding.NextAttemptAt = time.Now().Add(30 * time.Minute)
	_, _ = s.store.SaveAutoLoginProgress(binding)
	if s.logger != nil {
		s.logger.Warn("自动接码登录失败", "owner", s.ownerName(binding.OwnerID), "account_id", binding.AccountID, "err", keepAliveChineseError(err))
	}
}
