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
var autoLoginLogURLPattern = regexp.MustCompile(`https?://[^\s\"']+`)

const maxAutoLoginAttemptsPerAccount = 10
const maxAutoLoginStepsPerAttempt = 80

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
	binding := AutoLoginBinding{OwnerID: ownerID, AccountID: payload.AccountID, AppleID: session.AppleID, PhoneMasked: maskPhone(phone), PhoneCipher: phoneCipher, URLMasked: maskAutoURL(rawURL), URLCipher: urlCipher, PasswordCipher: passwordCipher, Enabled: payload.Enabled, Status: "等待登录态异常时自动登录", UpdatedAt: time.Now(), Logs: previous.Logs}
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
	trigger := autoLoginTriggerSummary(session)
	binding.Status = "自动登录中"
	binding.LastError = ""
	binding.LastAttemptAt = time.Now()
	binding.NextAttemptAt = time.Now().Add(10 * time.Minute)
	attemptID := s.startAutoLoginAttemptLog(&binding, trigger)
	password, err := decryptAutoSecret(s.cfg.AutoLoginSecret, binding.PasswordCipher)
	if err != nil {
		s.appendAutoLoginLogStep(&binding, attemptID, "准备配置", "error", "Apple 密码密文解密失败", "")
		s.autoLoginFailed(binding, attemptID, err)
		return
	}
	codeURL, err := decryptAutoSecret(s.cfg.AutoLoginSecret, binding.URLCipher)
	if err != nil {
		s.appendAutoLoginLogStep(&binding, attemptID, "准备配置", "error", "接码地址密文解密失败", "")
		s.autoLoginFailed(binding, attemptID, err)
		return
	}
	s.appendAutoLoginLogStep(&binding, attemptID, "准备配置", "success", "加密配置读取成功，接码地址与密码未写入日志", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, clientErr := s.appleAuthClientForAccount(session.OwnerID, session.AccountID, session.AppleID)
	if clientErr != nil {
		s.appendAutoLoginLogStep(&binding, attemptID, "检查代理", "error", keepAliveChineseError(clientErr), "")
		s.autoLoginFailed(binding, attemptID, clientErr)
		return
	}
	proxyMessage := "Apple 请求客户端准备完成，使用服务器直连或原固定代理"
	if strings.TrimSpace(session.ProxyPoolNode) != "" {
		proxyMessage = "Apple 请求客户端准备完成，使用账号固定节点：" + session.ProxyPoolNode
	}
	s.appendAutoLoginLogStep(&binding, attemptID, "检查代理", "success", proxyMessage, "")
	var successes []string
	if state, saved := appleAccountLoginState(session); saved && state.LastCheckedAt.IsZero() == false && !state.LastCheckOK {
		s.appendAutoLoginLogStep(&binding, attemptID, "新接口登录", "info", "检测到新接口登录态失效，开始短信方式自动登录", "")
		store := newAppleAuthPendingStore()
		result, e := client.StartAppleAccountManageLogin(ctx, session.AppleID, password, store, "phone")
		if e != nil {
			s.appendAutoLoginLogStep(&binding, attemptID, "新接口登录", "error", "发起登录失败："+safeAutoLoginLogError(e), "")
		}
		if e == nil && !result.Needs2FA {
			s.appendAutoLoginLogStep(&binding, attemptID, "新接口登录", "info", "Apple 未要求验证码，正在保存刷新后的登录态", "")
			refreshed := result.Session
			refreshed.OwnerID = session.OwnerID
			refreshed.AccountID = session.AccountID
			e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
		}
		if e == nil && result.Needs2FA {
			s.appendAutoLoginLogStep(&binding, attemptID, "等待验证码", "info", "短信验证已触发，开始轮询接码地址", "")
			if code, ce := pollAutoCode(ctx, codeURL, func(count int, pollErr error) {
				if count == 1 || count%5 == 0 {
					s.appendAutoLoginLogStep(&binding, attemptID, "等待验证码", "info", fmt.Sprintf("第 %d 次读取暂未获得验证码：%s", count, safeAutoLoginLogError(pollErr)), "")
				}
			}); ce == nil {
				s.appendAutoLoginLogStep(&binding, attemptID, "收到验证码", "success", "已从接码地址获得短信验证码", code)
				if pending, found := store.get(result.PendingID); found {
					s.appendAutoLoginLogStep(&binding, attemptID, "提交验证码", "info", "正在向 Apple 新接口提交短信验证码", "")
					var refreshed ICloudSession
					refreshed, e = client.SubmitAppleAccountManage2FA(ctx, pending, code, nil)
					if e == nil {
						refreshed.OwnerID = session.OwnerID
						refreshed.AccountID = session.AccountID
						e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
					}
				} else {
					e = errCode("auto_login_pending_missing", "新接口待验证登录已过期", true)
				}
			} else {
				e = ce
			}
		}
		if e == nil {
			successes = append(successes, "新接口")
			s.appendAutoLoginLogStep(&binding, attemptID, "新接口完成", "success", "新接口自动登录成功，登录态已保存", "")
		} else {
			err = e
			s.appendAutoLoginLogStep(&binding, attemptID, "新接口完成", "error", "新接口自动登录失败："+safeAutoLoginLogError(e), "")
		}
	}
	if state, saved := iCloudWebLoginState(session); saved && !state.LastCheckedAt.IsZero() && !state.LastCheckOK {
		s.appendAutoLoginLogStep(&binding, attemptID, "旧接口登录", "info", "检测到旧接口登录态失效，开始短信方式自动登录", "")
		store := newAppleAuthPendingStore()
		result, e := client.StartLogin(ctx, session.AppleID, password, s.cfg.ICloudDefaultHost, s.cfg.ICloudClientID, store, "phone")
		if e != nil {
			s.appendAutoLoginLogStep(&binding, attemptID, "旧接口登录", "error", "发起登录失败："+safeAutoLoginLogError(e), "")
		}
		if e == nil && !result.Needs2FA {
			s.appendAutoLoginLogStep(&binding, attemptID, "旧接口登录", "info", "Apple 未要求验证码，正在保存刷新后的登录态", "")
			refreshed := result.Session
			refreshed.OwnerID = session.OwnerID
			refreshed.AccountID = session.AccountID
			e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
		}
		if e == nil && result.Needs2FA {
			s.appendAutoLoginLogStep(&binding, attemptID, "等待验证码", "info", "短信验证已触发，开始轮询接码地址", "")
			if code, ce := pollAutoCode(ctx, codeURL, func(count int, pollErr error) {
				if count == 1 || count%5 == 0 {
					s.appendAutoLoginLogStep(&binding, attemptID, "等待验证码", "info", fmt.Sprintf("第 %d 次读取暂未获得验证码：%s", count, safeAutoLoginLogError(pollErr)), "")
				}
			}); ce == nil {
				s.appendAutoLoginLogStep(&binding, attemptID, "收到验证码", "success", "已从接码地址获得短信验证码", code)
				if pending, found := store.get(result.PendingID); found {
					s.appendAutoLoginLogStep(&binding, attemptID, "提交验证码", "info", "正在向 Apple 旧接口提交短信验证码", "")
					var refreshed ICloudSession
					refreshed, e = client.Submit2FA(ctx, pending, code)
					if e == nil {
						refreshed.OwnerID = session.OwnerID
						refreshed.AccountID = session.AccountID
						e = s.store.SaveICloudSessionForOwner(session.OwnerID, refreshed)
					}
				} else {
					e = errCode("auto_login_pending_missing", "旧接口待验证登录已过期", true)
				}
			} else {
				e = ce
			}
		}
		if e == nil {
			successes = append(successes, "旧接口")
			s.appendAutoLoginLogStep(&binding, attemptID, "旧接口完成", "success", "旧接口自动登录成功，登录态已保存", "")
		} else {
			err = e
			s.appendAutoLoginLogStep(&binding, attemptID, "旧接口完成", "error", "旧接口自动登录失败："+safeAutoLoginLogError(e), "")
		}
	}
	if len(successes) > 0 {
		binding.Status = "自动登录成功：" + strings.Join(successes, "、")
		binding.LastSuccessAt = time.Now()
		binding.LastError = ""
		binding.NextAttemptAt = time.Time{}
		s.finishAutoLoginAttemptLog(&binding, attemptID, "success", "")
		return
	}
	if err == nil {
		err = fmt.Errorf("没有需要自动登录的异常接口")
	}
	s.autoLoginFailed(binding, attemptID, err)
}

func pollAutoCode(ctx context.Context, rawURL string, onPoll func(int, error)) (string, error) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	count := 0
	for {
		count++
		code, err := fetchAutoCode(ctx, rawURL)
		if err == nil {
			return code, nil
		}
		if onPoll != nil {
			onPoll(count, err)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("等待短信验证码超时")
		case <-ticker.C:
		}
	}
}
func (s *Server) autoLoginFailed(binding AutoLoginBinding, attemptID string, err error) {
	binding.Status = "自动登录失败"
	binding.LastError = keepAliveChineseError(err)
	binding.NextAttemptAt = time.Now().Add(30 * time.Minute)
	s.finishAutoLoginAttemptLog(&binding, attemptID, "failed", keepAliveChineseError(err))
}

func autoLoginTriggerSummary(session ICloudSession) string {
	parts := make([]string, 0, 2)
	if state, saved := appleAccountLoginState(session); saved && !state.LastCheckedAt.IsZero() && !state.LastCheckOK {
		parts = append(parts, "新接口登录态失效")
	}
	if state, saved := iCloudWebLoginState(session); saved && !state.LastCheckedAt.IsZero() && !state.LastCheckOK {
		parts = append(parts, "旧接口登录态失效")
	}
	if len(parts) == 0 {
		return "系统检测到登录态异常"
	}
	return strings.Join(parts, "、")
}

func safeAutoLoginLogError(err error) string {
	if err == nil {
		return "未知原因"
	}
	message := strings.TrimSpace(keepAliveChineseError(err))
	message = autoLoginLogURLPattern.ReplaceAllString(message, "https://***/***")
	if len([]rune(message)) > 500 {
		message = string([]rune(message)[:500]) + "..."
	}
	return message
}

func maskAutoLoginCode(code string) string {
	code = strings.TrimSpace(code)
	if len(code) <= 2 {
		return strings.Repeat("*", len(code))
	}
	return code[:2] + strings.Repeat("*", len(code)-2)
}

func (s *Server) startAutoLoginAttemptLog(binding *AutoLoginBinding, trigger string) string {
	id, err := randomToken(12)
	if err != nil {
		id = fmt.Sprintf("attempt-%d", time.Now().UnixNano())
	}
	attempt := AutoLoginAttemptLog{ID: id, Trigger: trigger, Status: "running", StartedAt: time.Now(), Steps: []AutoLoginLogStep{{At: time.Now(), Stage: "触发自动登录", Level: "info", Message: trigger}}}
	binding.Logs = append([]AutoLoginAttemptLog{attempt}, binding.Logs...)
	if len(binding.Logs) > maxAutoLoginAttemptsPerAccount {
		binding.Logs = binding.Logs[:maxAutoLoginAttemptsPerAccount]
	}
	_ = s.store.SaveAutoLoginBinding(*binding)
	return id
}

func (s *Server) appendAutoLoginLogStep(binding *AutoLoginBinding, attemptID, stage, level, message, code string) {
	for i := range binding.Logs {
		if binding.Logs[i].ID != attemptID {
			continue
		}
		step := AutoLoginLogStep{At: time.Now(), Stage: strings.TrimSpace(stage), Level: firstNonEmpty(strings.TrimSpace(level), "info"), Message: safeAutoLoginLogMessage(message)}
		if code = strings.TrimSpace(code); code != "" {
			step.CodeMasked = maskAutoLoginCode(code)
			if cipher, err := encryptAutoSecret(s.cfg.AutoLoginSecret, code); err == nil {
				step.CodeCipher = cipher
			} else {
				step.Message += "；验证码加密保存失败，仅保留脱敏记录"
			}
		}
		binding.Logs[i].Steps = append(binding.Logs[i].Steps, step)
		if len(binding.Logs[i].Steps) > maxAutoLoginStepsPerAttempt {
			binding.Logs[i].Steps = binding.Logs[i].Steps[len(binding.Logs[i].Steps)-maxAutoLoginStepsPerAttempt:]
		}
		return
	}
}

func safeAutoLoginLogMessage(message string) string {
	message = autoLoginLogURLPattern.ReplaceAllString(strings.TrimSpace(message), "https://***/***")
	if len([]rune(message)) > 500 {
		message = string([]rune(message)[:500]) + "..."
	}
	return message
}

func (s *Server) finishAutoLoginAttemptLog(binding *AutoLoginBinding, attemptID, status, message string) {
	for i := range binding.Logs {
		if binding.Logs[i].ID != attemptID {
			continue
		}
		binding.Logs[i].Status = status
		binding.Logs[i].FinishedAt = time.Now()
		binding.Logs[i].Error = safeAutoLoginLogMessage(message)
		_ = s.store.SaveAutoLoginBinding(*binding)
		return
	}
}

func (s *Server) handleAutoLoginLogs(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID   string `json:"account_id"`
		RevealCodes bool   `json:"reveal_codes"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ownerID := requestOwnerID(r, s.store)
	if _, ok := s.sessionForOwnerAccount(ownerID, payload.AccountID); !ok {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	binding, ok := s.store.AutoLoginBinding(ownerID, payload.AccountID)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "logs": []any{}})
		return
	}
	logs := make([]map[string]any, 0, len(binding.Logs))
	for _, attempt := range binding.Logs {
		steps := make([]map[string]any, 0, len(attempt.Steps))
		for _, step := range attempt.Steps {
			item := map[string]any{"at": formatTime(step.At), "stage": step.Stage, "level": step.Level, "message": step.Message}
			if step.CodeMasked != "" {
				item["code"] = step.CodeMasked
				item["code_revealed"] = false
			}
			if payload.RevealCodes && step.CodeCipher != "" {
				if code, err := decryptAutoSecret(s.cfg.AutoLoginSecret, step.CodeCipher); err == nil {
					item["code"] = code
					item["code_revealed"] = true
				}
			}
			steps = append(steps, item)
		}
		logs = append(logs, map[string]any{"id": attempt.ID, "trigger": attempt.Trigger, "status": attempt.Status, "started_at": formatTime(attempt.StartedAt), "finished_at": formatTime(attempt.FinishedAt), "error": attempt.Error, "steps": steps})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "account_id": payload.AccountID, "apple_id": binding.AppleID, "logs": logs, "max_logs": maxAutoLoginAttemptsPerAccount, "codes_revealed": payload.RevealCodes})
}
