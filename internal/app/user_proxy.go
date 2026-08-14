package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	xproxy "golang.org/x/net/proxy"
)

func normalizeFixedProxyURL(raw string) (string, bool) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" || strings.Contains(normalized, "://") {
		return normalized, false
	}
	return "http://" + normalized, true
}

func validateFixedProxyURL(raw string) (*url.URL, error) {
	normalized, _ := normalizeFixedProxyURL(raw)
	u, err := url.Parse(normalized)
	if err != nil || u.Hostname() == "" {
		return nil, errCode("proxy_invalid", "代理地址格式无效", false)
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		return nil, errCode("proxy_scheme_invalid", "代理仅支持 http://、https://、socks5://", false)
	}
	if u.Port() == "" {
		return nil, errCode("proxy_port_required", "代理地址必须包含端口", false)
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return nil, errCode("proxy_dns_failed", "代理服务器域名解析失败", true)
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return nil, errCode("proxy_private_address", "代理服务器不能指向本机或内网地址", false)
		}
	}
	return u, nil
}

func proxyHTTPClient(raw string, timeout time.Duration) (*http.Client, error) {
	u, err := validateFixedProxyURL(raw)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if u.Scheme == "socks5" {
		var auth *xproxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: password}
		}
		dialer, err := xproxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}
	} else {
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

func maskProxyURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "已配置"
	}
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

func testFixedProxy(ctx context.Context, raw string) (string, int64, bool, error) {
	proxyURL, parseErr := validateFixedProxyURL(raw)
	if parseErr != nil {
		return "", 0, false, parseErr
	}
	client, err := proxyHTTPClient(raw, 15*time.Second)
	if err != nil {
		return "", 0, false, err
	}
	started := time.Now()
	checks := []struct {
		url   string
		parse func(string) string
	}{
		{"https://checkip.amazonaws.com/", parsePlainProxyIP},
		{"https://icanhazip.com/", parsePlainProxyIP},
		{"https://www.cloudflare.com/cdn-cgi/trace", parseCloudflareProxyIP},
		{"https://api.ipify.org/", parsePlainProxyIP},
	}
	errorsSeen := make([]string, 0, len(checks))
	tlsOK := false
	for _, check := range checks {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, check.url, nil)
		res, requestErr := client.Do(req)
		if requestErr != nil {
			errorsSeen = append(errorsSeen, compactProxyCheckError(check.url, requestErr))
			continue
		}
		tlsOK = tlsOK || res.TLS != nil
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 16*1024))
		res.Body.Close()
		if readErr != nil {
			errorsSeen = append(errorsSeen, compactProxyCheckError(check.url, readErr))
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s 返回 HTTP %d", proxyCheckHost(check.url), res.StatusCode))
			continue
		}
		ip := check.parse(string(body))
		if net.ParseIP(ip) == nil {
			errorsSeen = append(errorsSeen, proxyCheckHost(check.url)+" 未返回有效出口 IP")
			continue
		}
		return ip, time.Since(started).Milliseconds(), tlsOK, nil
	}

	// Some residential proxy providers block public IP lookup sites. Verify ordinary
	// HTTPS connectivity separately so one blocked test domain does not mark a usable
	// proxy as offline.
	connectivityChecks := []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}
	for _, checkURL := range connectivityChecks {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
		res, requestErr := client.Do(req)
		if requestErr != nil {
			errorsSeen = append(errorsSeen, compactProxyCheckError(checkURL, requestErr))
			continue
		}
		tlsOK = tlsOK || res.TLS != nil
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4*1024))
		res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 400 && tlsOK {
			return "检测站点受限", time.Since(started).Milliseconds(), true, nil
		}
		errorsSeen = append(errorsSeen, fmt.Sprintf("%s 返回 HTTP %d", proxyCheckHost(checkURL), res.StatusCode))
	}

	lastErr := errors.New("所有普通检测站点均连接失败")
	if len(errorsSeen) > 0 {
		lastErr = errors.New(strings.Join(errorsSeen, "；"))
	}
	return "", time.Since(started).Milliseconds(), tlsOK, explainFixedProxyError(proxyURL, lastErr)
}

func parsePlainProxyIP(body string) string {
	return strings.TrimSpace(strings.SplitN(body, "\n", 2)[0])
}

func parseCloudflareProxyIP(body string) string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "ip="))
		}
	}
	return ""
}

func proxyCheckHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "检测站点"
	}
	return u.Hostname()
}

func compactProxyCheckError(raw string, err error) string {
	message := strings.TrimSpace(err.Error())
	if len(message) > 180 {
		message = message[:180] + "..."
	}
	return proxyCheckHost(raw) + "：" + message
}

func explainFixedProxyError(proxyURL *url.URL, err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	scheme := ""
	if proxyURL != nil {
		scheme = strings.ToLower(proxyURL.Scheme)
	}
	if strings.Contains(message, "407") || strings.Contains(message, "proxy authentication required") {
		return fmt.Errorf("代理认证失败（HTTP 407），请检查代理用户名和密码")
	}
	if strings.Contains(message, "403") || strings.Contains(message, "forbidden") {
		return fmt.Errorf("所有普通检测站点均被代理拒绝（HTTP 403），请检查代理授权、IP 白名单、地区参数和套餐权限")
	}
	if strings.Contains(message, "404") || strings.Contains(message, "not found") {
		if scheme == "https" {
			return fmt.Errorf("代理服务器未提供 HTTPS 正向代理隧道（HTTP 404）；多数标注“支持 HTTPS”的代理仍应填写 http://IP:端口，请改为 http:// 后重新检测")
		}
		return fmt.Errorf("代理地址返回 HTTP 404，它可能是普通网页/API 而不是支持 CONNECT 的正向代理，请核对代理主机和端口")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(message, "timeout") || strings.Contains(message, "deadline exceeded") {
		return fmt.Errorf("连接代理超时，请检查代理地址、端口、防火墙和代理是否在线")
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(message, "connection refused") {
		return fmt.Errorf("代理端口拒绝连接，请检查主机、端口和代理服务是否启动")
	}
	if strings.Contains(message, "no such host") || strings.Contains(message, "server misbehaving") {
		return fmt.Errorf("代理域名解析失败，请检查代理域名")
	}
	if strings.Contains(message, "tls") || strings.Contains(message, "certificate") || strings.Contains(message, "first record does not look like a tls handshake") {
		if scheme == "https" {
			return fmt.Errorf("代理协议不匹配：该端口不像 HTTPS 代理，请尝试改为 http:// 后重新检测")
		}
		return fmt.Errorf("代理 TLS 检测失败：%v", err)
	}
	if strings.Contains(message, "socks") {
		return fmt.Errorf("SOCKS5 代理对所有普通检测站点均握手失败，请检查该端口是否真正支持 SOCKS5、账号地区参数和认证信息")
	}
	return fmt.Errorf("代理连接失败：%v", err)
}

func (s *Server) appleHTTPClientForOwner(ownerID string) (*http.Client, error) {
	return s.appleHTTPClientForAccount(context.Background(), ownerID, "", "")
}

func (s *Server) appleHTTPClientForAccount(ctx context.Context, ownerID, accountID, appleID string) (*http.Client, error) {
	_ = ctx
	if s.proxyPool != nil {
		if client, selected, err := s.proxyPool.client(ownerID, accountID, appleID); selected {
			if err != nil {
				return nil, errCode("proxy_pool_unavailable", "账号代理异常，已停止 Apple 请求："+err.Error(), true)
			}
			return client, nil
		}
	}
	config, ok := s.store.UserProxyConfig(ownerID)
	if !ok || !config.Enabled {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	raw, err := decryptAutoSecret(s.cfg.AutoLoginSecret, config.URLCipher)
	if err != nil {
		return nil, errCode("proxy_decrypt_failed", "代理配置无法解密，已停止 Apple 请求", false)
	}
	client, err := proxyHTTPClient(raw, 30*time.Second)
	if err != nil {
		return nil, errCode("proxy_unavailable", "代理异常，已停止 Apple 请求："+err.Error(), true)
	}
	return client, nil
}

func (s *Server) accountAppleID(ownerID, accountID string) string {
	if accountID == "" {
		return ""
	}
	if session, ok := s.sessionForOwnerAccount(ownerID, accountID); ok {
		return session.AppleID
	}
	return ""
}

func (s *Server) iCloudClientForAccount(ctx context.Context, ownerID, accountID string) (*ICloudClient, error) {
	client, err := s.appleHTTPClientForAccount(ctx, ownerID, accountID, s.accountAppleID(ownerID, accountID))
	if err != nil {
		return nil, err
	}
	return NewICloudClientWithHTTPClient(client), nil
}

func (s *Server) appleAuthClientForAccount(ctx context.Context, ownerID, accountID string) (*AppleAuthClient, error) {
	client, err := s.appleHTTPClientForAccount(ctx, ownerID, accountID, s.accountAppleID(ownerID, accountID))
	if err != nil {
		return nil, err
	}
	return NewAppleAuthClientWithHTTPClient(client), nil
}

func (s *Server) appleAuthClientForLogin(ctx context.Context, ownerID, accountID, appleID string) (*AppleAuthClient, error) {
	client, err := s.appleHTTPClientForAccount(ctx, ownerID, accountID, appleID)
	if err != nil {
		return nil, err
	}
	return NewAppleAuthClientWithHTTPClient(client), nil
}

// proxyURLForAccount returns the isolated per-user proxy that IMAP and other
// protocol clients should use. Pool nodes take precedence over the user's
// fixed proxy, matching the Apple HTTP client selection above.
func (s *Server) proxyURLForAccount(ctx context.Context, ownerID, accountID string) (string, ProxyPoolNode, error) {
	_ = ctx
	nodeName := s.store.ProxyPoolNodeForAccount(ownerID, accountID, "")
	if nodeName != "" && s.proxyPool != nil {
		port, err := s.proxyPool.ensure(ownerID, nodeName)
		if err != nil {
			return "", ProxyPoolNode{Name: nodeName}, errCode("proxy_pool_unavailable", "账号代理异常，已停止请求："+err.Error(), true)
		}
		return fmt.Sprintf("http://127.0.0.1:%d", port), ProxyPoolNode{Name: nodeName}, nil
	}
	config, ok := s.store.UserProxyConfig(ownerID)
	if !ok || !config.Enabled || config.URLCipher == "" {
		return "", ProxyPoolNode{}, nil
	}
	raw, err := decryptAutoSecret(s.cfg.AutoLoginSecret, config.URLCipher)
	if err != nil {
		return "", ProxyPoolNode{}, errCode("proxy_decrypt_failed", "代理配置无法解密，已停止请求", false)
	}
	if _, err = validateFixedProxyURL(raw); err != nil {
		return "", ProxyPoolNode{}, err
	}
	return raw, ProxyPoolNode{}, nil
}

func (s *Server) iCloudClientForOwner(ownerID string) (*ICloudClient, error) {
	client, err := s.appleHTTPClientForOwner(ownerID)
	if err != nil {
		return nil, err
	}
	return NewICloudClientWithHTTPClient(client), nil
}

func (s *Server) appleAuthClientForOwner(ownerID string) (*AppleAuthClient, error) {
	client, err := s.appleHTTPClientForOwner(ownerID)
	if err != nil {
		return nil, err
	}
	return NewAppleAuthClientWithHTTPClient(client), nil
}

func (s *Server) handleGetFixedProxy(w http.ResponseWriter, r *http.Request) {
	c, ok := s.store.UserProxyConfig(requestOwnerID(r, s.store))
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "configured": ok, "proxy": map[string]any{"url_masked": c.URLMasked, "enabled": c.Enabled, "status": c.Status, "exit_ip": c.ExitIP, "latency_ms": c.LatencyMS, "tls_ok": c.TLSOK, "last_error": c.LastError, "last_tested_at": formatTime(c.LastTestedAt)}})
}

func (s *Server) handleSaveFixedProxy(w http.ResponseWriter, r *http.Request) {
	var p struct {
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, 400, err)
		return
	}
	owner := requestOwnerID(r, s.store)
	old, _ := s.store.UserProxyConfig(owner)
	cipher := old.URLCipher
	masked := old.URLMasked
	schemeAdded := false
	if strings.TrimSpace(p.URL) != "" {
		var normalizedURL string
		normalizedURL, schemeAdded = normalizeFixedProxyURL(p.URL)
		if _, err := validateFixedProxyURL(normalizedURL); err != nil {
			writeError(w, 400, err)
			return
		}
		var err error
		cipher, err = encryptAutoSecret(s.cfg.AutoLoginSecret, normalizedURL)
		if err != nil {
			writeError(w, 503, err)
			return
		}
		masked = maskProxyURL(normalizedURL)
		if schemeAdded {
			p.URL = normalizedURL
		}
	}
	if cipher == "" {
		writeError(w, 400, errCode("proxy_required", "首次配置必须填写代理地址", false))
		return
	}
	c := old
	c.OwnerID = owner
	c.URLCipher = cipher
	c.URLMasked = masked
	c.Enabled = p.Enabled
	c.Status = "等待连通性测试"
	c.ExitIP = ""
	c.LatencyMS = 0
	c.TLSOK = false
	c.LastError = ""
	c.LastTestedAt = time.Time{}
	c.UpdatedAt = time.Now()
	if err := s.store.SaveUserProxyConfig(c); err != nil {
		writeError(w, 500, err)
		return
	}
	message := "固定代理已加密保存"
	if schemeAdded {
		message = "未填写代理协议，已自动补全 http:// 并加密保存"
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": message, "url_masked": masked})
}

func (s *Server) handleTestFixedProxy(w http.ResponseWriter, r *http.Request) {
	owner := requestOwnerID(r, s.store)
	c, ok := s.store.UserProxyConfig(owner)
	if !ok {
		writeError(w, 400, errCode("proxy_missing", "请先保存代理", false))
		return
	}
	raw, err := decryptAutoSecret(s.cfg.AutoLoginSecret, c.URLCipher)
	if err != nil {
		writeError(w, 503, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ip, latency, tlsOK, testErr := testFixedProxy(ctx, raw)
	c.LastTestedAt = time.Now()
	c.LatencyMS = latency
	c.TLSOK = tlsOK
	c.ExitIP = ip
	c.UpdatedAt = time.Now()
	if testErr != nil {
		c.Status = "代理异常"
		c.LastError = testErr.Error()
		_ = s.store.SaveUserProxyConfig(c)
		writeError(w, 502, errCode("proxy_test_failed", "代理异常："+testErr.Error(), true))
		return
	}
	c.Status = "代理正常"
	c.LastError = ""
	_ = s.store.SaveUserProxyConfig(c)
	writeJSON(w, 200, map[string]any{"success": true, "exit_ip": ip, "latency_ms": latency, "tls_ok": tlsOK, "message": "代理连通性和 TLS 检测正常"})
}
