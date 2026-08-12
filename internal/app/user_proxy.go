package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

func validateFixedProxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
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
	client, err := proxyHTTPClient(raw, 15*time.Second)
	if err != nil {
		return "", 0, false, err
	}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	res, err := client.Do(req)
	if err != nil {
		return "", time.Since(start).Milliseconds(), false, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", time.Since(start).Milliseconds(), false, fmt.Errorf("代理检测 HTTP %d", res.StatusCode)
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", 0, false, err
	}
	return strings.TrimSpace(body.IP), time.Since(start).Milliseconds(), res.TLS != nil, nil
}

func (s *Server) appleHTTPClientForOwner(ownerID string) (*http.Client, error) {
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
	if strings.TrimSpace(p.URL) != "" {
		if _, err := validateFixedProxyURL(p.URL); err != nil {
			writeError(w, 400, err)
			return
		}
		var err error
		cipher, err = encryptAutoSecret(s.cfg.AutoLoginSecret, p.URL)
		if err != nil {
			writeError(w, 503, err)
			return
		}
		masked = maskProxyURL(p.URL)
	}
	if cipher == "" {
		writeError(w, 400, errCode("proxy_required", "首次配置必须填写代理地址", false))
		return
	}
	c := UserProxyConfig{OwnerID: owner, URLCipher: cipher, URLMasked: masked, Enabled: p.Enabled, Status: "等待连通性测试", UpdatedAt: time.Now()}
	if err := s.store.SaveUserProxyConfig(c); err != nil {
		writeError(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": "固定代理已加密保存"})
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
