package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const maxProxyPoolSourceBytes = 4 << 20

type proxyPoolDocument struct {
	Proxies []map[string]any `yaml:"proxies"`
}

type proxyPoolRuntime struct {
	cfg    Config
	store  *FileStore
	logger *slog.Logger
	mu     sync.Mutex
	owners map[string]*proxyPoolOwnerRuntime
}

type proxyPoolOwnerRuntime struct {
	cmd       *exec.Cmd
	ports     map[string]int
	signature string
	dir       string
}

func newProxyPoolRuntime(cfg Config, store *FileStore, logger *slog.Logger) *proxyPoolRuntime {
	return &proxyPoolRuntime{cfg: cfg, store: store, logger: logger, owners: make(map[string]*proxyPoolOwnerRuntime)}
}

func parseAndSanitizeProxyPoolYAML(raw []byte) ([]byte, []ProxyPoolNode, error) {
	if len(raw) == 0 || len(raw) > maxProxyPoolSourceBytes {
		return nil, nil, errCode("proxy_pool_source_size", "代理配置为空或超过 4MB", false)
	}
	var input proxyPoolDocument
	if err := yaml.Unmarshal(raw, &input); err != nil {
		return nil, nil, errCode("proxy_pool_yaml_invalid", "YAML 格式错误："+err.Error(), false)
	}
	if len(input.Proxies) == 0 {
		return nil, nil, errCode("proxy_pool_empty", "配置中没有 proxies 节点", false)
	}
	if len(input.Proxies) > 500 {
		return nil, nil, errCode("proxy_pool_too_many", "单个用户最多导入 500 个代理节点", false)
	}
	allowedTypes := map[string]bool{"http": true, "socks5": true, "ss": true, "ssr": true, "vmess": true, "vless": true, "trojan": true, "hysteria": true, "hysteria2": true, "tuic": true, "wireguard": true, "anytls": true, "mieru": true, "ssh": true, "snell": true}
	names := make(map[string]bool, len(input.Proxies))
	nodes := make([]ProxyPoolNode, 0, len(input.Proxies))
	for _, proxy := range input.Proxies {
		name := strings.TrimSpace(fmt.Sprint(proxy["name"]))
		typ := strings.ToLower(strings.TrimSpace(fmt.Sprint(proxy["type"])))
		if name == "" || len([]rune(name)) > 120 {
			return nil, nil, errCode("proxy_pool_node_name", "代理节点名称为空或过长", false)
		}
		if names[name] {
			return nil, nil, errCode("proxy_pool_node_duplicate", "代理节点名称重复："+name, false)
		}
		if !allowedTypes[typ] {
			return nil, nil, errCode("proxy_pool_node_type", "暂不允许代理协议："+typ, false)
		}
		server := strings.TrimSpace(fmt.Sprint(proxy["server"]))
		port, portErr := intValue(proxy["port"])
		if server == "" || portErr != nil || port < 1 || port > 65535 {
			return nil, nil, errCode("proxy_pool_node_address", "节点服务器或端口无效："+name, false)
		}
		if err := validatePublicProxyHost(server); err != nil {
			return nil, nil, errCode("proxy_pool_node_private", "节点不能指向本机或内网："+name, false)
		}
		delete(proxy, "interface-name")
		delete(proxy, "routing-mark")
		dialer := strings.TrimSpace(fmt.Sprint(proxy["dialer-proxy"]))
		if dialer == "<nil>" {
			dialer = ""
		}
		names[name] = true
		nodes = append(nodes, ProxyPoolNode{Name: name, Type: typ, DialerProxy: dialer})
	}
	byName := make(map[string]string, len(nodes))
	for _, n := range nodes {
		byName[n.Name] = n.DialerProxy
	}
	for _, n := range nodes {
		if n.DialerProxy != "" && !names[n.DialerProxy] {
			return nil, nil, errCode("proxy_pool_dialer_missing", "节点 "+n.Name+" 引用的 dialer-proxy 不存在", false)
		}
	}
	for _, n := range nodes {
		seen := map[string]bool{}
		current := n.Name
		for depth := 0; current != ""; depth++ {
			if depth > 8 || seen[current] {
				return nil, nil, errCode("proxy_pool_dialer_cycle", "代理链存在循环或超过 8 层："+n.Name, false)
			}
			seen[current] = true
			current = byName[current]
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return strings.ToLower(nodes[i].Name) < strings.ToLower(nodes[j].Name) })
	clean := proxyPoolDocument{Proxies: input.Proxies}
	out, err := yaml.Marshal(clean)
	if err != nil {
		return nil, nil, err
	}
	return out, nodes, nil
}

func intValue(value any) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case uint64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(v)
	default:
		return 0, errors.New("invalid integer")
	}
}

func validatePublicProxyHost(host string) error {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if isUnsafeProxyIP(ip) {
			return errors.New("unsafe")
		}
		return nil
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".local") {
		return errors.New("unsafe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return errors.New("dns lookup failed")
	}
	for _, ip := range ips {
		if isUnsafeProxyIP(ip) {
			return errors.New("unsafe")
		}
	}
	return nil
}

func isUnsafeProxyIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func fetchProxySubscription(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, errCode("proxy_pool_subscription_url", "订阅链接必须是有效的 HTTPS 地址", false)
	}
	if err = validatePublicProxyHost(u.Hostname()); err != nil {
		return nil, errCode("proxy_pool_subscription_private", "订阅链接不能指向本机或内网", false)
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			if isUnsafeProxyIP(ip) {
				return nil, errors.New("订阅域名解析到内网地址")
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}}
	client := &http.Client{Timeout: 20 * time.Second, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("订阅重定向过多")
		}
		if req.URL.Scheme != "https" || validatePublicProxyHost(req.URL.Hostname()) != nil {
			return errors.New("订阅重定向地址不安全")
		}
		return nil
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("User-Agent", "iCloud-Privacy-Mail/ProxyPool")
	res, err := client.Do(req)
	if err != nil {
		return nil, errCode("proxy_pool_subscription_fetch", "读取订阅失败："+err.Error(), true)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errCode("proxy_pool_subscription_http", fmt.Sprintf("订阅返回 HTTP %d", res.StatusCode), true)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxProxyPoolSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProxyPoolSourceBytes {
		return nil, errCode("proxy_pool_source_size", "订阅内容超过 4MB", false)
	}
	return data, nil
}

func (p *proxyPoolRuntime) client(ownerID, accountID, appleID string) (*http.Client, bool, error) {
	node := p.store.ProxyPoolNodeForAccount(ownerID, accountID, appleID)
	if node == "" {
		return nil, false, nil
	}
	port, err := p.ensure(ownerID, node)
	if err != nil {
		return nil, true, err
	}
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)})}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, true, nil
}

func (p *proxyPoolRuntime) ensure(ownerID, node string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	config, ok := p.store.UserProxyConfig(ownerID)
	if !ok || !config.PoolEnabled {
		return 0, errCode("proxy_pool_disabled", "该账号绑定的代理池未启用", false)
	}
	valid := false
	for _, n := range config.PoolNodes {
		if n.Name == node {
			valid = true
			break
		}
	}
	if !valid {
		return 0, errCode("proxy_pool_node_missing", "账号绑定的代理节点已不存在，请重新选择", false)
	}
	raw, err := decryptAutoSecret(p.cfg.AutoLoginSecret, config.PoolYAMLCipher)
	if err != nil {
		return 0, errCode("proxy_pool_decrypt", "代理池无法解密", false)
	}
	sigBytes := sha256.Sum256([]byte(raw))
	signature := hex.EncodeToString(sigBytes[:])
	if current := p.owners[ownerID]; current != nil && current.signature == signature && current.cmd != nil && current.cmd.Process != nil && current.cmd.ProcessState == nil {
		if port := current.ports[node]; port > 0 {
			return port, nil
		}
	}
	return p.startLocked(ownerID, raw, config.PoolNodes, signature, node)
}

func (p *proxyPoolRuntime) startLocked(ownerID, raw string, nodes []ProxyPoolNode, signature, wanted string) (int, error) {
	if old := p.owners[ownerID]; old != nil && old.cmd != nil && old.cmd.Process != nil {
		_ = old.cmd.Process.Kill()
	}
	root := p.cfg.ProxyPoolRuntimeDir
	if root == "" {
		root = filepath.Join(filepath.Dir(p.cfg.DataPath), "proxy-pools")
	}
	h := sha256.Sum256([]byte(ownerID))
	dir := filepath.Join(root, hex.EncodeToString(h[:8]))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return 0, err
	}
	var doc proxyPoolDocument
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return 0, err
	}
	ports := make(map[string]int, len(nodes))
	listeners := make([]map[string]any, 0, len(nodes))
	for i, n := range nodes {
		port, err := freeLocalPort()
		if err != nil {
			return 0, err
		}
		ports[n.Name] = port
		listeners = append(listeners, map[string]any{"name": fmt.Sprintf("account-node-%d", i+1), "type": "mixed", "listen": "127.0.0.1", "port": port, "proxy": n.Name})
	}
	runtimeDoc := map[string]any{"allow-lan": false, "mode": "direct", "log-level": "warning", "ipv6": false, "proxies": doc.Proxies, "listeners": listeners, "rules": []string{"MATCH,DIRECT"}}
	content, err := yaml.Marshal(runtimeDoc)
	if err != nil {
		return 0, err
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(configPath, content, 0600); err != nil {
		return 0, err
	}
	binary := strings.TrimSpace(p.cfg.MihomoBinary)
	if binary == "" {
		binary = "mihomo"
	}
	cmd := exec.Command(binary, "-d", dir, "-f", configPath)
	logFile, logErr := os.OpenFile(filepath.Join(dir, "mihomo.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if logErr == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err = cmd.Start(); err != nil {
		if logFile != nil {
			logFile.Close()
		}
		return 0, errCode("proxy_pool_runtime_missing", "Mihomo 未安装或无法启动："+err.Error(), false)
	}
	runtime := &proxyPoolOwnerRuntime{cmd: cmd, ports: ports, signature: signature, dir: dir}
	p.owners[ownerID] = runtime
	go func() {
		err := cmd.Wait()
		if logFile != nil {
			logFile.Close()
		}
		if p.logger != nil && err != nil {
			p.logger.Warn("proxy pool runtime stopped", "owner", ownerID, "err", err)
		}
	}()
	deadline := time.Now().Add(8 * time.Second)
	port := ports[wanted]
	for time.Now().Before(deadline) {
		conn, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 250*time.Millisecond)
		if e == nil {
			conn.Close()
			return port, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, errCode("proxy_pool_runtime_start", "代理池启动超时，请检查节点配置", true)
}

func freeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func (p *proxyPoolRuntime) restart(ownerID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old := p.owners[ownerID]; old != nil && old.cmd != nil && old.cmd.Process != nil {
		_ = old.cmd.Process.Kill()
	}
	delete(p.owners, ownerID)
}

func (p *proxyPoolRuntime) stopAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ownerID, runtime := range p.owners {
		if runtime != nil && runtime.cmd != nil && runtime.cmd.Process != nil && runtime.cmd.ProcessState == nil {
			_ = runtime.cmd.Process.Kill()
		}
		delete(p.owners, ownerID)
	}
}

func (s *Server) StopProxyPool() {
	if s.proxyPool != nil {
		s.proxyPool.stopAll()
	}
}

func (s *Server) handleGetProxyPool(w http.ResponseWriter, r *http.Request) {
	owner := requestOwnerID(r, s.store)
	c, ok := s.store.UserProxyConfig(owner)
	writeJSON(w, 200, map[string]any{"success": true, "configured": ok && c.PoolYAMLCipher != "", "pool": map[string]any{"enabled": c.PoolEnabled, "source_type": c.PoolSourceType, "source_masked": c.PoolSourceMasked, "nodes": c.PoolNodes, "status": c.PoolStatus, "last_error": c.PoolLastError, "updated_at": formatTime(c.PoolUpdatedAt)}})
}

func (s *Server) handleImportProxyPool(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		SourceType string `json:"source_type"`
		Source     string `json:"source"`
		Enabled    bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, 400, err)
		return
	}
	owner := requestOwnerID(r, s.store)
	if strings.TrimSpace(s.cfg.AutoLoginSecret) == "" {
		writeError(w, 503, errCode("proxy_pool_secret_missing", "服务器未配置代理池加密密钥", false))
		return
	}
	typ := strings.ToLower(strings.TrimSpace(payload.SourceType))
	source := strings.TrimSpace(payload.Source)
	var data []byte
	var err error
	switch typ {
	case "yaml":
		data = []byte(source)
	case "subscription":
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		data, err = fetchProxySubscription(ctx, source)
	default:
		err = errCode("proxy_pool_source_type", "请选择 YAML 或订阅链接", false)
	}
	if err != nil {
		writeError(w, 400, err)
		return
	}
	clean, nodes, err := parseAndSanitizeProxyPoolYAML(data)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	yamlCipher, err := encryptAutoSecret(s.cfg.AutoLoginSecret, string(clean))
	if err != nil {
		writeError(w, 503, err)
		return
	}
	sourceCipher, err := encryptAutoSecret(s.cfg.AutoLoginSecret, source)
	if err != nil {
		writeError(w, 503, err)
		return
	}
	c, _ := s.store.UserProxyConfig(owner)
	c.OwnerID = owner
	c.PoolEnabled = payload.Enabled
	c.PoolSourceType = typ
	c.PoolSourceCipher = sourceCipher
	c.PoolYAMLCipher = yamlCipher
	c.PoolNodes = nodes
	c.PoolStatus = "代理池已导入"
	c.PoolLastError = ""
	c.PoolUpdatedAt = time.Now()
	if typ == "subscription" {
		c.PoolSourceMasked = maskSubscriptionURL(source)
	} else {
		c.PoolSourceMasked = "手动 YAML（内容已加密）"
	}
	if err = s.store.SaveUserProxyConfig(c); err != nil {
		writeError(w, 500, err)
		return
	}
	if s.proxyPool != nil {
		s.proxyPool.restart(owner)
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": fmt.Sprintf("代理池已加密导入，共 %d 个节点", len(nodes)), "nodes": nodes})
}

func maskSubscriptionURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "已配置订阅"
	}
	u.RawQuery = ""
	u.Fragment = ""
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

func (s *Server) handleRefreshProxyPool(w http.ResponseWriter, r *http.Request) {
	owner := requestOwnerID(r, s.store)
	c, ok := s.store.UserProxyConfig(owner)
	if !ok || c.PoolSourceType != "subscription" || c.PoolSourceCipher == "" {
		writeError(w, 400, errCode("proxy_pool_subscription_missing", "当前代理池不是订阅链接导入", false))
		return
	}
	source, err := decryptAutoSecret(s.cfg.AutoLoginSecret, c.PoolSourceCipher)
	if err != nil {
		writeError(w, 503, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	data, err := fetchProxySubscription(ctx, source)
	if err != nil {
		writeError(w, 502, err)
		return
	}
	clean, nodes, err := parseAndSanitizeProxyPoolYAML(data)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	c.PoolYAMLCipher, err = encryptAutoSecret(s.cfg.AutoLoginSecret, string(clean))
	if err != nil {
		writeError(w, 503, err)
		return
	}
	c.PoolNodes = nodes
	c.PoolUpdatedAt = time.Now()
	c.PoolStatus = "订阅已刷新"
	c.PoolLastError = ""
	if err = s.store.SaveUserProxyConfig(c); err != nil {
		writeError(w, 500, err)
		return
	}
	s.proxyPool.restart(owner)
	writeJSON(w, 200, map[string]any{"success": true, "message": fmt.Sprintf("订阅已刷新，共 %d 个节点", len(nodes)), "nodes": nodes})
}

func (s *Server) handleSetProxyPoolStatus(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	owner := requestOwnerID(r, s.store)
	c, ok := s.store.UserProxyConfig(owner)
	if !ok || c.PoolYAMLCipher == "" || len(c.PoolNodes) == 0 {
		writeError(w, http.StatusBadRequest, errCode("proxy_pool_missing", "请先导入代理池配置", false))
		return
	}
	c.PoolEnabled = payload.Enabled
	c.PoolUpdatedAt = time.Now()
	if payload.Enabled {
		c.PoolStatus = "代理池已启用"
		c.PoolLastError = ""
	} else {
		c.PoolStatus = "代理池已暂停"
	}
	if err := s.store.SaveUserProxyConfig(c); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !payload.Enabled && s.proxyPool != nil {
		s.proxyPool.restart(owner)
	}
	message := "代理池已暂停"
	if payload.Enabled {
		message = "代理池已启用"
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "enabled": payload.Enabled, "message": message})
}

func (s *Server) handleBindAccountProxyPool(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
		Node      string `json:"node"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, 400, err)
		return
	}
	owner := requestOwnerID(r, s.store)
	if strings.TrimSpace(payload.AccountID) == "" {
		writeError(w, 400, errCode("account_required", "请选择 Apple 账号", false))
		return
	}
	if strings.TrimSpace(payload.Node) != "" {
		c, ok := s.store.UserProxyConfig(owner)
		found := false
		if ok {
			for _, n := range c.PoolNodes {
				if n.Name == strings.TrimSpace(payload.Node) {
					found = true
					break
				}
			}
		}
		if !found {
			writeError(w, 400, errCode("proxy_pool_node_missing", "选择的代理节点不存在", false))
			return
		}
	}
	if err := s.store.SaveAccountProxyPoolNode(owner, payload.AccountID, payload.Node); err != nil {
		writeError(w, 404, err)
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": firstNonEmpty(map[bool]string{true: "账号已改回原有固定代理/直连", false: "账号已绑定固定代理池节点"}[strings.TrimSpace(payload.Node) == ""], "代理设置已保存")})
}

func (s *Server) handleTestAccountProxyPool(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
		Node      string `json:"node"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, 400, err)
		return
	}
	owner := requestOwnerID(r, s.store)
	node := strings.TrimSpace(payload.Node)
	if node == "" {
		node = s.store.ProxyPoolNodeForAccount(owner, payload.AccountID, "")
	}
	if node == "" {
		writeError(w, 400, errCode("proxy_pool_node_required", "请选择代理池节点", false))
		return
	}
	port, err := s.proxyPool.ensure(owner, node)
	if err != nil {
		writeError(w, 502, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ip, latency, tlsOK, err := testLoopbackHTTPProxy(ctx, port)
	if err != nil {
		writeError(w, 502, errCode("proxy_pool_test_failed", "节点检测失败："+err.Error(), true))
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "node": node, "exit_ip": ip, "latency_ms": latency, "tls_ok": tlsOK, "message": "代理节点连通正常"})
}

func testLoopbackHTTPProxy(ctx context.Context, port int) (string, int64, bool, error) {
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)})}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	started := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://checkip.amazonaws.com/", nil)
	res, err := client.Do(req)
	if err != nil {
		return "", time.Since(started).Milliseconds(), false, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1024))
	if err != nil {
		return "", 0, res.TLS != nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", 0, res.TLS != nil, fmt.Errorf("检测地址返回 HTTP %d", res.StatusCode)
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", 0, res.TLS != nil, errors.New("未返回有效出口 IP")
	}
	return ip, time.Since(started).Milliseconds(), res.TLS != nil, nil
}
