package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// parseAndSanitizeProxyPoolSource accepts both a Mihomo/Clash YAML document
// and the Base64 encoded share-link lists returned by many subscriptions.
func parseAndSanitizeProxyPoolSource(raw []byte) ([]byte, []ProxyPoolNode, error) {
	if len(raw) == 0 || len(raw) > maxProxyPoolSourceBytes {
		return nil, nil, errCode("proxy_pool_source_size", "代理配置为空或超过 4MB", false)
	}
	trimmed := strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff"))
	if looksLikeProxyShareList(trimmed) {
		return sanitizeProxyShareList(trimmed)
	}
	if decoded, ok := decodeProxySubscriptionBase64(trimmed); ok && looksLikeProxyShareList(string(decoded)) {
		return sanitizeProxyShareList(string(decoded))
	}
	return parseAndSanitizeProxyPoolYAML([]byte(trimmed))
}

func decodeProxySubscriptionBase64(raw string) ([]byte, bool) {
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, raw)
	if compact == "" {
		return nil, false
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(compact)
		if err == nil && len(decoded) > 0 && len(decoded) <= maxProxyPoolSourceBytes {
			return decoded, true
		}
	}
	return nil, false
}

func looksLikeProxyShareList(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	for _, scheme := range []string{"vless://", "vmess://", "trojan://", "http://", "https://", "socks5://", "ss://", "hysteria2://", "hy2://", "tuic://"} {
		if strings.HasPrefix(lower, scheme) || strings.Contains(lower, "\n"+scheme) || strings.Contains(lower, "\r"+scheme) {
			return true
		}
	}
	return false
}

func sanitizeProxyShareList(raw string) ([]byte, []ProxyPoolNode, error) {
	lines := strings.FieldsFunc(raw, func(r rune) bool { return r == '\r' || r == '\n' })
	proxies := make([]map[string]any, 0, len(lines))
	names := make(map[string]int)
	for lineNo, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxy, err := proxyMapFromShareLink(line)
		if err != nil {
			return nil, nil, errCode("proxy_pool_subscription_node", fmt.Sprintf("订阅第 %d 个节点格式错误：%v", lineNo+1, err), false)
		}
		name := strings.TrimSpace(fmt.Sprint(proxy["name"]))
		names[name]++
		if names[name] > 1 {
			proxy["name"] = fmt.Sprintf("%s #%d", name, names[name])
		}
		proxies = append(proxies, proxy)
	}
	if len(proxies) == 0 {
		return nil, nil, errCode("proxy_pool_empty", "订阅中没有可识别的代理节点", false)
	}
	document, err := yaml.Marshal(proxyPoolDocument{Proxies: proxies})
	if err != nil {
		return nil, nil, err
	}
	return parseAndSanitizeProxyPoolYAML(document)
}

func proxyMapFromShareLink(raw string) (map[string]any, error) {
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "vmess://") {
		return vmessProxyMap(strings.TrimSpace(raw[len("vmess://"):]))
	}
	if strings.HasPrefix(lower, "ss://") {
		return shadowsocksProxyMap(raw)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("分享链接无效")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("节点端口无效")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "https" {
		scheme = "http"
	}
	if scheme == "hy2" {
		scheme = "hysteria2"
	}
	name, _ := url.QueryUnescape(u.Fragment)
	name = strings.TrimSpace(name)
	if name == "" {
		name = fmt.Sprintf("%s-%s-%d", scheme, u.Hostname(), port)
	}
	proxy := map[string]any{"name": name, "type": scheme, "server": u.Hostname(), "port": port}
	query := u.Query()
	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	switch scheme {
	case "http", "socks5":
		if username != "" {
			proxy["username"] = username
		}
		if password != "" {
			proxy["password"] = password
		}
		if strings.EqualFold(u.Scheme, "https") {
			proxy["tls"] = true
		}
	case "vless":
		if username == "" {
			return nil, errors.New("VLESS UUID 为空")
		}
		proxy["uuid"] = username
		proxy["udp"] = true
		applyVLESSOptions(proxy, query)
	case "trojan":
		if username == "" {
			return nil, errors.New("Trojan 密码为空")
		}
		proxy["password"] = username
		proxy["udp"] = true
		proxy["tls"] = true
		applyTransportOptions(proxy, query)
	case "hysteria2":
		secret := username
		if password != "" {
			secret = password
		}
		if secret == "" {
			return nil, errors.New("Hysteria2 密码为空")
		}
		proxy["password"] = secret
		if sni := firstQuery(query, "sni", "peer"); sni != "" {
			proxy["sni"] = sni
		}
		if queryBool(query, "insecure", "allowInsecure") {
			proxy["skip-cert-verify"] = true
		}
		if obfs := query.Get("obfs"); obfs != "" {
			proxy["obfs"] = obfs
		}
		if obfsPassword := firstQuery(query, "obfs-password", "obfsPassword"); obfsPassword != "" {
			proxy["obfs-password"] = obfsPassword
		}
	case "tuic":
		if username == "" || password == "" {
			return nil, errors.New("TUIC UUID 或密码为空")
		}
		proxy["uuid"], proxy["password"], proxy["udp"] = username, password, true
		if sni := firstQuery(query, "sni", "servername"); sni != "" {
			proxy["sni"] = sni
		}
		if queryBool(query, "insecure", "allowInsecure") {
			proxy["skip-cert-verify"] = true
		}
	default:
		return nil, fmt.Errorf("暂不支持 %s 分享链接", u.Scheme)
	}
	return proxy, nil
}

func shadowsocksProxyMap(raw string) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("Shadowsocks 分享链接无效")
	}
	name, _ := url.QueryUnescape(u.Fragment)
	payload := strings.TrimPrefix(strings.SplitN(raw, "#", 2)[0], "ss://")
	var methodPassword, hostPort string
	if at := strings.LastIndex(payload, "@"); at >= 0 {
		methodPassword, hostPort = payload[:at], payload[at+1:]
		if decoded, ok := decodeProxySubscriptionBase64(methodPassword); ok {
			methodPassword = string(decoded)
		}
	} else {
		decoded, ok := decodeProxySubscriptionBase64(payload)
		if !ok {
			return nil, errors.New("Shadowsocks 节点不是有效的 Base64")
		}
		decodedPayload := string(decoded)
		at = strings.LastIndex(decodedPayload, "@")
		if at < 0 {
			return nil, errors.New("Shadowsocks 节点缺少服务器地址")
		}
		methodPassword, hostPort = decodedPayload[:at], decodedPayload[at+1:]
	}
	methodPassword, _ = url.QueryUnescape(methodPassword)
	colon := strings.Index(methodPassword, ":")
	if colon <= 0 {
		return nil, errors.New("Shadowsocks 加密方式或密码无效")
	}
	hostPort, _ = url.QueryUnescape(hostPort)
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, errors.New("Shadowsocks 服务器地址无效")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("Shadowsocks 端口无效")
	}
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("ss-%s-%d", host, port)
	}
	return map[string]any{"name": name, "type": "ss", "server": strings.Trim(host, "[]"), "port": port, "cipher": methodPassword[:colon], "password": methodPassword[colon+1:], "udp": true}, nil
}

func applyVLESSOptions(proxy map[string]any, query url.Values) {
	security := strings.ToLower(query.Get("security"))
	if security == "tls" || security == "reality" {
		proxy["tls"] = true
	}
	if flow := query.Get("flow"); flow != "" {
		proxy["flow"] = flow
	}
	if fingerprint := firstQuery(query, "fp", "fingerprint"); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
	if security == "reality" {
		reality := map[string]any{}
		if publicKey := firstQuery(query, "pbk", "public-key"); publicKey != "" {
			reality["public-key"] = publicKey
		}
		if shortID := firstQuery(query, "sid", "short-id"); shortID != "" {
			reality["short-id"] = shortID
		}
		if len(reality) > 0 {
			proxy["reality-opts"] = reality
		}
	}
	applyTransportOptions(proxy, query)
}

func applyTransportOptions(proxy map[string]any, query url.Values) {
	if sni := firstQuery(query, "sni", "serverName", "servername"); sni != "" {
		proxy["servername"] = sni
	}
	if queryBool(query, "insecure", "allowInsecure") {
		proxy["skip-cert-verify"] = true
	}
	network := strings.ToLower(firstQuery(query, "type", "network"))
	if network == "" || network == "tcp" {
		return
	}
	proxy["network"] = network
	switch network {
	case "ws":
		options := map[string]any{}
		if path := query.Get("path"); path != "" {
			options["path"] = path
		}
		if host := query.Get("host"); host != "" {
			options["headers"] = map[string]any{"Host": host}
		}
		if len(options) > 0 {
			proxy["ws-opts"] = options
		}
	case "grpc":
		if service := firstQuery(query, "serviceName", "service-name"); service != "" {
			proxy["grpc-opts"] = map[string]any{"grpc-service-name": service}
		}
	}
}

func firstQuery(values url.Values, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func queryBool(values url.Values, keys ...string) bool {
	value := strings.ToLower(firstQuery(values, keys...))
	return value == "1" || value == "true" || value == "yes"
}

func vmessProxyMap(encoded string) (map[string]any, error) {
	decoded, ok := decodeProxySubscriptionBase64(encoded)
	if !ok {
		return nil, errors.New("VMess 节点不是有效的 Base64")
	}
	var value map[string]any
	if err := json.Unmarshal(decoded, &value); err != nil {
		return nil, errors.New("VMess 节点 JSON 无效")
	}
	server := strings.TrimSpace(fmt.Sprint(value["add"]))
	port, err := intValue(value["port"])
	uuid := strings.TrimSpace(fmt.Sprint(value["id"]))
	if server == "" || uuid == "" || err != nil || port < 1 || port > 65535 {
		return nil, errors.New("VMess 服务器、端口或 UUID 无效")
	}
	name := strings.TrimSpace(fmt.Sprint(value["ps"]))
	if name == "" || name == "<nil>" {
		name = fmt.Sprintf("vmess-%s-%d", server, port)
	}
	proxy := map[string]any{"name": name, "type": "vmess", "server": server, "port": port, "uuid": uuid, "alterId": 0, "cipher": "auto", "udp": true}
	if alterID, alterErr := intValue(value["aid"]); alterErr == nil {
		proxy["alterId"] = alterID
	}
	if cipher := strings.TrimSpace(fmt.Sprint(value["scy"])); cipher != "" && cipher != "<nil>" {
		proxy["cipher"] = cipher
	}
	query := make(url.Values)
	for source, target := range map[string]string{"net": "type", "host": "host", "path": "path", "sni": "sni"} {
		if item := strings.TrimSpace(fmt.Sprint(value[source])); item != "" && item != "<nil>" {
			query.Set(target, item)
		}
	}
	if strings.EqualFold(strings.TrimSpace(fmt.Sprint(value["tls"])), "tls") {
		proxy["tls"] = true
	}
	applyTransportOptions(proxy, query)
	return proxy, nil
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
	host = strings.TrimSpace(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if ip := net.ParseIP(host); ip != nil {
		if isUnsafeProxyIP(ip) {
			return errors.New("unsafe")
		}
		return nil
	}
	lower := strings.ToLower(host)
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") || strings.ContainsAny(host, " /\\@:#") ||
		lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".lan") || strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".home.arpa") ||
		strings.HasSuffix(lower, ".localdomain") {
		return errors.New("unsafe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		// Proxy subscription domains may intentionally be resolved by Mihomo's
		// own DNS or through a dialer proxy. A local DNS miss is not proof that
		// the configured destination is private.
		return nil
	}
	for _, ip := range ips {
		if !isUnsafeProxyIP(ip) {
			return nil
		}
	}
	return errors.New("unsafe")
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
		URL        string `json:"url"`
		YAML       string `json:"yaml"`
		// Kept for compatibility with the GitHub frontend; local node names
		// remain the names from the imported Mihomo document.
		TagPrefix string `json:"tag_prefix"`
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
	if source == "" && strings.TrimSpace(payload.YAML) != "" {
		typ, source, payload.Enabled = "yaml", strings.TrimSpace(payload.YAML), true
	}
	if source == "" && strings.TrimSpace(payload.URL) != "" {
		typ, source, payload.Enabled = "subscription", strings.TrimSpace(payload.URL), true
	}
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
	clean, nodes, err := parseAndSanitizeProxyPoolSource(data)
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
	clean, nodes, err := parseAndSanitizeProxyPoolSource(data)
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
		NodeTag   string `json:"node_tag"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, 400, err)
		return
	}
	owner := requestOwnerID(r, s.store)
	if strings.TrimSpace(payload.Node) == "" {
		payload.Node = payload.NodeTag
	}
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

type proxyPoolNodeTestResult struct {
	Available    bool      `json:"available"`
	LatencyMS    int64     `json:"latency_ms"`
	ExitIP       string    `json:"exit_ip,omitempty"`
	TLSOK        bool      `json:"tls_ok"`
	LastError    string    `json:"last_error,omitempty"`
	LastTestedAt time.Time `json:"last_tested_at,omitempty"`
}

type proxyPoolTestJob struct {
	ID        string `json:"id"`
	OwnerID   string `json:"-"`
	Status    string `json:"status"`
	Total     int    `json:"total"`
	Completed int    `json:"completed"`
	Passed    int    `json:"passed"`
	Failed    int    `json:"failed"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) handleProxyPoolNodesCompat(w http.ResponseWriter, r *http.Request) {
	owner := requestOwnerID(r, s.store)
	config, _ := s.store.UserProxyConfig(owner)
	state := s.store.SnapshotForOwner(owner)
	bound := make(map[string][]string)
	for _, account := range state.Accounts {
		if node := strings.TrimSpace(account.ProxyPoolNode); node != "" {
			label := firstNonEmpty(account.AppleID, account.Label, account.ID)
			bound[node] = append(bound[node], label)
		}
	}
	s.proxyPoolTestMu.Lock()
	results := make(map[string]proxyPoolNodeTestResult)
	for name, result := range s.proxyPoolNodeResults[owner] {
		results[name] = result
	}
	s.proxyPoolTestMu.Unlock()
	nodes := make([]map[string]any, 0, len(config.PoolNodes))
	for _, node := range config.PoolNodes {
		result, tested := results[node.Name]
		nodes = append(nodes, map[string]any{
			"tag": node.Name, "name": node.Name, "type": node.Type,
			"available": tested && result.Available, "blacklisted": false,
			"latency_ms": map[bool]int64{true: result.LatencyMS, false: -1}[tested],
			"exit_ip":    result.ExitIP, "tls_ok": result.TLSOK,
			"last_error": result.LastError, "bound_accounts": bound[node.Name],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "enabled": config.PoolEnabled, "nodes": nodes})
}

func (s *Server) handleStartProxyPoolTestCompat(w http.ResponseWriter, r *http.Request) {
	owner := requestOwnerID(r, s.store)
	config, ok := s.store.UserProxyConfig(owner)
	if !ok || !config.PoolEnabled || len(config.PoolNodes) == 0 {
		writeError(w, http.StatusBadRequest, errCode("proxy_pool_disabled", "该账号绑定的代理池未启用或没有节点", false))
		return
	}
	jobID, err := randomToken(18)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	job := &proxyPoolTestJob{ID: jobID, OwnerID: owner, Status: "running", Total: len(config.PoolNodes), Message: "代理节点异步测速已启动"}
	s.proxyPoolTestMu.Lock()
	s.proxyPoolTestJobs[job.ID] = job
	s.proxyPoolNodeResults[owner] = make(map[string]proxyPoolNodeTestResult, len(config.PoolNodes))
	s.proxyPoolTestMu.Unlock()
	go s.runProxyPoolTestJob(job.ID, owner, config.PoolNodes)
	writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "job_id": job.ID, "id": job.ID, "message": job.Message})
}

func (s *Server) runProxyPoolTestJob(jobID, owner string, nodes []ProxyPoolNode) {
	type completedResult struct {
		name   string
		result proxyPoolNodeTestResult
	}
	results := make(chan completedResult, len(nodes))
	limit := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, node := range nodes {
		node := node
		wg.Add(1)
		go func() {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			result := proxyPoolNodeTestResult{LatencyMS: -1}
			port, err := s.proxyPool.ensure(owner, node.Name)
			if err == nil {
				result.ExitIP, result.LatencyMS, result.TLSOK, err = testLoopbackHTTPProxy(ctx, port)
			}
			result.Available = err == nil
			if err != nil {
				result.LastError = err.Error()
			}
			result.LastTestedAt = time.Now()
			_ = s.store.SaveProxyPoolNodeResult(owner, node.Name, ProxyPoolNode{
				Name: node.Name, Available: result.Available, LatencyMS: result.LatencyMS,
				ExitIP: result.ExitIP, TLSOK: result.TLSOK, LastError: result.LastError,
				LastTestedAt: result.LastTestedAt,
			})
			results <- completedResult{name: node.Name, result: result}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	for completed := range results {
		s.proxyPoolTestMu.Lock()
		s.proxyPoolNodeResults[owner][completed.name] = completed.result
		job := s.proxyPoolTestJobs[jobID]
		job.Completed++
		if completed.result.Available {
			job.Passed++
		} else {
			job.Failed++
		}
		s.proxyPoolTestMu.Unlock()
	}
	s.proxyPoolTestMu.Lock()
	if job := s.proxyPoolTestJobs[jobID]; job != nil {
		job.Status = "finished"
		job.Message = fmt.Sprintf("测速完成：可用 %d，不可用 %d", job.Passed, job.Failed)
	}
	s.proxyPoolTestMu.Unlock()
}

func (s *Server) handleProxyPoolTestStatusCompat(w http.ResponseWriter, r *http.Request) {
	owner, id := requestOwnerID(r, s.store), strings.TrimSpace(r.URL.Query().Get("id"))
	s.proxyPoolTestMu.Lock()
	job := s.proxyPoolTestJobs[id]
	if job != nil && job.OwnerID == owner {
		copy := *job
		s.proxyPoolTestMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "job": copy, "result": copy, "status": copy.Status, "total": copy.Total, "completed": copy.Completed, "passed": copy.Passed, "failed": copy.Failed, "message": copy.Message})
		return
	}
	s.proxyPoolTestMu.Unlock()
	writeError(w, http.StatusNotFound, errCode("proxy_pool_test_missing", "测速任务不存在或已过期", false))
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
