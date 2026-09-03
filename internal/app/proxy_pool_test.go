package app

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseProxyPoolPreservesDialerAndDropsRuntimeConfig(t *testing.T) {
	raw := []byte(`mixed-port: 7890
allow-lan: true
external-controller: 0.0.0.0:9090
proxies:
  - name: tunnel
    type: hysteria2
    server: 1.1.1.1
    port: 443
    password: secret
  - name: residential
    type: http
    server: 8.8.8.8
    port: 3000
    username: user
    password: pass
    dialer-proxy: tunnel
rules:
  - MATCH,residential
`)
	clean, nodes, err := parseAndSanitizeProxyPoolYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes=%d", len(nodes))
	}
	var found bool
	for _, node := range nodes {
		if node.Name == "residential" && node.DialerProxy == "tunnel" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dialer-proxy not preserved: %+v", nodes)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(clean, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 1 || doc["proxies"] == nil {
		t.Fatalf("unsafe top-level config survived: %#v", doc)
	}
	if strings.Contains(string(clean), "external-controller") || strings.Contains(string(clean), "mixed-port") {
		t.Fatalf("runtime config leaked: %s", clean)
	}
}

func TestParseProxyPoolSourceAcceptsBase64VLESSSubscription(t *testing.T) {
	links := strings.Join([]string{
		"vless://11111111-1111-1111-1111-111111111111@8.8.8.8:443?encryption=none&security=tls&sni=example.com&type=ws&host=cdn.example.com&path=%2Fws#Tokyo",
		"socks5://user:pass@1.1.1.1:1080#Backup",
	}, "\n")
	raw := []byte(base64.StdEncoding.EncodeToString([]byte(links)))
	clean, nodes, err := parseAndSanitizeProxyPoolSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes=%d, want 2", len(nodes))
	}
	var document proxyPoolDocument
	if err := yaml.Unmarshal(clean, &document); err != nil {
		t.Fatal(err)
	}
	var vless map[string]any
	for _, proxy := range document.Proxies {
		if proxy["type"] == "vless" {
			vless = proxy
		}
	}
	if vless == nil || vless["uuid"] != "11111111-1111-1111-1111-111111111111" || vless["tls"] != true || vless["network"] != "ws" {
		t.Fatalf("unexpected VLESS proxy: %#v", vless)
	}
	if vless["servername"] != "example.com" {
		t.Fatalf("VLESS SNI not preserved: %#v", vless)
	}
}

func TestParseProxyPoolSourceKeepsYAMLCompatibility(t *testing.T) {
	raw := []byte("proxies:\n  - {name: direct-http, type: http, server: 8.8.8.8, port: 8080}\n")
	_, nodes, err := parseAndSanitizeProxyPoolSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "direct-http" {
		t.Fatalf("unexpected nodes: %+v", nodes)
	}
}

func TestParseProxyPoolRejectsDialerCycleAndPrivateTarget(t *testing.T) {
	cycle := []byte(`proxies:
  - {name: a, type: http, server: 1.1.1.1, port: 80, dialer-proxy: b}
  - {name: b, type: socks5, server: 8.8.8.8, port: 1080, dialer-proxy: a}
`)
	if _, _, err := parseAndSanitizeProxyPoolYAML(cycle); err == nil {
		t.Fatal("expected cycle rejection")
	}
	private := []byte(`proxies:
  - {name: internal, type: http, server: 127.0.0.1, port: 8080}
`)
	if _, _, err := parseAndSanitizeProxyPoolYAML(private); err == nil {
		t.Fatal("expected private target rejection")
	}
}

func TestParseProxyPoolAllowsPublicShapedDomainWithoutLocalDNS(t *testing.T) {
	raw := []byte(`proxies:
  - {name: remote-dns, type: vless, server: edge-node.example.invalid, port: 443, uuid: 11111111-1111-1111-1111-111111111111}
`)
	_, nodes, err := parseAndSanitizeProxyPoolYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "remote-dns" {
		t.Fatalf("unexpected nodes: %+v", nodes)
	}
}

func TestParseProxyPlainList(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantCount int
		wantType  string
		wantUser  string
	}{
		{"host_port", "1.2.3.4:8080", 1, "http", ""},
		{"host_port_user_pass", "1.2.3.4:8080:user:pass", 1, "http", "user"},
		{"user_pass_at_host_port", "user:pass@1.2.3.4:8080", 1, "http", "user"},
		{"http_url", "http://user:pass@example.com:8080", 1, "http", "user"},
		{"socks5_url", "socks5://user:pass@example.com:1080", 1, "socks5", "user"},
		{"multiple_lines", "1.1.1.1:8080\n2.2.2.2:8081:u:p\nhttp://u:p@3.3.3.3:8082", 3, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clean, nodes, err := parseAndSanitizeProxyPoolSource([]byte(tc.input))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(nodes) != tc.wantCount {
				t.Fatalf("nodes=%d want %d (%+v)", len(nodes), tc.wantCount, nodes)
			}
			if tc.wantType != "" && nodes[0].Type != tc.wantType {
				t.Fatalf("type=%s want %s", nodes[0].Type, tc.wantType)
			}
			var doc map[string]any
			if err := yaml.Unmarshal(clean, &doc); err != nil {
				t.Fatal(err)
			}
			proxies := doc["proxies"].([]any)
			if tc.wantUser != "" {
				p := proxies[0].(map[string]any)
				if got := p["username"]; got != tc.wantUser {
					t.Fatalf("username=%v want %s", got, tc.wantUser)
				}
			}
		})
	}
}

func TestParseProxyPlainListRejectsPrivateHost(t *testing.T) {
	_, _, err := parseAndSanitizeProxyPoolSource([]byte("127.0.0.1:8080"))
	if err == nil {
		t.Fatal("expected error for private host")
	}
}

func TestDeleteUserProxyPoolUnbindsOnlyOwnerAccounts(t *testing.T) {
	store := newTestStore(t)
	// Two users, each with a proxy pool config and a bound account.
	ownerA := "user-a"
	ownerB := "user-b"
	poolA := UserProxyConfig{OwnerID: ownerA, PoolEnabled: true, PoolYAMLCipher: "cipher-a", PoolNodes: []ProxyPoolNode{{Name: "node-a1", Type: "http"}}}
	poolB := UserProxyConfig{OwnerID: ownerB, PoolEnabled: true, PoolYAMLCipher: "cipher-b", PoolNodes: []ProxyPoolNode{{Name: "node-b1", Type: "http"}}}
	if err := store.SaveUserProxyConfig(poolA); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUserProxyConfig(poolB); err != nil {
		t.Fatal(err)
	}
	accA, err := store.AddAccountForOwner(ownerA, "a", "a@icloud.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accB, err := store.AddAccountForOwner(ownerB, "b", "b@icloud.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccountProxyPoolNode(ownerA, accA.ID, "node-a1"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccountProxyPoolNode(ownerB, accB.ID, "node-b1"); err != nil {
		t.Fatal(err)
	}

	bound, err := store.DeleteUserProxyPool(ownerA)
	if err != nil {
		t.Fatal(err)
	}
	if bound != 1 {
		t.Fatalf("unbound=%d want 1", bound)
	}
	// owner A's pool cleared, account unbound.
	cfgA, _ := store.UserProxyConfig(ownerA)
	if cfgA.PoolEnabled || len(cfgA.PoolNodes) != 0 || cfgA.PoolYAMLCipher != "" {
		t.Fatalf("owner A pool not cleared: %+v", cfgA)
	}
	if got := store.ProxyPoolNodeForAccount(ownerA, accA.ID, ""); got != "" {
		t.Fatalf("owner A account still bound: %q", got)
	}
	// owner B's pool and binding untouched.
	cfgB, _ := store.UserProxyConfig(ownerB)
	if !cfgB.PoolEnabled || len(cfgB.PoolNodes) != 1 || cfgB.PoolYAMLCipher != "cipher-b" {
		t.Fatalf("owner B pool was touched: %+v", cfgB)
	}
	if got := store.ProxyPoolNodeForAccount(ownerB, accB.ID, ""); got != "node-b1" {
		t.Fatalf("owner B account binding changed: %q", got)
	}
}

func TestBindProxyPoolCreatesAccountPlaceholderBeforeLogin(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{ConfigPath: "test", AutoLoginSecret: "test-secret"}, store, discardLogger())
	server := handler.(*Server)

	// Owner imports a proxy pool with one node.
	cipher, _ := encryptAutoSecret("test-secret", "proxies:\n  - name: node-1\n    type: http\n    server: 8.8.8.8\n    port: 8080\n")
	if err := store.SaveUserProxyConfig(UserProxyConfig{OwnerID: "owner", PoolEnabled: true, PoolYAMLCipher: cipher, PoolNodes: []ProxyPoolNode{{Name: "node-1", Type: "http"}}}); err != nil {
		t.Fatal(err)
	}

	// Bind a proxy node with only an Apple ID, no account_id yet.
	owner := "owner"
	appleID := "new-user@icloud.com"
	// Simulate the handler path by calling AddAccountForOwner then SaveAccountProxyPoolNode.
	account, err := store.AddAccountForOwner(owner, "", appleID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccountProxyPoolNode(owner, account.ID, "node-1"); err != nil {
		t.Fatal(err)
	}
	if got := store.ProxyPoolNodeForAccount(owner, account.ID, ""); got != "node-1" {
		t.Fatalf("account proxy node = %q want node-1", got)
	}

	// The account exists before login, so the require-proxy gate can find it.
	if !server.accountHasProxy(owner, account.ID) {
		t.Fatalf("accountHasProxy should be true after binding")
	}
}

func TestAccountHasProxyTrueWithEnabledPoolNoExplicitBind(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{ConfigPath: "test", AutoLoginSecret: "test-secret", AppleRequireProxy: true}, store, discardLogger())
	server := handler.(*Server)

	owner := "owner-pool"
	// Enabled pool with nodes, but the account has no explicit binding.
	if err := store.SaveUserProxyConfig(UserProxyConfig{
		OwnerID: owner, PoolEnabled: true,
		PoolYAMLCipher: "cipher",
		PoolNodes:      []ProxyPoolNode{{Name: "node-1", Type: "http", Available: true}},
	}); err != nil {
		t.Fatal(err)
	}
	account, err := store.AddAccountForOwner(owner, "", "u@icloud.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if !server.accountHasProxy(owner, account.ID) {
		t.Fatalf("accountHasProxy should be true when an enabled pool exists, even without explicit bind")
	}
}

func TestDefaultProxyPoolNodePrefersAvailable(t *testing.T) {
	store := newTestStore(t)
	owner := "owner-def"
	if err := store.SaveUserProxyConfig(UserProxyConfig{
		OwnerID: owner, PoolEnabled: true,
		PoolNodes: []ProxyPoolNode{
			{Name: "bad", Type: "http", Available: false},
			{Name: "good", Type: "http", Available: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if got := store.DefaultProxyPoolNode(owner); got != "good" {
		t.Fatalf("DefaultProxyPoolNode = %q want good", got)
	}
}
