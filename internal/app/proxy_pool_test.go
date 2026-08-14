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
