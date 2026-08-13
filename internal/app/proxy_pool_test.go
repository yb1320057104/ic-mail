package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyPoolImportAcceptsTagPrefixJSONField(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/import/parse", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["tag_prefix"] != "icloud" || body["url"] != "https://example.com/sub" {
			t.Fatalf("unexpected parse request: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"import_id": "imp-1", "nodes": []map[string]any{}})
	})
	mux.HandleFunc("/api/import/imp-1/commit", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	})
	upstream := httptest.NewServer(mux)
	defer upstream.Close()
	store := newTestStore(t)
	h := NewServer(Config{EasyProxiesURL: upstream.URL}, store, discardLogger()).(*Server)
	req := httptest.NewRequest(http.MethodPost, "/api/proxy-pool/import", bytes.NewBufferString(`{"url":"https://example.com/sub","yaml":"","tag_prefix":"icloud"}`))
	rec := httptest.NewRecorder()
	h.handleProxyPoolImport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAccountProxyBindingPersistsAcrossSessionMerge(t *testing.T) {
	store := newTestStore(t)
	base := ICloudSession{OwnerID: "owner-a", AccountID: "acc-a", AppleID: "a@example.com", ProxyNodeTag: "node-a", ProxyNodeName: "香港节点"}
	if err := store.SaveICloudSessionForOwner("owner-a", base); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-a", ICloudSession{AccountID: "acc-a", AppleID: "a@example.com", LastStatusMessage: "刷新成功"}); err != nil {
		t.Fatal(err)
	}
	got, ok := store.ICloudSessionForOwnerAccount("owner-a", "acc-a")
	if !ok || got.ProxyNodeTag != "node-a" || got.ProxyNodeName != "香港节点" {
		t.Fatalf("proxy binding lost: %+v", got)
	}
	updated, found, err := store.SetICloudSessionProxy("owner-a", "acc-a", "node-b", "日本节点")
	if err != nil || !found || updated.ProxyNodeTag != "node-b" {
		t.Fatalf("update=%+v found=%v err=%v", updated, found, err)
	}
}

func TestProxyPoolNodeMappingAndOwnerIsolation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/debug", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"nodes": []map[string]any{{"tag": "node-a", "name": "香港", "port": 24001, "last_latency_ms": 88}}})
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"nodes": []map[string]any{{"tag": "node-a", "available": true}}})
	})
	upstream := httptest.NewServer(mux)
	defer upstream.Close()
	store := newTestStore(t)
	_ = store.SaveICloudSessionForOwner("owner-a", ICloudSession{AccountID: "acc-a", AppleID: "a@example.com", ProxyNodeTag: "node-a"})
	_ = store.SaveICloudSessionForOwner("owner-b", ICloudSession{AccountID: "acc-b", AppleID: "b@example.com", ProxyNodeTag: "node-a"})
	h := NewServer(Config{EasyProxiesURL: upstream.URL, EasyProxiesHost: "127.0.0.1"}, store, discardLogger()).(*Server)
	nodes, err := h.proxyPoolNodes(context.Background(), "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || !nodes[0].Available || nodes[0].LatencyMS != 88 || len(nodes[0].BoundAccounts) != 1 || nodes[0].BoundAccounts[0] != "a@example.com" {
		t.Fatalf("nodes=%+v", nodes)
	}
	raw, node, err := h.proxyURLForAccount(context.Background(), "owner-a", "acc-a")
	if err != nil || raw != "http://127.0.0.1:24001" || node.Tag != "node-a" {
		t.Fatalf("raw=%q node=%+v err=%v", raw, node, err)
	}
}
