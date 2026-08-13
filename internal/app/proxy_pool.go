package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type ProxyPoolNode struct {
	Tag           string   `json:"tag"`
	Name          string   `json:"name"`
	Port          int      `json:"port"`
	LatencyMS     int64    `json:"latency_ms"`
	Available     bool     `json:"available"`
	Blacklisted   bool     `json:"blacklisted"`
	LastError     string   `json:"last_error,omitempty"`
	BoundAccounts []string `json:"bound_accounts"`
}

type easyProxiesClient struct {
	baseURL, password string
	httpClient        *http.Client
	mu                sync.Mutex
	token             string
}

func newEasyProxiesClient(baseURL, password string) *easyProxiesClient {
	return &easyProxiesClient{baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), password: password, httpClient: &http.Client{Timeout: 90 * time.Second}}
}

func (c *easyProxiesClient) request(ctx context.Context, method, path string, body any, out any) error {
	if c.baseURL == "" {
		return fmt.Errorf("easy-proxies 管理地址未配置")
	}
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	do := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		c.mu.Lock()
		token := c.token
		c.mu.Unlock()
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return c.httpClient.Do(req)
	}
	resp, err := do()
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized && c.password != "" {
		resp.Body.Close()
		if err := c.login(ctx); err != nil {
			return err
		}
		resp, err = do()
		if err != nil {
			return err
		}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 12<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e map[string]any
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("easy-proxies HTTP %d：%v", resp.StatusCode, firstNonEmpty(fmt.Sprint(e["error"]), strings.TrimSpace(string(data))))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *easyProxiesClient) login(ctx context.Context) error {
	data, _ := json.Marshal(map[string]string{"password": c.password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/auth", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var payload struct{ Token, Error string }
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("easy-proxies 登录失败：%s", payload.Error)
	}
	c.mu.Lock()
	c.token = payload.Token
	c.mu.Unlock()
	return nil
}

func (s *Server) proxyPoolNodes(ctx context.Context, ownerID string) ([]ProxyPoolNode, error) {
	var payload struct {
		Nodes []struct {
			Tag           string `json:"tag"`
			Name          string `json:"name"`
			LastError     string `json:"last_error"`
			Port          int    `json:"port"`
			LastLatencyMS int64  `json:"last_latency_ms"`
			Available     bool   `json:"available"`
			Blacklisted   bool   `json:"blacklisted"`
		} `json:"nodes"`
	}
	if err := s.easyProxies.request(ctx, http.MethodGet, "/api/debug", nil, &payload); err != nil {
		return nil, err
	}
	var health struct {
		Nodes []struct {
			Tag string `json:"tag"`
		} `json:"nodes"`
	}
	if err := s.easyProxies.request(ctx, http.MethodGet, "/api/nodes", nil, &health); err != nil {
		return nil, err
	}
	available := make(map[string]bool, len(health.Nodes))
	for _, node := range health.Nodes {
		// /api/nodes only contains healthy nodes and nodes awaiting their
		// first probe; failed or blacklisted nodes are filtered out upstream.
		available[node.Tag] = true
	}
	all := s.sessionsForOwner(ownerID, "")
	bound := map[string][]string{}
	for _, session := range all {
		if session.ProxyNodeTag != "" {
			bound[session.ProxyNodeTag] = append(bound[session.ProxyNodeTag], firstNonEmpty(session.AppleID, session.AccountID))
		}
	}
	nodes := make([]ProxyPoolNode, 0, len(payload.Nodes))
	for _, n := range payload.Nodes {
		nodes = append(nodes, ProxyPoolNode{Tag: n.Tag, Name: n.Name, Port: n.Port, LatencyMS: n.LastLatencyMS, Available: available[n.Tag], Blacklisted: n.Blacklisted, LastError: n.LastError, BoundAccounts: bound[n.Tag]})
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Available != nodes[j].Available {
			return nodes[i].Available
		}
		return nodes[i].LatencyMS < nodes[j].LatencyMS
	})
	return nodes, nil
}

func (s *Server) proxyURLForAccount(ctx context.Context, ownerID, accountID string) (string, ProxyPoolNode, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID != "" {
		for _, session := range s.store.ICloudSessionsForOwner(ownerID) {
			if session.AccountID != accountID || session.ProxyNodeTag == "" {
				continue
			}
			nodes, err := s.proxyPoolNodes(ctx, ownerID)
			if err != nil {
				return "", ProxyPoolNode{}, err
			}
			for _, n := range nodes {
				if n.Tag == session.ProxyNodeTag {
					if n.Port == 0 {
						return "", n, fmt.Errorf("代理节点尚未分配端口")
					}
					if !n.Available || n.Blacklisted {
						return "", n, fmt.Errorf("代理节点当前不可用：%s", firstNonEmpty(n.LastError, n.Name))
					}
					return fmt.Sprintf("http://%s:%d", s.cfg.EasyProxiesHost, n.Port), n, nil
				}
			}
			return "", ProxyPoolNode{}, fmt.Errorf("绑定的代理节点已不存在：%s", session.ProxyNodeName)
		}
	}
	return "", ProxyPoolNode{}, nil
}

func (s *Server) proxyURLForAppleLogin(ctx context.Context, ownerID, accountID, appleID string) (string, ProxyPoolNode, error) {
	if strings.TrimSpace(accountID) != "" {
		return s.proxyURLForAccount(ctx, ownerID, accountID)
	}
	appleID = strings.TrimSpace(strings.ToLower(appleID))
	if appleID != "" {
		for _, session := range s.store.ICloudSessionsForOwner(ownerID) {
			if strings.ToLower(strings.TrimSpace(session.AppleID)) == appleID {
				return s.proxyURLForAccount(ctx, ownerID, session.AccountID)
			}
		}
	}
	return "", ProxyPoolNode{}, nil
}

func (s *Server) handleProxyPoolNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.proxyPoolNodes(r.Context(), requestOwnerID(r, s.store))
	if err != nil {
		writeError(w, 502, errCode("proxy_pool_unavailable", err.Error(), true))
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "nodes": nodes, "management_url": s.cfg.EasyProxiesURL})
}

func (s *Server) handleProxyPoolTest(w http.ResponseWriter, r *http.Request) {
	var result struct {
		Total    int `json:"total"`
		Retested int `json:"retested"`
		Passed   int `json:"passed"`
		Failed   int `json:"failed"`
	}
	request := map[string]any{
		"scopes":         []string{"pool"},
		"retest":         true,
		"country":        false,
		"promote_passed": false,
		"auto_reload":    true,
	}
	if err := s.easyProxies.request(r.Context(), http.MethodPost, "/api/managed-nodes/batch-test", request, &result); err != nil {
		writeError(w, http.StatusBadGateway, errCode("proxy_test_failed", err.Error(), true))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": fmt.Sprintf("测速完成：节点 %d，可用 %d，失败 %d", result.Total, result.Passed, result.Failed),
		"result":  result,
	})
}

func (s *Server) handleProxyPoolImport(w http.ResponseWriter, r *http.Request) {
	var p struct {
		URL       string `json:"url"`
		YAML      string `json:"yaml"`
		TagPrefix string `json:"tag_prefix"`
	}
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, 400, err)
		return
	}
	mode, source := "url", strings.TrimSpace(p.URL)
	if strings.TrimSpace(p.YAML) != "" {
		mode, source = "content", p.YAML
	}
	if source == "" {
		writeError(w, 400, errCode("proxy_import_empty", "请输入订阅链接或 YAML 内容", false))
		return
	}
	prefix := firstNonEmpty(strings.TrimSpace(p.TagPrefix), "icloud")
	request := map[string]any{"mode": mode, "tag_prefix": prefix}
	if mode == "url" {
		request["url"] = source
	} else {
		request["content"] = source
	}
	var parsed struct {
		ImportID string `json:"import_id"`
		Nodes    []struct {
			ID string `json:"id"`
		} `json:"nodes"`
	}
	if err := s.easyProxies.request(r.Context(), http.MethodPost, "/api/import/parse", request, &parsed); err != nil {
		writeError(w, 502, errCode("proxy_import_failed", err.Error(), true))
		return
	}
	ids := make([]string, 0, len(parsed.Nodes))
	for _, n := range parsed.Nodes {
		ids = append(ids, n.ID)
	}
	var committed map[string]any
	if err := s.easyProxies.request(r.Context(), http.MethodPost, "/api/import/"+url.PathEscape(parsed.ImportID)+"/commit", map[string]any{"node_ids": ids, "auto_reload": true, "promote_passed": true}, &committed); err != nil {
		writeError(w, 502, errCode("proxy_import_commit_failed", err.Error(), true))
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": fmt.Sprintf("已解析 %d 个节点，正在测速并加入代理池", len(ids)), "import_id": parsed.ImportID, "job": committed})
}

func (s *Server) handleBindAccountProxy(w http.ResponseWriter, r *http.Request) {
	var p struct{ AccountID, NodeTag string }
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, 400, err)
		return
	}
	owner := requestOwnerID(r, s.store)
	sessions := s.sessionsForOwner(owner, p.AccountID)
	if len(sessions) != 1 {
		writeError(w, 404, errCode("account_not_found", "登录态账号不存在", false))
		return
	}
	session := sessions[0]
	session.ProxyNodeTag = strings.TrimSpace(p.NodeTag)
	session.ProxyNodeName = ""
	if session.ProxyNodeTag != "" {
		nodes, err := s.proxyPoolNodes(r.Context(), owner)
		if err != nil {
			writeError(w, 502, err)
			return
		}
		found := false
		for _, n := range nodes {
			if n.Tag == session.ProxyNodeTag {
				session.ProxyNodeName = n.Name
				found = true
				break
			}
		}
		if !found {
			writeError(w, 404, errCode("proxy_node_not_found", "代理节点不存在", false))
			return
		}
	}
	updated, found, err := s.store.SetICloudSessionProxy(owner, session.AccountID, session.ProxyNodeTag, session.ProxyNodeName)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if !found {
		writeError(w, 404, errCode("account_not_found", "登录态账号不存在", false))
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": firstNonEmpty(map[bool]string{true: "账号代理节点已绑定", false: "账号已改为直连/固定代理回退"}[updated.ProxyNodeTag != ""], "保存成功"), "session": s.publicSession(&updated)})
}
