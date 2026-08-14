package app

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestProxyFallbackRetriesSafeTransportFailure(t *testing.T) {
	primaryCalls, fallbackCalls := 0, 0
	transport := &proxyFallbackTransport{
		primary: roundTripFunc(func(*http.Request) (*http.Response, error) {
			primaryCalls++
			return nil, errors.New("proxyconnect tcp: connection refused")
		}),
		fallback: roundTripFunc(func(*http.Request) (*http.Response, error) {
			fallbackCalls++
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		}),
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.com/test", nil)
	response, err := transport.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusOK || primaryCalls != 1 || fallbackCalls != 1 {
		t.Fatalf("response=%+v err=%v primary=%d fallback=%d", response, err, primaryCalls, fallbackCalls)
	}
}

func TestProxyFallbackDoesNotSwitchOnAppleStatusOrAmbiguousPostError(t *testing.T) {
	fallbackCalls := 0
	fallback := roundTripFunc(func(*http.Request) (*http.Response, error) {
		fallbackCalls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	statusTransport := &proxyFallbackTransport{
		primary: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("Apple unavailable"))}, nil
		}),
		fallback: fallback,
	}
	request, _ := http.NewRequest(http.MethodGet, "https://apple.example/test", nil)
	response, err := statusTransport.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || fallbackCalls != 0 {
		t.Fatalf("503 response=%+v err=%v fallback=%d", response, err, fallbackCalls)
	}

	postTransport := &proxyFallbackTransport{
		primary:  roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }),
		fallback: fallback,
	}
	request, _ = http.NewRequest(http.MethodPost, "https://apple.example/test", bytes.NewBufferString(`{"action":"create"}`))
	if _, err = postTransport.RoundTrip(request); !errors.Is(err, io.ErrUnexpectedEOF) || fallbackCalls != 0 {
		t.Fatalf("ambiguous POST err=%v fallback=%d", err, fallbackCalls)
	}
}

func TestProxyFallbackAllowsPostBeforeProxyConnection(t *testing.T) {
	fallbackCalls := 0
	transport := &proxyFallbackTransport{
		primary: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("proxyconnect tcp: connection refused")
		}),
		fallback: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			fallbackCalls++
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"code":"123456"}` {
				t.Fatalf("fallback body=%q", body)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		}),
	}
	request, _ := http.NewRequest(http.MethodPost, "https://apple.example/test", bytes.NewBufferString(`{"code":"123456"}`))
	response, err := transport.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusOK || fallbackCalls != 1 {
		t.Fatalf("response=%+v err=%v fallback=%d", response, err, fallbackCalls)
	}
}

func TestFixedProxyValidationAndMasking(t *testing.T) {
	for _, raw := range []string{"ftp://8.8.8.8:1080", "socks5://127.0.0.1:1080", "http://10.0.0.1:8080", "https://8.8.8.8"} {
		if _, err := validateFixedProxyURL(raw); err == nil {
			t.Fatalf("unsafe proxy accepted: %s", raw)
		}
	}
	masked := maskProxyURL("socks5://alice:secret@8.8.8.8:1080")
	if strings.Contains(masked, "alice") || strings.Contains(masked, "secret") || strings.Contains(masked, "@") {
		t.Fatalf("credentials leaked in mask: %s", masked)
	}
}

func TestNormalizeFixedProxyURLAddsHTTPByDefault(t *testing.T) {
	tests := []struct {
		raw   string
		want  string
		added bool
	}{
		{"8.8.8.8:8080", "http://8.8.8.8:8080", true},
		{"alice:secret@8.8.8.8:8080", "http://alice:secret@8.8.8.8:8080", true},
		{"proxy.example.com:3128", "http://proxy.example.com:3128", true},
		{"http://8.8.8.8:8080", "http://8.8.8.8:8080", false},
		{"https://8.8.8.8:8080", "https://8.8.8.8:8080", false},
		{"socks5://8.8.8.8:1080", "socks5://8.8.8.8:1080", false},
	}
	for _, tt := range tests {
		got, added := normalizeFixedProxyURL(tt.raw)
		if got != tt.want || added != tt.added {
			t.Fatalf("normalize %q = %q, %v; want %q, %v", tt.raw, got, added, tt.want, tt.added)
		}
	}
}

func TestUserProxyConfigsAreOwnerIsolated(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveUserProxyConfig(UserProxyConfig{OwnerID: "owner-a", URLCipher: "a", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.UserProxyConfig("owner-b"); ok {
		t.Fatal("owner-b read owner-a proxy")
	}
	got, ok := store.UserProxyConfig("owner-a")
	if !ok || got.URLCipher != "a" {
		t.Fatalf("proxy=%+v ok=%v", got, ok)
	}
}

func TestExplainFixedProxyError(t *testing.T) {
	tests := []struct {
		raw  string
		err  error
		want string
	}{
		{"https://8.8.8.8:8080", errors.New("Not Found"), "改为 http://"},
		{"http://8.8.8.8:8080", errors.New("407 Proxy Authentication Required"), "认证失败"},
		{"http://8.8.8.8:8080", errors.New("connection refused"), "拒绝连接"},
		{"https://8.8.8.8:8080", errors.New("tls: first record does not look like a TLS handshake"), "协议不匹配"},
	}
	for _, tt := range tests {
		u, err := url.Parse(tt.raw)
		if err != nil {
			t.Fatal(err)
		}
		got := explainFixedProxyError(u, tt.err).Error()
		if !strings.Contains(got, tt.want) {
			t.Fatalf("explain %q = %q, want contains %q", tt.err, got, tt.want)
		}
	}
}

func TestParseProxyCheckResponses(t *testing.T) {
	if got := parsePlainProxyIP("203.0.113.9\n"); got != "203.0.113.9" {
		t.Fatalf("plain ip = %q", got)
	}
	trace := "fl=1\nh=example.com\nip=2001:db8::1\nts=1\n"
	if got := parseCloudflareProxyIP(trace); got != "2001:db8::1" {
		t.Fatalf("cloudflare ip = %q", got)
	}
}
