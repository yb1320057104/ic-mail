package app

import (
	"strings"
	"testing"
)

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
