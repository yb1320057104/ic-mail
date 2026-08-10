package app

import "testing"

func TestAutoLoginSecretRoundTrip(t *testing.T) {
	ciphertext, err := encryptAutoSecret("server-secret", "apple-password")
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == "apple-password" {
		t.Fatal("password was not encrypted")
	}
	plain, err := decryptAutoSecret("server-secret", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "apple-password" {
		t.Fatalf("plain = %q", plain)
	}
	if _, err := decryptAutoSecret("wrong-secret", ciphertext); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestValidateAutoCodeURLRejectsUnsafeTargets(t *testing.T) {
	for _, raw := range []string{"http://example.com/code", "https://127.0.0.1/code", "https://localhost/code"} {
		if _, err := validateAutoCodeURL(raw); err == nil {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}

func TestSMSCodePattern(t *testing.T) {
	match := smsCodePattern.FindStringSubmatch("【Apple】验证码为 691288，请勿泄露")
	if len(match) < 2 || match[1] != "691288" {
		t.Fatalf("code match = %#v", match)
	}
}
