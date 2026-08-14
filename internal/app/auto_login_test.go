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
	code, err := extractAppleVerificationCode([]byte("【Apple】验证码为 691288，请勿泄露"))
	if err != nil || code != "691288" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}

func TestAppleCodeExtractionIgnoresEarlierFourDigitNumber(t *testing.T) {
	code, err := extractAppleVerificationCode([]byte("短信编号 2026；【Apple】您的验证码是 691288，请勿泄露"))
	if err != nil || code != "691288" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}

func TestAppleCodeExtractionSupportsNestedJSONAndFullWidthDigits(t *testing.T) {
	for _, test := range []struct {
		body string
		want string
	}{
		{`{"status":200,"data":{"verification_code":"042817"}}`, "042817"},
		{`{"code":200,"message":"Apple verification code: 817204"}`, "817204"},
		{`{"data":[{"message":"old"},{"message":"验证码：６９１２８８"}]}`, "691288"},
		{"【Apple】Your verification code is 123-456.", "123456"},
	} {
		code, err := extractAppleVerificationCode([]byte(test.body))
		if err != nil || code != test.want {
			t.Errorf("body=%q code=%q err=%v want=%q", test.body, code, err, test.want)
		}
	}
}

func TestAppleCodeExtractionRejectsFourDigitAndAmbiguousResponses(t *testing.T) {
	for _, body := range []string{
		`【Apple】验证码是 1234`,
		`{"code":"1234"}`,
		`候选记录 123456，另一条 654321`,
	} {
		if code, err := extractAppleVerificationCode([]byte(body)); err == nil {
			t.Errorf("body=%q unexpectedly returned %q", body, code)
		}
	}
}
