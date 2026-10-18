package jwt

import "testing"

const (
	secret = "your-256-bit-secret"

	// jwt.io のサンプルトークン(HS256, 秘密鍵は上の secret)
	sampleToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

// フィールドの宣言順がそのまま JSON のキー順になる。
// キー順や空白が変わると payload のバイト列が変わり、署名も変わる。
type claims struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
	Iat  int64  `json:"iat"`
}

func TestSign(t *testing.T) {
	t.Run("known vector", func(t *testing.T) {
		payload := claims{Sub: "1234567890", Name: "John Doe", Iat: 1516239022}

		got, err := Sign(payload, []byte(secret))
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if got != sampleToken {
			t.Errorf("Sign() =\n  %s\nwant\n  %s", got, sampleToken)
		}
	})
}
