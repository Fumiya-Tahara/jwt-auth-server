package jwt

import (
	"strings"
	"testing"
	"time"
)

const (
	secret = "your-256-bit-secret"

	// jwt.io のサンプルトークン(HS256, 秘密鍵は上の secret)
	sampleToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

// Verify に渡す「現在時刻」。テストでは固定値を使い、sleep を不要にする。
var now = time.Unix(1_700_000_000, 0)

// 有効期限つきの payload。
type expiringClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

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

func TestVerify(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		if err := Verify(sampleToken, []byte(secret), now); err != nil {
			t.Errorf("Verify() error = %v, want nil", err)
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		// 別の payload に差し替え、署名は元のまま使い回す(攻撃者がやること)
		other, err := Sign(claims{Sub: "admin", Name: "John Doe", Iat: 1516239022}, []byte(secret))
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		orig := strings.Split(sampleToken, ".")
		forged := strings.Split(other, ".")
		tampered := orig[0] + "." + forged[1] + "." + orig[2]

		if err := Verify(tampered, []byte(secret), now); err == nil {
			t.Error("Verify() error = nil, want error")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		if err := Verify(sampleToken, []byte("wrong-key"), now); err == nil {
			t.Error("Verify() error = nil, want error")
		}
	})

	t.Run("garbage signature", func(t *testing.T) {
		orig := strings.Split(sampleToken, ".")
		garbage := orig[0] + "." + orig[1] + ".AAAA"

		if err := Verify(garbage, []byte(secret), now); err == nil {
			t.Error("Verify() error = nil, want error")
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		parts := strings.Split(sampleToken, ".")

		tests := []struct {
			name  string
			token string
		}{
			{"empty", ""},
			{"no dot", "abc"},
			{"two parts", parts[0] + "." + parts[1]},
			{"four parts", sampleToken + ".extra"},
			{"empty signature", parts[0] + "." + parts[1] + "."},
			{"signature is not base64url", parts[0] + "." + parts[1] + ".!!!"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if err := Verify(tt.token, []byte(secret), now); err == nil {
					t.Error("Verify() error = nil, want error")
				}
			})
		}
	})

	t.Run("expiration", func(t *testing.T) {
		tests := []struct {
			name    string
			exp     int64
			wantErr bool
		}{
			{"expired", now.Unix() - 1, true},
			{"expires exactly now", now.Unix(), true},
			{"not yet expired", now.Unix() + 1, false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token, err := Sign(expiringClaims{Sub: "1234567890", Exp: tt.exp}, []byte(secret))
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}

				err = Verify(token, []byte(secret), now)
				if (err != nil) != tt.wantErr {
					t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		}
	})
}
