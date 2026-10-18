package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// header は固定。空白やキー順が変わると署名も変わる。
const header = `{"alg":"HS256","typ":"JWT"}`

// Sign は payload を JSON にして、HS256 で署名した JWT を返す。
func Sign(payload any, key []byte) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	signingInput := encode([]byte(header)) + "." + encode(body)

	return signingInput + "." + encode(computeSignature(signingInput, key)), nil
}

// Verify はトークンの署名が key で作られたものかを検証し、有効期限(exp)を過ぎていないかを確認する。
// 署名の検証に使うのはトークン自身の header.payload と key だけで、サーバー側に正解は保存しない。
// exp が無いトークンは期限なしとして扱う(RFC 7519 で exp は任意)。
func Verify(token string, key []byte, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("jwt: malformed token")
	}

	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("jwt: malformed signature: %w", err)
	}

	want := computeSignature(parts[0]+"."+parts[1], key)

	// == だと不一致の位置で比較が止まり、処理時間から署名を推測されうる。
	// hmac.Equal は一定時間で比較する。
	if !hmac.Equal(got, want) {
		return errors.New("jwt: invalid signature")
	}

	// payload は署名が合ったあとで初めて信用できるので、exp の確認は署名検証のあとに行う。
	return checkExpiration(parts[1], now)
}

// checkExpiration は payload(エンコード済み)の exp を見て、now が exp より前かを確認する。
func checkExpiration(encodedPayload string, now time.Time) error {
	raw, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return fmt.Errorf("jwt: malformed payload: %w", err)
	}

	// *int64 にして、exp が「無い」ことと 0 であることを区別する。
	var c struct {
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("jwt: malformed payload: %w", err)
	}

	// 仕様では「現在時刻は exp より前でなければならない」ので、同時刻も期限切れ。
	if c.Exp != nil && now.Unix() >= *c.Exp {
		return errors.New("jwt: token expired")
	}
	return nil
}

// computeSignature は signingInput(エンコード済みの header.payload)の HMAC-SHA256 を返す。
func computeSignature(signingInput string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

// encode は JWT の仕様どおり、パディングなしの Base64URL にする。
func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
