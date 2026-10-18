package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))

	return signingInput + "." + encode(mac.Sum(nil)), nil
}

// encode は JWT の仕様どおり、パディングなしの Base64URL にする。
func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
