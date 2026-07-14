// Package random generates URL-safe random tokens for ids, secrets, and
// OAuth state values.
package random

import (
	"crypto/rand"
	"encoding/base64"
)

// Token returns byteLen bytes of cryptographic randomness, base64url-encoded
// without padding.
func Token(byteLen int) (string, error) {
	raw := make([]byte, byteLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
