package codex

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// pkceS256 生成 Codex OAuth 需要的 PKCE 对。
// 对齐上游 core/codex_oauth.py:149-155：
//
//	verifier  = base64url(96 字节随机源) 去 padding
//	challenge = base64url(sha256(verifier)) 去 padding
func pkceS256() (verifier, challenge string, err error) {
	b := make([]byte, 96)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("生成 PKCE 随机源失败: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// randomState 对齐上游 _generate_state()：secrets.token_urlsafe(32)。
func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成 state 失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomToken 生成 n 字节随机源的 base64url 串，用于前端同源参数。
func randomToken(n int) string {
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", n)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
