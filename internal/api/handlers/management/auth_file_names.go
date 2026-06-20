package management

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
)

func codexCredentialFileNameFromMetadata(meta map[string]any) string {
	email := cpaString(meta, "email")
	if email == "" {
		return ""
	}
	return filepath.Base(codex.CredentialFileName(
		email,
		codexPlanTypeFromMetadata(meta),
		codexHashAccountIDFromMetadata(meta),
		true,
	))
}

func codexPlanTypeFromMetadata(meta map[string]any) string {
	if value := firstCPAString(cpaString(meta, "plan_type"), cpaString(meta, "chatgpt_plan_type")); value != "" {
		return value
	}
	for _, claims := range codexJWTClaimsFromMetadata(meta) {
		if value := strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType); value != "" {
			return value
		}
	}
	return ""
}

func codexHashAccountIDFromMetadata(meta map[string]any) string {
	accountID := codexAccountIDFromMetadata(meta)
	if accountID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(accountID))
	return hex.EncodeToString(sum[:])[:8]
}

func codexAccountIDFromMetadata(meta map[string]any) string {
	if value := firstCPAString(cpaString(meta, "account_id"), cpaString(meta, "chatgpt_account_id")); value != "" {
		return value
	}
	for _, claims := range codexJWTClaimsFromMetadata(meta) {
		if value := strings.TrimSpace(claims.GetAccountID()); value != "" {
			return value
		}
	}
	return ""
}

func codexJWTClaimsFromMetadata(meta map[string]any) []*codex.JWTClaims {
	var result []*codex.JWTClaims
	for _, key := range []string{"id_token", "access_token"} {
		token := cpaString(meta, key)
		if token == "" {
			continue
		}
		claims, err := codex.ParseJWTToken(token)
		if err == nil {
			result = append(result, claims)
		}
	}
	return result
}
