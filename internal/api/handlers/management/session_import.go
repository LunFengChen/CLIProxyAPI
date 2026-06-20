package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

type sessionTextImportRequest struct {
	Content  string `json:"content"`
	ProxyURL string `json:"proxy_url"`
	Name     string `json:"name"`
}

type sessionTextImportResult struct {
	Total     int                        `json:"total"`
	Created   int                        `json:"created"`
	Failed    int                        `json:"failed"`
	ProxyURL  string                     `json:"proxy_url,omitempty"`
	Files     []string                   `json:"files,omitempty"`
	Errors    []sessionTextImportMessage `json:"errors,omitempty"`
	Converted []map[string]any           `json:"converted,omitempty"`
}

type sessionTextImportMessage struct {
	Index   int    `json:"index"`
	Message string `json:"message"`
}

// ImportSessionText delegates conversion to the gpt-session-convert submodule CLI.
// CPA only owns proxy-pool glue and auth-file persistence.
func (h *Handler) ImportSessionText(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req sessionTextImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content is required"})
		return
	}

	proxyURL := strings.TrimSpace(req.ProxyURL)
	if proxyURL != "" {
		normalizedProxyURL, err := h.ensureProxyPoolEntry(proxyURL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		proxyURL = normalizedProxyURL
	} else {
		proxyURL = h.pickProxyURLForImportedAuth()
	}

	converted, err := convertSessionTextWithSubmoduleCLI(c.Request.Context(), req.Content, proxyURL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.importConvertedCPAAutos(ctxWithoutCancel(c.Request.Context()), req, proxyURL, converted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func ctxWithoutCancel(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}

func convertSessionTextWithSubmoduleCLI(ctx context.Context, content, proxyURL string) ([]map[string]any, error) {
	cli := findGPTSessionConverterCLI()
	if cli == "" {
		return nil, fmt.Errorf("gpt-session-convert CLI not found; run git submodule update --init --recursive")
	}
	args := []string{cli, "--format", "cpa", "--extract-json"}
	if strings.TrimSpace(proxyURL) != "" {
		args = append(args, "--proxy-url", strings.TrimSpace(proxyURL))
	}
	cmd := exec.CommandContext(ctx, "node", args...)
	cmd.Stdin = strings.NewReader(content)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("gpt-session-convert failed: %s", msg)
	}
	return decodeCPAConverterOutput(stdout.Bytes())
}

func decodeCPAConverterOutput(raw []byte) ([]map[string]any, error) {
	var single map[string]any
	if err := json.Unmarshal(raw, &single); err == nil && len(single) > 0 {
		return []map[string]any{single}, nil
	}
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("invalid converter output: %w", err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("converter produced no CPA auth records")
	}
	return list, nil
}

func (h *Handler) importConvertedCPAAutos(ctx context.Context, req sessionTextImportRequest, proxyURL string, converted []map[string]any) (sessionTextImportResult, error) {
	result := sessionTextImportResult{Total: len(converted), ProxyURL: proxyURL}
	seen := make(map[string]struct{})
	reservedNames := make(map[string]struct{})
	for i, cpa := range converted {
		if strings.TrimSpace(cpaString(cpa, "type")) == "" {
			cpa["type"] = "codex"
		}
		if proxyURL != "" && strings.TrimSpace(cpaString(cpa, "proxy_url")) == "" {
			cpa["proxy_url"] = proxyURL
		}
		if strings.TrimSpace(cpaString(cpa, "access_token")) == "" {
			result.Failed++
			result.Errors = append(result.Errors, sessionTextImportMessage{Index: i + 1, Message: "converted CPA auth missing access_token"})
			continue
		}
		identity := cpaIdentity(cpa)
		if identity != "" {
			if _, ok := seen[identity]; ok {
				continue
			}
			seen[identity] = struct{}{}
		}
		name := h.uniqueAuthFileName(buildCPAImportFileName(req.Name, cpa, len(result.Files)+1), reservedNames)
		reservedNames[strings.ToLower(name)] = struct{}{}
		raw, err := json.MarshalIndent(cpa, "", "  ")
		if err != nil {
			return result, err
		}
		raw = append(raw, '\n')
		if err := h.writeAuthFile(ctx, name, raw); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, sessionTextImportMessage{Index: i + 1, Message: err.Error()})
			continue
		}
		result.Created++
		result.Files = append(result.Files, name)
		result.Converted = append(result.Converted, cpa)
	}
	return result, nil
}

func findGPTSessionConverterCLI() string {
	candidates := []string{
		"third_party/gpt-session-convert/bin/gpt-session-convert.js",
		"cli-proxy-api/third_party/gpt-session-convert/bin/gpt-session-convert.js",
	}
	if wd, err := os.Getwd(); err == nil {
		current := wd
		for i := 0; i < 6; i++ {
			for _, rel := range candidates {
				path := filepath.Join(current, rel)
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					return path
				}
			}
			next := filepath.Dir(current)
			if next == current || strings.TrimSpace(next) == "" {
				break
			}
			current = next
		}
	}
	return ""
}

func buildCPAImportFileName(base string, cpa map[string]any, index int) string {
	if strings.EqualFold(cpaString(cpa, "type"), "codex") {
		if name := codexCredentialFileNameFromMetadata(cpa); name != "" {
			return name
		}
	}
	seed := firstCPAString(base, cpaString(cpa, "email"), cpaString(cpa, "account_id"), fmt.Sprintf("codex-session-%d", index))
	seed = strings.ToLower(seed)
	replacer := strings.NewReplacer("@", "_", ".", "_", "/", "_", "\\", "_", " ", "_", ":", "_")
	seed = replacer.Replace(seed)
	seed = strings.Trim(seed, "_")
	if seed == "" {
		seed = fmt.Sprintf("codex-session-%d", index)
	}
	if len(seed) > 80 {
		seed = seed[:80]
	}
	if index > 1 {
		seed = fmt.Sprintf("%s_%d", seed, index)
	}
	return filepath.Base(seed + ".json")
}

func (h *Handler) uniqueAuthFileName(name string, reserved map[string]struct{}) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." {
		name = "auth.json"
	}
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		name += ".json"
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if base == "" {
		base = "auth"
	}
	for i := 1; ; i++ {
		candidate := name
		if i > 1 {
			candidate = fmt.Sprintf("%s_%d%s", base, i, ext)
		}
		key := strings.ToLower(candidate)
		if _, ok := reserved[key]; ok {
			continue
		}
		if h != nil && h.cfg != nil {
			if _, err := os.Stat(filepath.Join(h.cfg.AuthDir, candidate)); err == nil {
				continue
			}
		}
		return candidate
	}
}

func cpaIdentity(cpa map[string]any) string {
	for _, key := range []string{"access_token", "refresh_token", "session_token"} {
		value := cpaString(cpa, key)
		if value == "" {
			continue
		}
		sum := sha256.Sum256([]byte(value))
		return key + ":" + hex.EncodeToString(sum[:])
	}
	accountID := firstCPAString(cpaString(cpa, "account_id"), cpaString(cpa, "chatgpt_account_id"))
	email := cpaString(cpa, "email")
	if accountID != "" && email != "" {
		return "account_email:" + strings.ToLower(accountID) + ":" + strings.ToLower(email)
	}
	if accountID != "" {
		return "account_id:" + strings.ToLower(accountID)
	}
	if userID := cpaString(cpa, "chatgpt_user_id"); userID != "" {
		return "chatgpt_user_id:" + strings.ToLower(userID)
	}
	if email != "" {
		return "email:" + strings.ToLower(email)
	}
	return ""
}

func cpaString(obj map[string]any, key string) string {
	if obj == nil {
		return ""
	}
	if value, ok := obj[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func firstCPAString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
