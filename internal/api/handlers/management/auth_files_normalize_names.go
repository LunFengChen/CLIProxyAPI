package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/antigravity"
	geminiAuth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/gemini"
	xaiauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/xai"
)

type normalizeAuthFileNameItem struct {
	Old string `json:"old"`
	New string `json:"new"`
}

type normalizeAuthFileNameError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

type normalizeAuthFileNameResult struct {
	Total   int                          `json:"total"`
	Renamed int                          `json:"renamed"`
	Skipped int                          `json:"skipped"`
	Failed  int                          `json:"failed"`
	Files   []normalizeAuthFileNameItem  `json:"files,omitempty"`
	Errors  []normalizeAuthFileNameError `json:"errors,omitempty"`
}

func (h *Handler) PostNormalizeAuthFileNames(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	result, err := h.normalizeAuthFileNames(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *Handler) normalizeAuthFileNames(ctx context.Context) (normalizeAuthFileNameResult, error) {
	var result normalizeAuthFileNameResult
	if h == nil || h.cfg == nil || strings.TrimSpace(h.cfg.AuthDir) == "" {
		return result, fmt.Errorf("auth dir unavailable")
	}
	entries, err := os.ReadDir(h.cfg.AuthDir)
	if err != nil {
		return result, fmt.Errorf("read auth dir: %w", err)
	}
	reserved := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		result.Total++
		oldName := entry.Name()
		oldPath := filepath.Join(h.cfg.AuthDir, oldName)
		data, errRead := os.ReadFile(oldPath)
		if errRead != nil {
			result.Failed++
			result.Errors = append(result.Errors, normalizeAuthFileNameError{Name: oldName, Message: errRead.Error()})
			continue
		}
		var meta map[string]any
		if errJSON := json.Unmarshal(data, &meta); errJSON != nil {
			result.Failed++
			result.Errors = append(result.Errors, normalizeAuthFileNameError{Name: oldName, Message: errJSON.Error()})
			continue
		}
		desired := standardAuthFileName(meta)
		if desired == "" || strings.EqualFold(desired, oldName) {
			result.Skipped++
			continue
		}
		newName := h.uniqueAuthFileName(desired, reserved)
		reserved[strings.ToLower(newName)] = struct{}{}
		if strings.EqualFold(newName, oldName) {
			result.Skipped++
			continue
		}
		newPath := filepath.Join(h.cfg.AuthDir, newName)
		if errRename := os.Rename(oldPath, newPath); errRename != nil {
			result.Failed++
			result.Errors = append(result.Errors, normalizeAuthFileNameError{Name: oldName, Message: errRename.Error()})
			continue
		}
		h.removeAuth(ctx, oldPath)
		h.removeAuth(ctx, oldName)
		if errRegister := h.registerAuthFromFile(ctx, newPath, data); errRegister != nil {
			result.Failed++
			result.Errors = append(result.Errors, normalizeAuthFileNameError{Name: oldName, Message: errRegister.Error()})
			continue
		}
		result.Renamed++
		result.Files = append(result.Files, normalizeAuthFileNameItem{Old: oldName, New: newName})
	}
	return result, nil
}

func standardAuthFileName(meta map[string]any) string {
	provider := strings.ToLower(cpaString(meta, "type"))
	email := cpaString(meta, "email")
	switch provider {
	case "codex":
		return codexCredentialFileNameFromMetadata(meta)
	case "gemini", "aistudio":
		projectID := cpaString(meta, "project_id")
		if email == "" || projectID == "" {
			return ""
		}
		return filepath.Base(geminiAuth.CredentialFileName(email, projectID, true))
	case "antigravity":
		if email == "" {
			return ""
		}
		return filepath.Base(antigravity.CredentialFileName(email))
	case "claude":
		if email == "" {
			return ""
		}
		return filepath.Base("claude-" + email + ".json")
	case "xai":
		return filepath.Base(xaiauth.CredentialFileName(email, firstCPAString(cpaString(meta, "subject"), cpaString(meta, "sub"), cpaString(meta, "account_id"))))
	default:
		return ""
	}
}
