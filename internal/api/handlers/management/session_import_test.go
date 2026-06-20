package management

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestUploadAuthFile_AutoBindsProxyFromPool(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	if _, err := h.ensureProxyPoolEntry("socks5://127.0.0.1:1080"); err != nil {
		t.Fatalf("seed proxy pool: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files?name=alpha.json", strings.NewReader(`{"type":"codex","email":"alpha@example.com","access_token":"tok"}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.UploadAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(authDir, "alpha.json"))
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("decode auth file: %v", err)
	}
	if got := stored["proxy_url"]; got != "socks5://127.0.0.1:1080" {
		t.Fatalf("proxy_url = %#v", got)
	}
	auths := manager.List()
	if len(auths) != 1 || auths[0].ProxyURL != "socks5://127.0.0.1:1080" {
		t.Fatalf("auth proxy not applied: %#v", auths)
	}
}

func TestImportSessionText_ExtractsNoisyJSONAddsProxyAndImportsCPA(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	content := `junk {} more
{"user":{"email":"alpha@example.com"},"account":{"id":"acc_123","planType":"plus"},"expires":"` + expires + `","accessToken":"access-token","sessionToken":"session-token"}
trailing {bad`
	body := bytes.NewBufferString(`{"content":` + strconvQuote(content) + `,"proxy_url":"127.0.0.1:8080:user:pass"}`)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/import-session-text", body)
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.ImportSessionText(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var result sessionTextImportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Created != 1 || result.ProxyURL != "socks5://user:pass@127.0.0.1:8080" || len(result.Files) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Files[0] != "codex-alpha@example.com-plus.json" {
		t.Fatalf("imported file name = %q, want OAuth-style codex file name", result.Files[0])
	}
	data, err := os.ReadFile(filepath.Join(authDir, result.Files[0]))
	if err != nil {
		t.Fatalf("read imported file: %v", err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("decode imported file: %v", err)
	}
	if stored["type"] != "codex" || stored["email"] != "alpha@example.com" || stored["proxy_url"] != "socks5://user:pass@127.0.0.1:8080" {
		t.Fatalf("unexpected imported json: %#v", stored)
	}
	if stored["id_token_synthetic"] != true {
		t.Fatalf("expected synthetic id token marker, got %#v", stored["id_token_synthetic"])
	}
	proxies, err := newProxyStore(authDir)
	if err != nil {
		t.Fatalf("proxy store: %v", err)
	}
	entries, err := proxies.load()
	if err != nil {
		t.Fatalf("load proxies: %v", err)
	}
	if len(entries) != 1 || entries[0].URL != "socks5://user:pass@127.0.0.1:8080" {
		t.Fatalf("proxy not added to pool: %#v", entries)
	}
}

func TestImportSessionText_DoesNotDedupeSameEmailDifferentTokens(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	var content strings.Builder
	for i := 1; i <= 5; i++ {
		content.WriteString("noise before\n")
		content.WriteString(fmt.Sprintf(
			`{"user":{"email":"same@example.com"},"expires":%s,"accessToken":"access-token-%d","sessionToken":"session-token-%d"}`,
			strconvQuote(expires),
			i,
			i,
		))
		content.WriteString("\nnoise after\n")
	}
	body := bytes.NewBufferString(`{"content":` + strconvQuote(content.String()) + `}`)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/import-session-text", body)
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.ImportSessionText(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var result sessionTextImportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Total != 5 || result.Created != 5 || result.Failed != 0 || len(result.Files) != 5 {
		t.Fatalf("unexpected result: %+v", result)
	}
	seen := make(map[string]struct{})
	for _, name := range result.Files {
		if _, ok := seen[name]; ok {
			t.Fatalf("duplicate file name: %s in %+v", name, result.Files)
		}
		seen[name] = struct{}{}
		if _, err := os.Stat(filepath.Join(authDir, name)); err != nil {
			t.Fatalf("expected imported file %s: %v", name, err)
		}
	}
}

func TestCPAIdentityKeepsDifferentEmailsWithSameAccountID(t *testing.T) {
	left := map[string]any{
		"type":       "codex",
		"account_id": "shared-account-id",
		"email":      "one@example.com",
	}
	right := map[string]any{
		"type":       "codex",
		"account_id": "shared-account-id",
		"email":      "two@example.com",
	}
	if cpaIdentity(left) == cpaIdentity(right) {
		t.Fatalf("different emails with same account_id must not dedupe: %q", cpaIdentity(left))
	}
}

func TestImportConvertedCPAAutos_DifferentEmailsDoNotGetArtificialSuffix(t *testing.T) {
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	converted := []map[string]any{
		{"type": "codex", "email": "one@example.com", "plan_type": "k12", "access_token": "tok-one"},
		{"type": "codex", "email": "two@example.com", "plan_type": "k12", "access_token": "tok-two"},
	}
	result, err := h.importConvertedCPAAutos(context.Background(), sessionTextImportRequest{}, "", converted)
	if err != nil {
		t.Fatalf("import converted: %v", err)
	}
	want := []string{"codex-one@example.com-k12.json", "codex-two@example.com-k12.json"}
	if strings.Join(result.Files, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %#v, want %#v", result.Files, want)
	}
}

func TestImportConvertedCPAAutos_DistributesProxyPoolAcrossImportedAccounts(t *testing.T) {
	authDir := t.TempDir()
	store, err := newProxyStore(authDir)
	if err != nil {
		t.Fatalf("proxy store: %v", err)
	}
	available := true
	if err := store.save([]ProxyEntry{
		{ID: "p1", URL: "socks5://proxy-a.local:443", Available: &available},
		{ID: "p2", URL: "socks5://proxy-b.local:443", Available: &available},
	}); err != nil {
		t.Fatalf("save proxies: %v", err)
	}

	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	converted := []map[string]any{
		{"type": "codex", "email": "one@example.com", "access_token": "tok-one"},
		{"type": "codex", "email": "two@example.com", "access_token": "tok-two"},
		{"type": "codex", "email": "three@example.com", "access_token": "tok-three"},
		{"type": "codex", "email": "four@example.com", "access_token": "tok-four"},
	}
	result, err := h.importConvertedCPAAutos(context.Background(), sessionTextImportRequest{}, "", converted)
	if err != nil {
		t.Fatalf("import converted: %v", err)
	}
	if result.Created != 4 || result.Failed != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}

	counts := map[string]int{}
	for _, name := range result.Files {
		data, err := os.ReadFile(filepath.Join(authDir, name))
		if err != nil {
			t.Fatalf("read imported file %s: %v", name, err)
		}
		var stored map[string]any
		if err := json.Unmarshal(data, &stored); err != nil {
			t.Fatalf("decode imported file %s: %v", name, err)
		}
		counts[cpaString(stored, "proxy_url")]++
	}
	if counts["socks5://proxy-a.local:443"] != 2 || counts["socks5://proxy-b.local:443"] != 2 {
		t.Fatalf("proxy distribution = %#v, want 2/2 split", counts)
	}
}

func TestBuildCPAImportFileNameReadsCodexPlanFromAccessToken(t *testing.T) {
	token := unsignedJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "afc78952-cc22-4a93-9435-afc2d347eb3b",
			"chatgpt_plan_type":  "plus",
		},
	})
	cpa := map[string]any{
		"type":         "codex",
		"email":        "soused_fenders6o+gmm@icloud.com",
		"access_token": token,
		"id_token":     "",
	}
	if got, want := buildCPAImportFileName("", cpa, 1), "codex-soused_fenders6o+gmm@icloud.com-plus.json"; got != want {
		t.Fatalf("file name = %q, want %q", got, want)
	}
}

func TestStandardAuthFileNameReadsCodexPlanFromAccessToken(t *testing.T) {
	token := unsignedJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "afc78952-cc22-4a93-9435-afc2d347eb3b",
			"chatgpt_plan_type":  "plus",
		},
	})
	meta := map[string]any{
		"type":         "codex",
		"email":        "soused_fenders6o+gmm@icloud.com",
		"access_token": token,
		"id_token":     "",
	}
	if got, want := standardAuthFileName(meta), "codex-soused_fenders6o+gmm@icloud.com-plus.json"; got != want {
		t.Fatalf("file name = %q, want %q", got, want)
	}
}

func TestNormalizeAuthFileNamesRenamesExistingFiles(t *testing.T) {
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	files := map[string]string{
		"1.json":                           `{"type":"codex","email":"one@example.com","plan_type":"k12","access_token":"tok-one"}`,
		"codex-two@example.com-k12_2.json": `{"type":"codex","email":"two@example.com","plan_type":"k12","access_token":"tok-two"}`,
	}
	for name, body := range files {
		path := filepath.Join(authDir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := h.registerAuthFromFile(context.Background(), path, []byte(body)); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	result, err := h.normalizeAuthFileNames(context.Background())
	if err != nil {
		t.Fatalf("normalize names: %v", err)
	}
	if result.Renamed != 2 || result.Failed != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, name := range []string{"codex-one@example.com-k12.json", "codex-two@example.com-k12.json"} {
		if _, err := os.Stat(filepath.Join(authDir, name)); err != nil {
			t.Fatalf("expected normalized file %s: %v", name, err)
		}
		if _, ok := manager.GetByID(name); !ok {
			t.Fatalf("expected auth manager to know %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(authDir, "1.json")); !os.IsNotExist(err) {
		t.Fatalf("expected 1.json removed, stat err=%v", err)
	}
}

func TestProxyCheckRecordsIPInfo(t *testing.T) {
	oldURL := proxyIPInfoURL
	proxyIPInfoURL = "http://ipinfo.io/json"
	t.Cleanup(func() { proxyIPInfoURL = oldURL })

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != proxyIPInfoURL {
			t.Fatalf("proxy target = %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"38.111.61.59","country":"US","region":"California","city":"Los Angeles"}`))
	}))
	defer proxy.Close()

	authDir := t.TempDir()
	store, err := newProxyStore(authDir)
	if err != nil {
		t.Fatalf("proxy store: %v", err)
	}
	entry := ProxyEntry{ID: "p1", URL: proxy.URL}
	if err := store.save([]ProxyEntry{entry}); err != nil {
		t.Fatalf("save proxy: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, coreauth.NewManager(nil, nil, nil))
	if err := h.refreshProxyInfo(context.Background(), store, entry.ID, entry.URL); err != nil {
		t.Fatalf("refresh proxy: %v", err)
	}
	entries, err := store.load()
	if err != nil {
		t.Fatalf("load proxy: %v", err)
	}
	if len(entries) != 1 || entries[0].Available == nil || !*entries[0].Available {
		t.Fatalf("proxy availability not recorded: %#v", entries)
	}
	if entries[0].IP != "38.111.61.59" || entries[0].Country != "US" || entries[0].Region != "California" || entries[0].City != "Los Angeles" || entries[0].Group != "US:California" {
		t.Fatalf("proxy geo not recorded: %#v", entries[0])
	}
}

func TestProxyAutoAssignAssignsOnlyAuthsWithoutProxy(t *testing.T) {
	authDir := t.TempDir()
	store, err := newProxyStore(authDir)
	if err != nil {
		t.Fatalf("proxy store: %v", err)
	}
	available := true
	if err := store.save([]ProxyEntry{
		{ID: "p1", URL: "http://proxy-a.local:8080", Available: &available},
		{ID: "p2", URL: "http://proxy-b.local:8080", Available: &available},
	}); err != nil {
		t.Fatalf("save proxies: %v", err)
	}
	manager := coreauth.NewManager(nil, nil, nil)
	if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: "a1", FileName: "a1.json", Provider: "codex"}); err != nil {
		t.Fatalf("register a1: %v", err)
	}
	if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: "a2", FileName: "a2.json", Provider: "codex", ProxyURL: "http://existing.local:8080"}); err != nil {
		t.Fatalf("register a2: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/proxies/auto-assign", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PostProxyAutoAssign(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}
	a1, _ := manager.GetByID("a1")
	if a1.ProxyURL == "" {
		t.Fatalf("a1 proxy not assigned")
	}
	a2, _ := manager.GetByID("a2")
	if a2.ProxyURL != "http://existing.local:8080" {
		t.Fatalf("a2 proxy should be preserved, got %q", a2.ProxyURL)
	}
}

func strconvQuote(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + ".sig"
}
