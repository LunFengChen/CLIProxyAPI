package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// ProxyEntry represents a single proxy in the pool.
// group is a free-text label used only for UI grouping (e.g. "US-California").
type ProxyEntry struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Group    string `json:"group,omitempty"`
	Label    string `json:"label,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
}

// proxyPoolResponse augments a ProxyEntry with derived assigned_to list.
type proxyPoolResponse struct {
	ProxyEntry
	AssignedTo []string `json:"assigned_to"`
}

// proxyStore handles atomic read/write of proxies.json inside auth-dir.
type proxyStore struct {
	mu   sync.RWMutex
	path string
}

func newProxyStore(authDir string) (*proxyStore, error) {
	resolved, err := util.ResolveAuthDir(authDir)
	if err != nil {
		return nil, fmt.Errorf("proxy store: resolve auth dir: %w", err)
	}
	if err := os.MkdirAll(resolved, 0o700); err != nil {
		return nil, fmt.Errorf("proxy store: mkdir: %w", err)
	}
	return &proxyStore{path: filepath.Join(resolved, "proxies.json")}, nil
}

func (s *proxyStore) load() ([]ProxyEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("proxy store: read: %w", err)
	}
	var entries []ProxyEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("proxy store: unmarshal: %w", err)
	}
	return entries, nil
}

func (s *proxyStore) save(entries []ProxyEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entries == nil {
		entries = []ProxyEntry{}
	}
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("proxy store: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("proxy store: write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("proxy store: rename: %w", err)
	}
	return nil
}

// ---- Handler wiring ----
// We cache a *proxyStore per *Handler using a package-level sync.Map to avoid
// modifying the Handler struct definition (which is managed upstream).

var handlerProxyStores sync.Map // key: *Handler → *proxyStoreCache

type proxyStoreCache struct {
	once  sync.Once
	store *proxyStore
	err   error
}

func (h *Handler) proxyStoreForHandler() (*proxyStore, error) {
	v, _ := handlerProxyStores.LoadOrStore(h, &proxyStoreCache{})
	c := v.(*proxyStoreCache)
	c.once.Do(func() {
		authDir := ""
		if h.cfg != nil {
			authDir = strings.TrimSpace(h.cfg.AuthDir)
		}
		c.store, c.err = newProxyStore(authDir)
	})
	return c.store, c.err
}

// assignedToMap returns proxy URL → slice of auth IDs using it.
func assignedToMap(auths []*coreauth.Auth) map[string][]string {
	m := make(map[string][]string)
	for _, a := range auths {
		if u := strings.TrimSpace(a.ProxyURL); u != "" {
			m[u] = append(m[u], a.ID)
		}
	}
	return m
}

// ---- HTTP handlers ----

// detectProxyRegion dials ipinfo.io/json through the given proxy URL and returns
// a "COUNTRY:Region" label (e.g. "US:California").  Returns "" on any failure
// (best-effort; callers should not block on this).
func detectProxyRegion(ctx context.Context, proxyURL string) string {
	transport := &http.Transport{}
	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			// best-effort; ignore
		}
	}()
	var info struct {
		Country string `json:"country"`
		Region  string `json:"region"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return ""
	}
	switch {
	case info.Country != "" && info.Region != "":
		return info.Country + ":" + info.Region
	case info.Country != "":
		return info.Country
	case info.Region != "":
		return info.Region
	default:
		return ""
	}
}

// GetProxies handles GET /v0/management/proxies
func (h *Handler) GetProxies(c *gin.Context) {
	store, err := h.proxyStoreForHandler()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entries, err := store.load()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []ProxyEntry{}
	}

	var assigned map[string][]string
	if h.authManager != nil {
		assigned = assignedToMap(h.authManager.List())
	}

	resp := make([]proxyPoolResponse, len(entries))
	for i, e := range entries {
		ids := assigned[e.URL]
		if ids == nil {
			ids = []string{}
		}
		resp[i] = proxyPoolResponse{ProxyEntry: e, AssignedTo: ids}
	}
	c.JSON(http.StatusOK, resp)
}

// PostProxy handles POST /v0/management/proxies
func (h *Handler) PostProxy(c *gin.Context) {
	var req ProxyEntry
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url is required"})
		return
	}
	req.ID = uuid.New().String()

	store, err := h.proxyStoreForHandler()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entries, err := store.load()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entries = append(entries, req)
	if err := store.save(entries); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Auto-detect region via ipinfo.io if the caller did not provide one.
	// This is done after the save so the proxy is persisted even if geo lookup fails.
	if req.Group == "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			region := detectProxyRegion(ctx, req.URL)
			if region == "" {
				return
			}
			entries2, err := store.load()
			if err != nil {
				return
			}
			updated := false
			for i, e := range entries2 {
				if e.ID == req.ID && e.Group == "" {
					entries2[i].Group = region
					updated = true
					break
				}
			}
			if updated {
				_ = store.save(entries2)
			}
		}()
	}

	c.JSON(http.StatusCreated, req)
}

// PutProxy handles PUT /v0/management/proxies/:id
func (h *Handler) PutProxy(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	var req ProxyEntry
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url is required"})
		return
	}
	req.ID = id

	store, err := h.proxyStoreForHandler()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entries, err := store.load()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	found := false
	for i, e := range entries {
		if e.ID == id {
			entries[i] = req
			found = true
			break
		}
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy not found"})
		return
	}
	if err := store.save(entries); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, req)
}

// DeleteProxy handles DELETE /v0/management/proxies/:id
func (h *Handler) DeleteProxy(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}

	store, err := h.proxyStoreForHandler()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entries, err := store.load()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	idx := -1
	for i, e := range entries {
		if e.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy not found"})
		return
	}
	deleted := entries[idx]
	entries = append(entries[:idx], entries[idx+1:]...)
	if err := store.save(entries); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "id": deleted.ID})
}

// assignRequest is the body for POST /v0/management/proxies/:id/assign
type assignRequest struct {
	AuthIDs []string `json:"auth_ids"`
}

// PostProxyAssign handles POST /v0/management/proxies/:id/assign
// It sets proxy_url on each listed auth to this proxy's URL.
func (h *Handler) PostProxyAssign(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
		return
	}

	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}

	store, err := h.proxyStoreForHandler()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entries, err := store.load()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var proxy *ProxyEntry
	for i := range entries {
		if entries[i].ID == id {
			proxy = &entries[i]
			break
		}
	}
	if proxy == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy not found"})
		return
	}

	var req assignRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.AuthIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_ids is required"})
		return
	}

	ctx := c.Request.Context()
	now := time.Now()
	var updated, notFound []string
	for _, authID := range req.AuthIDs {
		auth, ok := h.authManager.GetByID(authID)
		if !ok {
			notFound = append(notFound, authID)
			continue
		}
		auth.ProxyURL = proxy.URL
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata["proxy_url"] = proxy.URL
		auth.UpdatedAt = now
		if _, errUpdate := h.authManager.Update(ctx, auth); errUpdate != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("update auth %s: %v", authID, errUpdate)})
			return
		}
		updated = append(updated, authID)
	}
	if updated == nil {
		updated = []string{}
	}
	if notFound == nil {
		notFound = []string{}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"proxy_url": proxy.URL,
		"updated":   updated,
		"not_found": notFound,
	})
}
