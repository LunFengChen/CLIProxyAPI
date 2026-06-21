package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// ProxyEntry represents a single proxy in the pool.
// group is a free-text label used only for UI grouping (e.g. "US-California").
type ProxyEntry struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Group       string `json:"group,omitempty"`
	Label       string `json:"label,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	Available   *bool  `json:"available,omitempty"`
	CheckError  string `json:"check_error,omitempty"`
	LastChecked string `json:"last_checked,omitempty"`
	IP          string `json:"ip,omitempty"`
	Country     string `json:"country,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
}

// proxyPoolResponse augments a ProxyEntry with derived assigned_to list.
type proxyPoolResponse struct {
	ProxyEntry
	AssignedTo []string `json:"assigned_to"`
}

// proxyStore handles atomic read/write of one JSON file per proxy inside proxy-pool-dir.
type proxyStore struct {
	mu   sync.RWMutex
	path string
}

func newProxyStore(proxyPoolDir string) (*proxyStore, error) {
	resolved, err := util.ResolveProxyPoolDir(proxyPoolDir)
	if err != nil {
		return nil, fmt.Errorf("proxy store: resolve proxy pool dir: %w", err)
	}
	if err := os.MkdirAll(resolved, 0o700); err != nil {
		return nil, fmt.Errorf("proxy store: mkdir: %w", err)
	}
	return &proxyStore{path: resolved}, nil
}

func (s *proxyStore) load() ([]ProxyEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("proxy store: read dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	out := make([]ProxyEntry, 0, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") || strings.EqualFold(name, "proxies.json") {
			continue
		}
		fullPath := filepath.Join(s.path, name)
		data, errRead := os.ReadFile(fullPath)
		if errRead != nil {
			return nil, fmt.Errorf("proxy store: read %s: %w", name, errRead)
		}
		var proxy ProxyEntry
		if errUnmarshal := json.Unmarshal(data, &proxy); errUnmarshal != nil {
			return nil, fmt.Errorf("proxy store: unmarshal %s: %w", name, errUnmarshal)
		}
		if strings.TrimSpace(proxy.ID) == "" {
			proxy.ID = strings.TrimSuffix(name, filepath.Ext(name))
		}
		out = append(out, proxy)
	}
	return out, nil
}

func (s *proxyStore) save(entries []ProxyEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entries == nil {
		entries = []ProxyEntry{}
	}
	if err := os.MkdirAll(s.path, 0o700); err != nil {
		return fmt.Errorf("proxy store: mkdir: %w", err)
	}
	keep := make(map[string]struct{}, len(entries))
	for i := range entries {
		if strings.TrimSpace(entries[i].ID) == "" {
			entries[i].ID = uuid.New().String()
		}
		fileName := proxyEntryFileName(entries[i].ID)
		keep[fileName] = struct{}{}
		raw, errMarshal := json.MarshalIndent(entries[i], "", "  ")
		if errMarshal != nil {
			return fmt.Errorf("proxy store: marshal %s: %w", fileName, errMarshal)
		}
		raw = append(raw, '\n')
		fullPath := filepath.Join(s.path, fileName)
		tmp := fullPath + ".tmp"
		if errWrite := os.WriteFile(tmp, raw, 0o600); errWrite != nil {
			return fmt.Errorf("proxy store: write tmp %s: %w", fileName, errWrite)
		}
		if errRename := os.Rename(tmp, fullPath); errRename != nil {
			return fmt.Errorf("proxy store: rename %s: %w", fileName, errRename)
		}
	}
	existing, err := os.ReadDir(s.path)
	if err != nil {
		return fmt.Errorf("proxy store: read dir for cleanup: %w", err)
	}
	for _, entry := range existing {
		if entry == nil || entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") || strings.EqualFold(name, "proxies.json") {
			continue
		}
		if _, ok := keep[name]; ok {
			continue
		}
		if errRemove := os.Remove(filepath.Join(s.path, name)); errRemove != nil && !os.IsNotExist(errRemove) {
			return fmt.Errorf("proxy store: remove stale %s: %w", name, errRemove)
		}
	}
	return nil
}

func proxyEntryFileName(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		id = uuid.New().String()
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), ".")
	if name == "" {
		name = uuid.New().String()
	}
	return name + ".json"
}

// ---- Handler wiring ----
// We cache a *proxyStore per *Handler using a package-level sync.Map to avoid
// modifying the Handler struct definition (which is managed upstream).

var handlerProxyStores sync.Map // key: *Handler → *proxyStoreCache

var proxyIPInfoURL = "https://ipinfo.io/json"

const (
	proxyPoolHealthCheckInterval = 5 * time.Minute
	proxyPoolPerProxyTimeout     = 15 * time.Second
)

type proxyStoreCache struct {
	once  sync.Once
	store *proxyStore
	err   error
}

func (h *Handler) proxyStoreForHandler() (*proxyStore, error) {
	v, _ := handlerProxyStores.LoadOrStore(h, &proxyStoreCache{})
	c := v.(*proxyStoreCache)
	c.once.Do(func() {
		proxyPoolDir := ""
		if h.cfg != nil {
			proxyPoolDir = strings.TrimSpace(h.cfg.ProxyPoolDir)
		}
		c.store, c.err = newProxyStore(proxyPoolDir)
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

func activeProxyEntries(entries []ProxyEntry) []ProxyEntry {
	out := make([]ProxyEntry, 0, len(entries))
	for _, entry := range entries {
		entry.URL = strings.TrimSpace(entry.URL)
		if entry.URL == "" || entry.Disabled || (entry.Available != nil && !*entry.Available) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

type proxyAllocator struct {
	candidates []ProxyEntry
	assigned   map[string]int
}

func (h *Handler) newProxyAllocator() *proxyAllocator {
	store, err := h.proxyStoreForHandler()
	if err != nil {
		return nil
	}
	entries, err := store.load()
	if err != nil {
		return nil
	}
	candidates := activeProxyEntries(entries)
	if len(candidates) == 0 {
		return nil
	}

	assigned := map[string]int{}
	if h != nil && h.authManager != nil {
		for url, ids := range assignedToMap(h.authManager.List()) {
			assigned[url] = len(ids)
		}
	}
	return &proxyAllocator{candidates: candidates, assigned: assigned}
}

func (a *proxyAllocator) Next() string {
	if a == nil || len(a.candidates) == 0 {
		return ""
	}
	best := a.candidates[0]
	bestCount := a.assigned[best.URL]
	for _, candidate := range a.candidates[1:] {
		count := a.assigned[candidate.URL]
		if count < bestCount {
			best = candidate
			bestCount = count
		}
	}
	a.assigned[best.URL]++
	return best.URL
}

// pickProxyURLForImportedAuth chooses the least-assigned enabled proxy from the
// persisted proxy pool. Empty return means the import should proceed unproxied.
func (h *Handler) pickProxyURLForImportedAuth() string {
	return h.newProxyAllocator().Next()
}

func (h *Handler) startProxyPoolHealthLoop() {
	if h == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(proxyPoolHealthCheckInterval)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), proxyPoolHealthCheckInterval)
			if err := h.refreshProxyPoolOnce(ctx); err != nil {
				log.WithError(err).Warn("management: proxy pool health check failed")
			}
			cancel()
		}
	}()
}

func normalizeProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		if strings.Count(raw, ":") >= 3 && !strings.Contains(raw, "@") {
			parts := strings.SplitN(raw, ":", 4)
			if len(parts) == 4 && parts[0] != "" && parts[1] != "" {
				u := &url.URL{
					Scheme: "socks5",
					User:   url.UserPassword(parts[2], parts[3]),
					Host:   parts[0] + ":" + parts[1],
				}
				raw = u.String()
			} else {
				raw = "socks5://" + raw
			}
		} else {
			raw = "socks5://" + raw
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid proxy url")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}
	return parsed.String(), nil
}

func (h *Handler) ensureProxyPoolEntry(proxyURL string) (string, error) {
	proxyURL, err := normalizeProxyURL(proxyURL)
	if err != nil {
		return "", err
	}
	if proxyURL == "" {
		return "", nil
	}
	store, err := h.proxyStoreForHandler()
	if err != nil {
		return "", err
	}
	entries, err := store.load()
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if strings.TrimSpace(entry.URL) == proxyURL {
			if entry.LastChecked == "" {
				h.startProxyCheck(store, entry.ID, proxyURL)
			}
			return proxyURL, nil
		}
	}
	id := uuid.New().String()
	entries = append(entries, ProxyEntry{
		ID:    id,
		URL:   proxyURL,
		Label: "imported",
	})
	if err := store.save(entries); err != nil {
		return "", err
	}
	h.startProxyCheck(store, id, proxyURL)
	return proxyURL, nil
}

// ---- HTTP handlers ----

type proxyCheckResult struct {
	Available bool
	Error     string
	IP        string
	Country   string
	Region    string
	City      string
	Group     string
}

// detectProxyInfo dials ipinfo.io/json through the given proxy URL and returns
// availability + geo details. It is best-effort and bounded by caller context.
func detectProxyInfo(ctx context.Context, proxyURL string) proxyCheckResult {
	result := proxyCheckResult{}
	transport := &http.Transport{}
	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		} else {
			result.Error = err.Error()
			return result
		}
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyIPInfoURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("ipinfo status %d", resp.StatusCode)
		_ = resp.Body.Close()
		return result
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			// best-effort; ignore
		}
	}()
	var info struct {
		IP      string `json:"ip"`
		City    string `json:"city"`
		Country string `json:"country"`
		Region  string `json:"region"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Available = true
	result.IP = strings.TrimSpace(info.IP)
	result.Country = strings.TrimSpace(info.Country)
	result.Region = strings.TrimSpace(info.Region)
	result.City = strings.TrimSpace(info.City)
	switch {
	case info.Country != "" && info.Region != "":
		result.Group = info.Country + ":" + info.Region
	case info.Country != "":
		result.Group = info.Country
	case info.Region != "":
		result.Group = info.Region
	}
	return result
}

func (h *Handler) startProxyCheck(store *proxyStore, id, proxyURL string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), proxyPoolPerProxyTimeout)
		defer cancel()
		_ = h.refreshProxyInfo(ctx, store, id, proxyURL)
	}()
}

func (h *Handler) refreshProxyPoolOnce(ctx context.Context) error {
	store, err := h.proxyStoreForHandler()
	if err != nil {
		return err
	}
	entries, err := store.load()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		proxyURL := strings.TrimSpace(entry.URL)
		if proxyURL == "" || entry.Disabled {
			continue
		}
		if ctx != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
		checkCtx := ctx
		cancel := func() {}
		if checkCtx == nil {
			checkCtx = context.Background()
		}
		checkCtx, cancel = context.WithTimeout(checkCtx, proxyPoolPerProxyTimeout)
		errRefresh := h.refreshProxyInfo(checkCtx, store, entry.ID, proxyURL)
		cancel()
		if errRefresh != nil {
			return errRefresh
		}

		latest, errLoad := store.load()
		if errLoad != nil {
			return errLoad
		}
		if !proxyEntryAvailable(latest, entry.ID) {
			if _, errReassign := h.reassignAuthsFromProxy(ctx, proxyURL, latest); errReassign != nil {
				return errReassign
			}
		}
	}
	return nil
}

func proxyEntryAvailable(entries []ProxyEntry, id string) bool {
	for _, entry := range entries {
		if entry.ID != id {
			continue
		}
		return entry.Available == nil || *entry.Available
	}
	return false
}

func activeProxyEntriesExcept(entries []ProxyEntry, excludedURL string) []ProxyEntry {
	active := activeProxyEntries(entries)
	if strings.TrimSpace(excludedURL) == "" {
		return active
	}
	out := active[:0]
	for _, entry := range active {
		if strings.TrimSpace(entry.URL) == excludedURL {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func pickLeastAssignedProxy(candidates []ProxyEntry, assigned map[string]int) (ProxyEntry, bool) {
	if len(candidates) == 0 {
		return ProxyEntry{}, false
	}
	best := candidates[0]
	bestCount := assigned[best.URL]
	for _, candidate := range candidates[1:] {
		count := assigned[candidate.URL]
		if count < bestCount {
			best = candidate
			bestCount = count
		}
	}
	return best, true
}

func (h *Handler) reassignAuthsFromProxy(ctx context.Context, failedProxyURL string, entries []ProxyEntry) (int, error) {
	failedProxyURL = strings.TrimSpace(failedProxyURL)
	if h == nil || h.authManager == nil || failedProxyURL == "" {
		return 0, nil
	}
	candidates := activeProxyEntriesExcept(entries, failedProxyURL)
	if len(candidates) == 0 {
		return 0, nil
	}

	auths := h.authManager.List()
	assignedCount := map[string]int{}
	for url, ids := range assignedToMap(auths) {
		assignedCount[url] = len(ids)
	}

	now := time.Now()
	updated := 0
	for _, auth := range auths {
		if auth == nil || strings.TrimSpace(auth.ProxyURL) != failedProxyURL {
			continue
		}
		best, ok := pickLeastAssignedProxy(candidates, assignedCount)
		if !ok {
			break
		}
		auth.ProxyURL = best.URL
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata["proxy_url"] = best.URL
		auth.UpdatedAt = now
		if _, err := h.authManager.Update(ctx, auth); err != nil {
			return updated, fmt.Errorf("update auth %s proxy: %w", auth.ID, err)
		}
		assignedCount[failedProxyURL]--
		assignedCount[best.URL]++
		updated++
	}
	return updated, nil
}

func (h *Handler) refreshProxyInfo(ctx context.Context, store *proxyStore, id, proxyURL string) error {
	checkedAt := time.Now().UTC().Format(time.RFC3339)
	info := detectProxyInfo(ctx, proxyURL)
	entries, err := store.load()
	if err != nil {
		return err
	}
	updated := false
	for i := range entries {
		if entries[i].ID != id {
			continue
		}
		entries[i].Available = &info.Available
		entries[i].CheckError = info.Error
		entries[i].LastChecked = checkedAt
		entries[i].IP = info.IP
		entries[i].Country = info.Country
		entries[i].Region = info.Region
		entries[i].City = info.City
		if info.Group != "" && strings.TrimSpace(entries[i].Group) == "" {
			entries[i].Group = info.Group
		}
		updated = true
		break
	}
	if !updated {
		return nil
	}
	return store.save(entries)
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
	normalizedURL, err := normalizeProxyURL(req.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.URL = normalizedURL
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

	h.startProxyCheck(store, req.ID, req.URL)

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
	normalizedURL, err := normalizeProxyURL(req.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.URL = normalizedURL
	if req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url is required"})
		return
	}
	req.ID = id
	req.Available = nil
	req.CheckError = ""
	req.LastChecked = ""
	req.IP = ""
	req.Country = ""
	req.Region = ""
	req.City = ""

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
	h.startProxyCheck(store, req.ID, req.URL)
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

// PostProxyAutoAssign assigns enabled/available proxies to auth records that do
// not have a per-auth proxy_url. This migrates accounts off a global proxy.
func (h *Handler) PostProxyAutoAssign(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
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
	proxies := activeProxyEntries(entries)
	if len(proxies) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no enabled available proxies"})
		return
	}

	auths := h.authManager.List()
	assignedCount := map[string]int{}
	for url, ids := range assignedToMap(auths) {
		assignedCount[url] = len(ids)
	}

	ctx := c.Request.Context()
	now := time.Now()
	var updated []string
	var skipped []string
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if strings.TrimSpace(auth.ProxyURL) != "" {
			skipped = append(skipped, auth.ID)
			continue
		}
		best := proxies[0]
		bestCount := assignedCount[best.URL]
		for _, candidate := range proxies[1:] {
			count := assignedCount[candidate.URL]
			if count < bestCount {
				best = candidate
				bestCount = count
			}
		}
		auth.ProxyURL = best.URL
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata["proxy_url"] = best.URL
		auth.UpdatedAt = now
		if _, errUpdate := h.authManager.Update(ctx, auth); errUpdate != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("update auth %s: %v", auth.ID, errUpdate)})
			return
		}
		assignedCount[best.URL]++
		updated = append(updated, auth.ID)
	}
	if updated == nil {
		updated = []string{}
	}
	if skipped == nil {
		skipped = []string{}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":      "ok",
		"updated":     updated,
		"skipped":     skipped,
		"proxy_count": len(proxies),
	})
}
