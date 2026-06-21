package management

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProxyStoreUsesProxyPoolDir(t *testing.T) {
	authDir := t.TempDir()
	proxyPoolDir := t.TempDir()

	store, err := newProxyStore(proxyPoolDir)
	if err != nil {
		t.Fatalf("new proxy store: %v", err)
	}
	if err := store.save([]ProxyEntry{{ID: "p1", URL: "socks5://proxy.local:1080"}}); err != nil {
		t.Fatalf("save proxies: %v", err)
	}

	if _, err := os.Stat(filepath.Join(proxyPoolDir, "p1.json")); err != nil {
		t.Fatalf("proxy pool file not written under proxy-pool-dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(authDir, "proxies.json")); !os.IsNotExist(err) {
		t.Fatalf("proxy pool file should not be written under auth-dir, stat err=%v", err)
	}
}
