package scan

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "203.0.113.5", "224.0.0.1", "255.255.255.255", "::1", "fd00::1", "fe80::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2001:db8::1",
	}
	for _, s := range blocked {
		if IsPublicIP(netip.MustParseAddr(s)) {
			t.Errorf("%s devrait être bloquée", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "76.76.21.21", "2606:4700:4700::1111"} {
		if !IsPublicIP(netip.MustParseAddr(s)) {
			t.Errorf("%s devrait être autorisée", s)
		}
	}
}

func TestSafeScannerBlocksInternalTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	s := NewSafeScanner(2 * time.Second)
	for _, target := range []string{
		srv.URL,                          // 127.0.0.1 sur un port aléatoire
		"http://localhost/",              // nom qui résout vers la boucle locale
		"http://127.0.0.1/",              // IP littérale
		"http://169.254.169.254/latest/", // métadonnées cloud
		"http://[::1]/",                  // IPv6 locale
		"http://10.0.0.1/",               // réseau privé
	} {
		if _, err := s.Scan(target); !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("%s : erreur %v, attendu ErrBlockedTarget", target, err)
		}
	}
}

func TestSafeScannerBlocksRedirectToInternal(t *testing.T) {
	// Le contrôle se fait à la connexion : même une redirection ne peut pas atteindre une IP interne.
	dial := safeDialContext(time.Second)
	if _, err := dial(t.Context(), "tcp", "127.0.0.1:80"); !errors.Is(err, ErrBlockedTarget) {
		t.Errorf("connexion directe à 127.0.0.1:80 : %v", err)
	}
	if _, err := dial(t.Context(), "tcp", "example.com:22"); !errors.Is(err, ErrBlockedTarget) {
		t.Errorf("port 22 : %v", err)
	}
}
