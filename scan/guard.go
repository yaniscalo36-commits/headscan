package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// ErrBlockedTarget est renvoyée quand la cible pointe vers une adresse interne ou réservée.
var ErrBlockedTarget = errors.New("cible interdite : adresse privée, locale ou réservée")

// Plages non couvertes par les méthodes de netip mais qu'un service public ne doit jamais contacter.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // « ce réseau »
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // tests de performance
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // réservé
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 : peut cacher une IPv4 privée
	netip.MustParsePrefix("64:ff9b:1::/48"),  // NAT64 local
	netip.MustParsePrefix("100::/64"),        // poubelle IPv6
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// IsPublicIP indique si une adresse est routable sur Internet (ni privée, ni locale, ni réservée).
// 169.254.169.254, l'adresse des métadonnées cloud, est couverte par IsLinkLocalUnicast.
func IsPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// safeDialContext résout le nom puis se connecte uniquement à une IP publique, sur le port 80 ou 443.
// Le contrôle est fait au moment de la connexion, et non sur l'URL : il s'applique aussi aux
// redirections et empêche le DNS rebinding (un nom qui change d'IP entre le contrôle et la connexion).
func safeDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if port != "80" && port != "443" {
			return nil, fmt.Errorf("%w (port %s : seuls 80 et 443 sont autorisés)", ErrBlockedTarget, port)
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if IsPublicIP(ip) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
		}
		return nil, fmt.Errorf("%w (%s)", ErrBlockedTarget, host)
	}
}

// NewSafeScanner crée un scanner destiné à un service public : connexions limitées aux IP publiques
// et aux ports 80/443, pas de proxy, en-têtes de réponse limités en taille.
func NewSafeScanner(timeout time.Duration) *Scanner {
	return &Scanner{
		Client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:                  nil,
				DialContext:            safeDialContext(timeout),
				TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS10},
				TLSHandshakeTimeout:    timeout,
				ResponseHeaderTimeout:  timeout,
				MaxResponseHeaderBytes: 64 << 10,
				DisableKeepAlives:      true,
			},
		},
		CheckHTTPRedirect: true,
	}
}
