// Package scan contient le moteur d'analyse de headscan : vérifications, score et rapport HTML.
package scan

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Status est le résultat d'une vérification.
type Status string

const (
	Pass Status = "ok"
	Warn Status = "attention"
	Fail Status = "échec"
	Info Status = "info"
)

// Finding est le résultat d'une vérification de sécurité.
type Finding struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
	Advice   string `json:"advice,omitempty"`
	Weight   int    `json:"weight"`
}

type TLSInfo struct {
	Version  string    `json:"version"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"notAfter"`
	DaysLeft int       `json:"daysLeft"`
	DNSNames []string  `json:"dnsNames"`
}

type Result struct {
	Target     string    `json:"target"`
	FinalURL   string    `json:"finalUrl"`
	StatusCode int       `json:"statusCode"`
	Redirects  []string  `json:"redirects,omitempty"`
	TLS        *TLSInfo  `json:"tls,omitempty"`
	Findings   []Finding `json:"findings"`
	Score      int       `json:"score"`
	Grade      string    `json:"grade"`
	ScannedAt  time.Time `json:"scannedAt"`
	DurationMs int64     `json:"durationMs"`
}

// Scanner effectue l'analyse. Le client HTTP est injectable pour les tests.
type Scanner struct {
	Client *http.Client
	// CheckHTTPRedirect vérifie que la version http:// redirige vers https://.
	CheckHTTPRedirect bool
}

const userAgent = "headscan/1.0 (+https://github.com/yaniscalo36-commits/headscan)"

func NewScanner(timeout time.Duration) *Scanner {
	return &Scanner{
		Client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10},
				Proxy:           http.ProxyFromEnvironment,
			},
		},
		CheckHTTPRedirect: true,
	}
}

// NormalizeTarget ajoute https:// si aucun schéma n'est précisé.
func NormalizeTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("schéma non supporté : %s (http ou https uniquement)", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("URL invalide : hôte manquant")
	}
	return u, nil
}

func (s *Scanner) get(u string, follow bool) (*http.Response, []string, error) {
	var chain []string
	client := *s.Client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !follow {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("trop de redirections")
		}
		chain = append(chain, req.URL.String())
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	// On lit un peu du corps pour libérer proprement la connexion.
	io.CopyN(io.Discard, resp.Body, 64<<10)
	resp.Body.Close()
	return resp, chain, nil
}

// Scan analyse la cible et renvoie le rapport complet.
func (s *Scanner) Scan(target string) (*Result, error) {
	start := time.Now()
	u, err := NormalizeTarget(target)
	if err != nil {
		return nil, err
	}

	resp, chain, err := s.get(u.String(), true)
	if err != nil {
		return nil, fmt.Errorf("connexion impossible à %s : %w", u, err)
	}

	r := &Result{
		Target:     u.String(),
		FinalURL:   resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Redirects:  chain,
		ScannedAt:  start,
	}
	isHTTPS := resp.Request.URL.Scheme == "https"

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		r.TLS = &TLSInfo{
			Version:  tls.VersionName(resp.TLS.Version),
			Issuer:   cert.Issuer.CommonName,
			NotAfter: cert.NotAfter,
			DaysLeft: int(time.Until(cert.NotAfter).Hours() / 24),
			DNSNames: cert.DNSNames,
		}
	}

	r.Findings = append(r.Findings, checkTransport(resp, isHTTPS)...)
	if s.CheckHTTPRedirect && isHTTPS {
		r.Findings = append(r.Findings, s.checkHTTPRedirect(resp.Request.URL))
	}
	r.Findings = append(r.Findings, checkHeaders(resp.Header, isHTTPS)...)
	r.Findings = append(r.Findings, checkCookies(resp.Cookies(), isHTTPS))
	r.Findings = append(r.Findings, checkDisclosure(resp.Header)...)

	r.Score, r.Grade = score(r.Findings)
	r.DurationMs = time.Since(start).Milliseconds()
	return r, nil
}

// checkHTTPRedirect vérifie que http://hôte redirige vers https://.
func (s *Scanner) checkHTTPRedirect(httpsURL *url.URL) Finding {
	f := Finding{Category: "Transport", Name: "Redirection HTTP → HTTPS", Weight: 10}
	plain := *httpsURL
	plain.Scheme = "http"
	plain.Host = httpsURL.Hostname() // port par défaut (80)
	plain.Path = "/"
	plain.RawQuery = ""

	resp, _, err := s.get(plain.String(), false)
	if err != nil {
		f.Status, f.Detail = Info, "Le port 80 ne répond pas (HTTP désactivé)."
		f.Weight = 0
		return f
	}
	loc := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(strings.ToLower(loc), "https://") {
		f.Status, f.Detail = Pass, fmt.Sprintf("%d vers %s", resp.StatusCode, loc)
		return f
	}
	f.Status = Fail
	f.Detail = fmt.Sprintf("http:// répond %d sans rediriger vers HTTPS.", resp.StatusCode)
	f.Advice = "Rediriger tout le trafic HTTP vers HTTPS avec un code 301."
	return f
}
