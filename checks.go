package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const sixMonths = 15552000 // secondes

// ---------- Transport (HTTPS, TLS, certificat) ----------

func checkTransport(resp *http.Response, isHTTPS bool) []Finding {
	if !isHTTPS {
		return []Finding{{
			Category: "Transport", Name: "HTTPS", Status: Fail, Weight: 30,
			Detail: "Le site est servi en HTTP : tout transite en clair.",
			Advice: "Activer HTTPS (certificat gratuit avec Let's Encrypt).",
		}}
	}

	out := []Finding{{Category: "Transport", Name: "HTTPS", Status: Pass, Detail: "Connexion chiffrée.", Weight: 30}}
	if resp.TLS == nil {
		return out
	}

	v := Finding{Category: "Transport", Name: "Version TLS", Weight: 10, Detail: tls.VersionName(resp.TLS.Version)}
	switch {
	case resp.TLS.Version >= tls.VersionTLS13:
		v.Status = Pass
	case resp.TLS.Version == tls.VersionTLS12:
		v.Status = Pass
		v.Detail += " (TLS 1.3 recommandé)"
	default:
		v.Status = Fail
		v.Advice = "Désactiver TLS 1.0 et 1.1, obsolètes et vulnérables."
	}
	out = append(out, v)

	if len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		c := Finding{Category: "Transport", Name: "Certificat", Weight: 5,
			Detail: fmt.Sprintf("Émis par %s, expire dans %d jours", cert.Issuer.CommonName, days)}
		switch {
		case days < 0:
			c.Status, c.Advice = Fail, "Le certificat a expiré : le renouveler immédiatement."
		case days < 14:
			c.Status, c.Advice = Warn, "Le certificat expire bientôt : automatiser le renouvellement."
		default:
			c.Status = Pass
		}
		out = append(out, c)
	}
	return out
}

// ---------- En-têtes de sécurité ----------

func checkHeaders(h http.Header, isHTTPS bool) []Finding {
	var out []Finding
	if isHTTPS {
		out = append(out, checkHSTS(h.Get("Strict-Transport-Security")))
	}
	csp := h.Get("Content-Security-Policy")
	out = append(out,
		checkCSP(csp),
		checkClickjacking(h.Get("X-Frame-Options"), csp),
		checkNoSniff(h.Get("X-Content-Type-Options")),
		checkReferrer(h.Get("Referrer-Policy")),
		checkPermissions(h.Get("Permissions-Policy")),
	)
	return out
}

func checkHSTS(v string) Finding {
	f := Finding{Category: "En-têtes", Name: "Strict-Transport-Security", Weight: 15}
	if v == "" {
		f.Status, f.Detail = Fail, "Absent : un attaquant peut forcer une connexion HTTP (SSL stripping)."
		f.Advice = "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains"
		return f
	}
	maxAge := -1
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "max-age=") {
			maxAge, _ = strconv.Atoi(strings.Trim(strings.TrimPrefix(part, "max-age="), `"`))
		}
	}
	f.Detail = v
	if maxAge < sixMonths {
		f.Status = Warn
		f.Advice = "max-age trop court : viser au moins 6 mois (15552000), idéalement 1 an."
		return f
	}
	f.Status = Pass
	return f
}

func checkCSP(v string) Finding {
	f := Finding{Category: "En-têtes", Name: "Content-Security-Policy", Weight: 20}
	if v == "" {
		f.Status, f.Detail = Fail, "Absent : aucune défense en profondeur contre les failles XSS."
		f.Advice = "Définir une politique, par exemple : default-src 'self'; object-src 'none'; frame-ancestors 'none'"
		return f
	}
	f.Detail = truncate(v, 120)
	var issues []string
	lower := strings.ToLower(v)
	for _, d := range strings.Split(lower, ";") {
		d = strings.TrimSpace(d)
		if !strings.HasPrefix(d, "script-src") && !strings.HasPrefix(d, "default-src") {
			continue
		}
		if strings.Contains(d, "'unsafe-inline'") {
			issues = append(issues, "'unsafe-inline'")
		}
		if strings.Contains(d, "'unsafe-eval'") {
			issues = append(issues, "'unsafe-eval'")
		}
		if fields := strings.Fields(d); contains(fields[1:], "*") {
			issues = append(issues, "source « * »")
		}
	}
	if len(issues) > 0 {
		f.Status = Warn
		f.Advice = "La politique autorise " + strings.Join(dedupe(issues), ", ") + " pour les scripts, ce qui affaiblit fortement la protection XSS."
		return f
	}
	f.Status = Pass
	return f
}

func checkClickjacking(xfo, csp string) Finding {
	f := Finding{Category: "En-têtes", Name: "Protection clickjacking", Weight: 10}
	if strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		f.Status, f.Detail = Pass, "CSP frame-ancestors"
		return f
	}
	switch strings.ToUpper(strings.TrimSpace(xfo)) {
	case "DENY", "SAMEORIGIN":
		f.Status, f.Detail = Pass, "X-Frame-Options: "+xfo
	case "":
		f.Status, f.Detail = Fail, "Ni X-Frame-Options ni frame-ancestors : le site peut être intégré dans une iframe malveillante."
		f.Advice = "Ajouter X-Frame-Options: DENY (ou frame-ancestors 'none' dans la CSP)."
	default:
		f.Status, f.Detail = Warn, "Valeur X-Frame-Options non standard : "+xfo
		f.Advice = "Utiliser DENY ou SAMEORIGIN."
	}
	return f
}

func checkNoSniff(v string) Finding {
	f := Finding{Category: "En-têtes", Name: "X-Content-Type-Options", Weight: 10}
	if strings.EqualFold(strings.TrimSpace(v), "nosniff") {
		f.Status, f.Detail = Pass, "nosniff"
		return f
	}
	f.Status, f.Detail = Fail, "Absent : le navigateur peut deviner le type des fichiers (MIME sniffing)."
	f.Advice = "Ajouter : X-Content-Type-Options: nosniff"
	return f
}

func checkReferrer(v string) Finding {
	f := Finding{Category: "En-têtes", Name: "Referrer-Policy", Weight: 5}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		f.Status, f.Detail = Warn, "Absent : le comportement par défaut du navigateur s'applique."
		f.Advice = "Ajouter : Referrer-Policy: strict-origin-when-cross-origin"
	case "unsafe-url", "no-referrer-when-downgrade":
		f.Status, f.Detail = Warn, v+" : l'URL complète peut fuiter vers d'autres sites."
		f.Advice = "Préférer strict-origin-when-cross-origin ou no-referrer."
	default:
		f.Status, f.Detail = Pass, v
	}
	return f
}

func checkPermissions(v string) Finding {
	f := Finding{Category: "En-têtes", Name: "Permissions-Policy", Weight: 5}
	if v == "" {
		f.Status, f.Detail = Warn, "Absent : les API sensibles (caméra, micro, géolocalisation) ne sont pas restreintes."
		f.Advice = "Ajouter par exemple : Permissions-Policy: camera=(), microphone=(), geolocation=()"
		return f
	}
	f.Status, f.Detail = Pass, truncate(v, 120)
	return f
}

// ---------- Cookies ----------

func checkCookies(cookies []*http.Cookie, isHTTPS bool) Finding {
	f := Finding{Category: "Cookies", Name: "Attributs des cookies", Weight: 10}
	if len(cookies) == 0 {
		f.Status, f.Detail, f.Weight = Info, "Aucun cookie défini sur cette page.", 0
		return f
	}
	var problems []string
	for _, c := range cookies {
		var missing []string
		if isHTTPS && !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if c.SameSite == http.SameSiteDefaultMode || c.SameSite == 0 {
			missing = append(missing, "SameSite")
		} else if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			missing = append(missing, "Secure (requis avec SameSite=None)")
		}
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("%s (sans %s)", c.Name, strings.Join(missing, ", ")))
		}
	}
	if len(problems) == 0 {
		f.Status, f.Detail = Pass, fmt.Sprintf("%d cookie(s) correctement protégé(s).", len(cookies))
		return f
	}
	f.Status = Warn
	f.Detail = strings.Join(problems, " ; ")
	f.Advice = "Les cookies de session doivent avoir Secure, HttpOnly et SameSite=Lax (ou Strict)."
	return f
}

// ---------- Fuites d'informations ----------

var versionRe = regexp.MustCompile(`\d+(\.\d+)+`)

func checkDisclosure(h http.Header) []Finding {
	server := Finding{Category: "Fuite d'informations", Name: "En-tête Server", Weight: 5}
	switch s := h.Get("Server"); {
	case s == "":
		server.Status, server.Detail = Pass, "Absent."
	case versionRe.MatchString(s):
		server.Status, server.Detail = Warn, s+" : la version exacte aide un attaquant à cibler des failles connues."
		server.Advice = "Masquer le numéro de version (ex. server_tokens off sous Nginx)."
	default:
		server.Status, server.Detail = Pass, s+" (sans numéro de version)"
	}

	powered := Finding{Category: "Fuite d'informations", Name: "En-tête X-Powered-By", Weight: 5}
	if p := h.Get("X-Powered-By"); p != "" {
		powered.Status, powered.Detail = Warn, p+" : révèle la technologie utilisée."
		powered.Advice = "Supprimer cet en-tête."
	} else {
		powered.Status, powered.Detail = Pass, "Absent."
	}
	return []Finding{server, powered}
}

// ---------- Score ----------

// score retire les points des vérifications ratées (la moitié pour un avertissement)
// et convertit le résultat en note de A+ à F.
func score(findings []Finding) (int, string) {
	total, lost := 0, 0
	for _, f := range findings {
		total += f.Weight
		switch f.Status {
		case Fail:
			lost += f.Weight
		case Warn:
			lost += f.Weight / 2
		}
	}
	if total == 0 {
		return 0, "?"
	}
	s := 100 * (total - lost) / total
	switch {
	case s >= 95:
		return s, "A+"
	case s >= 85:
		return s, "A"
	case s >= 70:
		return s, "B"
	case s >= 55:
		return s, "C"
	case s >= 40:
		return s, "D"
	case s >= 25:
		return s, "E"
	}
	return s, "F"
}

// ---------- Utilitaires ----------

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range list {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
