package scan

import (
	"net/http"
	"os"
	"net/http/httptest"
	"strings"
	"testing"
)

// scanServer lance un serveur HTTPS de test avec le handler donné et l'analyse.
func scanServer(t *testing.T, h http.HandlerFunc) *Result {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	s := &Scanner{Client: srv.Client()} // pas de vérification http:// en test
	r, err := s.Scan(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(t *testing.T, r *Result, name string) Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("vérification %q introuvable", name)
	return Finding{}
}

func TestWellConfiguredSiteGetsTopGrade(t *testing.T) {
	r := scanServer(t, func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=()")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	})
	if r.Grade != "A+" {
		for _, f := range r.Findings {
			t.Logf("%-28s %s %s", f.Name, f.Status, f.Detail)
		}
		t.Fatalf("note %s (%d), attendu A+", r.Grade, r.Score)
	}
}

func TestBareSiteGetsLowGrade(t *testing.T) {
	r := scanServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.29 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.2.24")
	})
	for _, name := range []string{"Strict-Transport-Security", "Content-Security-Policy", "Protection clickjacking", "X-Content-Type-Options"} {
		if f := find(t, r, name); f.Status != Fail {
			t.Errorf("%s : %s, attendu échec", name, f.Status)
		}
	}
	if f := find(t, r, "En-tête Server"); f.Status != Warn {
		t.Errorf("version du serveur non signalée")
	}
	if f := find(t, r, "En-tête X-Powered-By"); f.Status != Warn {
		t.Errorf("X-Powered-By non signalé")
	}
	if r.Grade != "D" && r.Grade != "E" && r.Grade != "F" {
		t.Fatalf("note %s (%d), attendu D ou moins", r.Grade, r.Score)
	}
}

func TestPlainHTTPFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	r, err := (&Scanner{Client: srv.Client()}).Scan(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if f := find(t, r, "HTTPS"); f.Status != Fail {
		t.Fatal("un site en HTTP devrait échouer")
	}
}

func TestHSTS(t *testing.T) {
	if f := checkHSTS("max-age=300"); f.Status != Warn {
		t.Errorf("max-age court : %s", f.Status)
	}
	if f := checkHSTS("max-age=63072000; preload"); f.Status != Pass {
		t.Errorf("max-age 2 ans : %s", f.Status)
	}
}

func TestCSPUnsafe(t *testing.T) {
	f := checkCSP("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'")
	if f.Status != Warn || !strings.Contains(f.Advice, "unsafe-inline") || !strings.Contains(f.Advice, "unsafe-eval") {
		t.Errorf("CSP faible non détectée : %+v", f)
	}
	// 'unsafe-inline' dans style-src seulement : acceptable.
	if f := checkCSP("default-src 'self'; style-src 'self' 'unsafe-inline'"); f.Status != Pass {
		t.Errorf("style-src unsafe-inline ne devrait pas être pénalisé : %+v", f)
	}
}

func TestCookies(t *testing.T) {
	bad := []*http.Cookie{{Name: "sid", Value: "1"}}
	f := checkCookies(bad, true)
	if f.Status != Warn || !strings.Contains(f.Detail, "Secure") || !strings.Contains(f.Detail, "HttpOnly") {
		t.Errorf("cookie non protégé non détecté : %+v", f)
	}
	if f := checkCookies(nil, true); f.Status != Info || f.Weight != 0 {
		t.Errorf("sans cookie : %+v", f)
	}
}

func TestNormalizeTarget(t *testing.T) {
	u, err := NormalizeTarget("example.com")
	if err != nil || u.String() != "https://example.com" {
		t.Errorf("got %v %v", u, err)
	}
	if _, err := NormalizeTarget("ftp://example.com"); err == nil {
		t.Error("ftp devrait être refusé")
	}
}

func TestScore(t *testing.T) {
	_, g := score([]Finding{{Status: Pass, Weight: 10}, {Status: Fail, Weight: 10}})
	if g != "D" {
		t.Errorf("50 %% devrait donner D, obtenu %s", g)
	}
}

func TestHTMLReport(t *testing.T) {
	r := scanServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	})
	path := t.TempDir() + "/rapport.html"
	if err := WriteHTML(path, r); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{r.Grade, "Content-Security-Policy", "nosniff"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("le rapport ne contient pas %q", want)
		}
	}
}


func TestInvalidCertificateIsReportedNotFatal(t *testing.T) {
	// Client sans le certificat du serveur de test : la vérification échoue (autorité inconnue).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}))
	defer srv.Close()
	r, err := (&Scanner{Client: &http.Client{}}).Scan(srv.URL)
	if err != nil {
		t.Fatalf("un certificat invalide ne doit pas empêcher l'analyse : %v", err)
	}
	f := find(t, r, "Certificat valide")
	if f.Status != Fail || !strings.Contains(f.Detail, "auto-signé") {
		t.Fatalf("certificat invalide mal signalé : %+v", f)
	}
	if find(t, r, "X-Content-Type-Options").Status != Pass {
		t.Fatal("les en-têtes doivent quand même être analysés")
	}
}
