package scan

import (
	"embed"
	"html/template"
	"os"
	"strings"
)

//go:embed templates/report.html
var templateFS embed.FS

var reportTmpl = template.Must(template.New("report.html").Funcs(template.FuncMap{
	"statusClass": func(s Status) string {
		switch s {
		case Pass:
			return "pass"
		case Warn:
			return "warn"
		case Fail:
			return "fail"
		}
		return "info"
	},
	"gradeClass": func(g string) string {
		switch g {
		case "A+", "A":
			return "good"
		case "B", "C":
			return "mid"
		}
		return "bad"
	},
	"categories": func(fs []Finding) []string {
		var out []string
		for _, f := range fs {
			if len(out) == 0 || out[len(out)-1] != f.Category {
				out = append(out, f.Category)
			}
		}
		return out
	},
	"count": func(fs []Finding, s Status) int {
		n := 0
		for _, f := range fs {
			if f.Status == s {
				n++
			}
		}
		return n
	},
	"join": strings.Join,
}).ParseFS(templateFS, "templates/report.html"))

// WriteHTML génère un rapport HTML autonome (un seul fichier, sans dépendance).
func WriteHTML(path string, r *Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return reportTmpl.Execute(f, r)
}
