package main

import (
	"fmt"
	"io"
	"strings"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
)

type palette struct{ on bool }

func (p palette) c(code, s string) string {
	if !p.on {
		return s
	}
	return code + s + reset
}

func statusIcon(p palette, s Status) string {
	switch s {
	case Pass:
		return p.c(green, "✔")
	case Warn:
		return p.c(yellow, "!")
	case Fail:
		return p.c(red, "✘")
	}
	return p.c(cyan, "i")
}

func gradeColor(g string) string {
	switch g {
	case "A+", "A":
		return green
	case "B", "C":
		return yellow
	}
	return red
}

// printText affiche le rapport dans le terminal.
func printText(w io.Writer, r *Result, color bool) {
	p := palette{on: color}

	fmt.Fprintf(w, "\n%s %s\n", p.c(bold, "headscan →"), r.FinalURL)
	if len(r.Redirects) > 0 {
		fmt.Fprintf(w, "%s\n", p.c(dim, "  via "+strings.Join(append([]string{r.Target}, r.Redirects[:len(r.Redirects)-1]...), " → ")))
	}
	fmt.Fprintf(w, "%s\n", p.c(dim, fmt.Sprintf("  HTTP %d · %d ms", r.StatusCode, r.DurationMs)))

	category := ""
	for _, f := range r.Findings {
		if f.Category != category {
			category = f.Category
			fmt.Fprintf(w, "\n%s\n", p.c(bold, category))
		}
		fmt.Fprintf(w, "  %s %-28s %s\n", statusIcon(p, f.Status), f.Name, f.Detail)
		if f.Advice != "" {
			fmt.Fprintf(w, "    %s %s\n", p.c(cyan, "→"), f.Advice)
		}
	}

	fmt.Fprintf(w, "\n%s %s %s\n\n",
		p.c(bold, "Note :"),
		p.c(bold+gradeColor(r.Grade), r.Grade),
		p.c(dim, fmt.Sprintf("(%d/100)", r.Score)))
}
