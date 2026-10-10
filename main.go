// headscan analyse la configuration de sécurité HTTP d'un site web.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

var gradeOrder = []string{"F", "E", "D", "C", "B", "A", "A+"}

func gradeRank(g string) int {
	for i, x := range gradeOrder {
		if x == g {
			return i
		}
	}
	return -1
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func main() {
	timeout := flag.Duration("timeout", 10*time.Second, "délai maximum par requête")
	asJSON := flag.Bool("json", false, "afficher le résultat en JSON")
	htmlOut := flag.String("html", "", "écrire un rapport HTML dans ce fichier")
	minGrade := flag.String("min-grade", "", "code de sortie 2 si la note est inférieure (ex. B) — utile en CI")
	noColor := flag.Bool("no-color", false, "désactiver les couleurs")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage : headscan [options] <url>

Analyse les en-têtes de sécurité, les cookies et la configuration TLS d'un site.

Exemples :
  headscan example.com
  headscan -html rapport.html https://example.com
  headscan -min-grade B -json https://example.com

Options :
`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	if *minGrade != "" && gradeRank(strings.ToUpper(*minGrade)) < 0 {
		fmt.Fprintln(os.Stderr, "Erreur : -min-grade doit valoir A+, A, B, C, D, E ou F")
		os.Exit(1)
	}

	r, err := NewScanner(*timeout).Scan(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)
		printText(os.Stdout, r, color)
	}

	if *htmlOut != "" {
		if err := writeHTML(*htmlOut, r); err != nil {
			fmt.Fprintln(os.Stderr, "Erreur rapport HTML :", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Rapport HTML écrit dans %s\n", *htmlOut)
	}

	if *minGrade != "" && gradeRank(r.Grade) < gradeRank(strings.ToUpper(*minGrade)) {
		fmt.Fprintf(os.Stderr, "Note %s inférieure au minimum demandé (%s)\n", r.Grade, strings.ToUpper(*minGrade))
		os.Exit(2)
	}
}
