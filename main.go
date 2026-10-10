// headscan analyse la configuration de sécurité HTTP d'un site web.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	timeout := flag.Duration("timeout", 10*time.Second, "délai maximum par requête")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage : headscan [options] <url>\n\nExemple : headscan example.com\n\nOptions :\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	r, err := NewScanner(*timeout).Scan(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}
	printText(os.Stdout, r, false)
}
