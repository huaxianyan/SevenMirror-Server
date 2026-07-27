package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: notification-mirroring-admin <command>")
		fmt.Fprintln(flag.CommandLine.Output(), "")
		fmt.Fprintln(flag.CommandLine.Output(), "Commands will be added after the private-pairing ADR is accepted.")
	}
	flag.Parse()
	flag.Usage()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", flag.Arg(0))
		os.Exit(2)
	}
}
