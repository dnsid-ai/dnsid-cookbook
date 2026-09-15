package main

import (
	"os"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
