// Command ocd is the OneCloud CLI for tenant members.
package main

import (
	"os"

	"github.com/ldc-dz/onecloud-cli/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
