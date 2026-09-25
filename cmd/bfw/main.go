// bfw is the better-firewall command-line tool: a ufw-compatible frontend for
// nftables. When invoked as "ufw" (argv[0]), behavior is identical — it is
// a drop-in replacement.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tmih06/better-firewall/internal/cli"
)

var version = "0.1.0"

func main() {
	// argv[0] "ufw" → drop-in mode (identical behavior; only the program
	// name in help/usage text differs).
	prog := filepath.Base(os.Args[0])
	os.Exit(cli.Run(prog, version, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// keep fmt import used even before cli grows
var _ = fmt.Sprintf
