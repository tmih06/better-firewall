// Package cli implements the bfw command line: the full ufw grammar plus
// better-firewall extensions. Output conventions mirror ufw exactly:
//
//	ERROR: <msg>   → stderr, exit 1
//	syntax error   → full help to stdout, exit 1
//	WARN: <msg>    → stderr, continue
//	results + non-error outcomes (Skipping…, Aborted, Could not delete
//	non-existent rule) → stdout, exit 0
//	prompts        → stdout, accept y/yes
package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/tmih06/better-firewall/internal/backend"
	nftbe "github.com/tmih06/better-firewall/internal/backend/nft"
	"github.com/tmih06/better-firewall/internal/store"
)

// Env carries the process environment a command needs.
type Env struct {
	Prog    string // argv[0] basename ("bfw" or "ufw")
	Version string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Store   *store.Store
	Backend backend.Backend

	DryRun bool
	Force  bool
	JSON   bool
}

// newBackend is the backend constructor; tests may replace it.
var newBackend = nftbe.New

// backend lazily initializes e.Backend.
func (e *Env) backend() (backend.Backend, error) {
	if e.Backend == nil {
		b, err := newBackend()
		if err != nil {
			return nil, err
		}
		e.Backend = b
	}
	return e.Backend, nil
}

// Errorf prints "ERROR: ..." to stderr and returns exit code 1.
func (e *Env) Errorf(format string, args ...any) int {
	fmt.Fprintf(e.Stderr, "ERROR: "+format+"\n", args...)
	return 1
}

// Warnf prints "WARN: ..." to stderr and continues.
func (e *Env) Warnf(format string, args ...any) {
	fmt.Fprintf(e.Stderr, "WARN: "+format+"\n", args...)
}

// Msg prints a result line to stdout.
func (e *Env) Msg(format string, args ...any) {
	fmt.Fprintf(e.Stdout, format+"\n", args...)
}

// Prompt asks on stdout, reads a line, returns true for y/yes.
func (e *Env) Prompt(format string, args ...any) bool {
	fmt.Fprintf(e.Stdout, format, args...)
	r := bufio.NewReader(e.Stdin)
	line, _ := r.ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

// Run parses global flags and dispatches. Returns the process exit code.
func Run(prog, version string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	env := &Env{Prog: prog, Version: version, Stdin: stdin, Stdout: stdout, Stderr: stderr}
	env.Store = store.Default()
	_ = env.Store.EnsureDefaults() // materialize bundled profiles+config; best-effort

	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			env.DryRun = true
		case "--force", "-f":
			env.Force = true
		case "--json":
			env.JSON = true
		case "--version":
			env.Msg("%s %s", prog, version)
			env.Msg("Copyright 2026 better-firewall authors")
			return 0
		case "-h", "--help":
			env.Msg("%s", HelpText(prog))
			return 0
		default:
			rest = append(rest, args[i])
		}
	}

	if len(rest) == 0 {
		env.Msg("%s", HelpText(prog))
		return 1
	}
	return env.dispatch(rest)
}

// HelpText is the usage text (ufw-compatible shape).
func HelpText(prog string) string {
	return fmt.Sprintf(`Usage: %s COMMAND

Commands:
  enable                          enables the firewall
  disable                         disables the firewall
  default ARG                     set default policy
  logging LEVEL                   set logging to LEVEL
  allow ARGS                      add allow rule
  deny ARGS                       add deny rule
  reject ARGS                     add reject rule
  limit ARGS                      add limit rule
  delete RULE|NUM                 delete RULE
  insert NUM RULE                 insert RULE at NUM
  prepend RULE                    prepend RULE
  route RULE                      add route RULE
  status                          show firewall status
  status numbered                 show firewall status as numbered list of RULES
  status verbose                  show verbose firewall status
  show ARG                        show firewall report
  reset                           reset firewall to installation defaults
  app ARG                         application profile commands
  set ARG                         named IP set commands (better-firewall)
  nat ARG                         NAT commands (better-firewall)
  check                           sanity-check ruleset (better-firewall)
  diff                            diff stored vs live ruleset (better-firewall)
  panic                           drop all traffic (better-firewall)
  export|import|import-ufw        state import/export
  migrate OPTIONS                 import a system firewall; optionally take over
  sweep                           remove expired rules (better-firewall)
  logs                            follow firewall logs (better-firewall)
  version                         show version

Report types: raw, builtins, before-rules, user-rules, after-rules,
              logging-rules, listening, added
`, prog)
}
