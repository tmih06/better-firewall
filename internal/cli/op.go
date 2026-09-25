package cli

import "github.com/tmih06/better-firewall/internal/rule"

// ParsedRuleOp is the output of the ufw rule-grammar parser: what the user
// asked to do, independent of execution.
type ParsedRuleOp struct {
	// Kind is the operation: add, delete, insert, prepend.
	Kind OpKind
	// Action is allow|deny|reject|limit (empty for delete-by-number).
	Action string
	// Rule is the parsed rule for add/insert/prepend/delete-by-text.
	Rule *rule.Rule
	// Num is the target number for `insert NUM` / `delete NUM` (0 = none).
	Num int
	// Routed marks the `route` prefix (rule.Direction == "routed").
	Routed bool
	// IPType is "v4", "v6", or "both" — inferred from address families.
	IPType string
	// Normalized is true when parsing's Normalize() changed the rule (ufw
	// warns "Rule changed after normalization" in that case).
	Normalized bool
}

// OpKind enumerates rule operations.
type OpKind int

const (
	OpAdd OpKind = iota
	OpDelete
	OpInsert
	OpPrepend
)

// ParseRuleArgs parses the full ufw rule grammar:
//
//	[rule] [route] [delete|insert NUM|prepend] ACTION [in|out [on IFACE]]
//	  [log|log-all] [proto PROTO [type TYPE]] [from ADDR [port PORT|app NAME]]
//	  [to ADDR [port PORT|app NAME]] [comment COMMENT] [expires DUR]
//	ACTION PORT[/PROTO] | ACTION APPNAME | ACTION in|out PORT[/PROTO]|APPNAME
//
// Returns an error whose text is shown via ERROR: (exit 1). A nil op with
// nil error means the args were a bare `delete NUM`.
func ParseRuleArgs(args []string) (*ParsedRuleOp, error) {
	return parseRuleArgs(args)
}
