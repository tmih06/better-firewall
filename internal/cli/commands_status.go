// `status [verbose|numbered]` — ufw get_status parity plus --json.
package cli

import (
	"encoding/json"
	"strings"

	"bfirewall/internal/store"
)

// cmdStatus implements `bfw status [verbose|numbered]`.
func (e *Env) cmdStatus(args []string) int {
	verbose := false
	numbered := false
	for _, a := range args {
		switch a {
		case "verbose":
			verbose = true
		case "numbered":
			numbered = true
		default:
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
	}

	if e.DryRun {
		e.Msg("> Checking nftables")
		return 0
	}

	conf, err := e.Store.LoadConf()
	if err != nil {
		return e.Errorf("%s", err)
	}
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	markFamilies(st)

	active := false
	if conf.Enabled {
		b, err := e.backend()
		if err != nil {
			return e.Errorf("%s", err)
		}
		loaded, err := b.Loaded()
		if err != nil {
			return e.Errorf("problem running nftables: %s", err)
		}
		active = loaded
	}

	if !active {
		if e.JSON {
			return e.statusJSON(st, false, numbered)
		}
		e.Msg("Status: inactive")
		return 0
	}

	if e.JSON {
		return e.statusJSON(st, true, numbered)
	}
	for _, line := range StatusLines(st, numbered, verbose) {
		e.Msg("%s", line)
	}
	return 0
}

// statusJSON emits the --json status document.
func (e *Env) statusJSON(st *store.State, active, numbered bool) int {
	type jsonRule struct {
		Num      int    `json:"num"`
		To       string `json:"to"`
		Action   string `json:"action"`
		From     string `json:"from"`
		Comment  string `json:"comment,omitempty"`
		V6       bool   `json:"v6"`
		Disabled bool   `json:"disabled,omitempty"`
	}
	doc := map[string]any{
		"status":   "inactive",
		"logging":  st.Logging,
		"profiles": st.AppPolicy,
		"default": map[string]string{
			"incoming": st.Policies.Input,
			"outgoing": st.Policies.Output,
			"routed":   st.Policies.Forward,
		},
		"rules": []jsonRule{},
	}
	if active {
		doc["status"] = "active"
	}
	seen := map[string]bool{}
	num := 1
	var rules []jsonRule
	for _, r := range combined(st) {
		if r.Dapp != "" || r.Sapp != "" {
			t := r.AppTuple()
			if seen[t] {
				continue
			}
			seen[t] = true
		}
		to, action, from, _ := RuleLine(r, false, numbered)
		rules = append(rules, jsonRule{
			Num:      num,
			To:       to,
			Action:   strings.TrimSpace(action),
			From:     from,
			Comment:  r.Comment,
			V6:       r.V6(),
			Disabled: r.Disabled,
		})
		num++
	}
	doc["rules"] = rules
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return e.Errorf("%s", err)
	}
	e.Msg("%s", out)
	return 0
}
