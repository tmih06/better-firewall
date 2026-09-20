// `app list|info|update|default` — ufw application-profile commands.
// Profile loading/validation lives in internal/appprof; this file
// replicates frontend.py's application_* flows and backend.py's
// update_app_rule group regeneration.
package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"bfirewall/internal/appprof"
	"bfirewall/internal/rule"
	"bfirewall/internal/store"
)

var appNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 _\-\.+]*$`)

// validProfileName mirrors applications.valid_profile_name.
func validProfileName(name string) bool {
	if name == "all" || len(name) > 64 {
		return false
	}
	if _, err := strconv.Atoi(name); err == nil {
		return false
	}
	return appNameRe.MatchString(name)
}

// loadProfiles loads profiles from the store dir plus the ufw-compat
// fallback dir, warning about /etc/services collisions.
func (e *Env) loadProfiles() []*appprof.Profile {
	profiles, skipped, err := appprof.LoadAll(e.Store.AppDir(), "/etc/ufw/applications.d")
	if err != nil {
		e.Warnf("%s", err)
	}
	for _, name := range skipped {
		e.Warnf("Skipping '%s': also in /etc/services", name)
	}
	return profiles
}

// cmdApp implements `bfw app list|info <name|all>|update [--add-new]
// <name|all>|default <policy>`.
func (e *Env) cmdApp(args []string) int {
	if len(args) == 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	action := strings.ToLower(args[0])
	rest := args[1:]

	switch action {
	case "list":
		if len(rest) != 0 {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		return e.appList()
	case "info":
		if len(rest) < 1 {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		return e.appInfo(rest[0])
	case "update":
		addNew := false
		if len(rest) >= 1 && rest[0] == "--add-new" {
			addNew = true
			rest = rest[1:]
		}
		if len(rest) < 1 {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		return e.appUpdate(rest[0], addNew)
	case "default":
		if len(rest) < 1 {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		return e.appDefault(strings.ToLower(rest[0]))
	default:
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
}

// appList prints "Available applications:" + sorted names.
func (e *Env) appList() int {
	profiles := e.loadProfiles()
	names := make([]string, 0, len(profiles))
	for _, p := range profiles {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	if e.JSON {
		out, err := json.MarshalIndent(map[string]any{"applications": names}, "", "  ")
		if err != nil {
			return e.Errorf("%s", err)
		}
		e.Msg("%s", out)
		return 0
	}
	e.Msg("Available applications:")
	for _, n := range names {
		e.Msg("  %s", n)
	}
	return 0
}

// appInfo prints Profile/Title/Description/Ports for one or all
// profiles (frontend.get_application_info).
func (e *Env) appInfo(name string) int {
	profiles := e.loadProfiles()
	var selected []*appprof.Profile
	if name == "all" {
		selected = profiles
		sort.Slice(selected, func(i, j int) bool { return selected[i].Name < selected[j].Name })
	} else {
		if !validProfileName(name) {
			return e.Errorf("Invalid profile name")
		}
		for _, p := range profiles {
			if p.Name == name {
				selected = append(selected, p)
			}
		}
		if len(selected) == 0 {
			return e.Errorf("Could not find profile '%s'", name)
		}
	}

	var b strings.Builder
	for i, p := range selected {
		if p.Title == "" || p.Description == "" || len(p.Expand()) == 0 {
			return e.Errorf("Invalid profile")
		}
		fmt.Fprintf(&b, "Profile: %s\n", p.Name)
		fmt.Fprintf(&b, "Title: %s\n\n", p.Title)
		fmt.Fprintf(&b, "Description: %s\n\n", p.Description)
		specs := p.Expand()
		if len(specs) > 1 || strings.Contains(specs[0].Ports, ",") {
			b.WriteString("Ports:")
		} else {
			b.WriteString("Port:")
		}
		for _, s := range specs {
			b.WriteString("\n  " + s.Ports)
			if s.Proto != "" && s.Proto != "any" {
				b.WriteString("/" + s.Proto)
			}
		}
		if i != len(selected)-1 {
			b.WriteString("\n\n--\n\n")
		}
	}
	e.Msg("%s", b.String())
	return 0
}

// appUpdate regenerates stored app-rule groups from current profiles
// (backend.update_app_rule + frontend.application_update).
func (e *Env) appUpdate(name string, addNew bool) int {
	profiles := e.loadProfiles()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	markFamilies(st)

	allowReload := !hookUnderSSH()
	var rstr string
	triggerReload := false

	if name == "all" {
		names := make([]string, 0, len(profiles))
		for _, p := range profiles {
			names = append(names, p.Name)
		}
		sort.Strings(names)
		for _, n := range names {
			tmp, found := updateAppRule(st, profiles, n)
			if found {
				if tmp != "" {
					tmp += "\n"
				}
				rstr += tmp
				triggerReload = true
			}
		}
	} else {
		var found bool
		rstr, found = updateAppRule(st, profiles, name)
		if rstr != "" {
			rstr += "\n"
		}
		triggerReload = found
	}

	if triggerReload {
		if !e.DryRun {
			if err := e.Store.Save(st); err != nil {
				return e.Errorf("%s", err)
			}
		}
		conf, _ := e.Store.LoadConf()
		if conf != nil && conf.Enabled {
			if allowReload && !e.DryRun {
				etc, err := e.Store.EtcDefaults()
				if err != nil {
					return e.Errorf("%s", err)
				}
				if code := e.applyRuleset(st, etc); code != 0 {
					return code
				}
			} else {
				e.Msg("Skipped reloading firewall")
			}
		}
	}
	if rstr != "" {
		e.Msg("%s", strings.TrimRight(rstr, "\n"))
	}
	if addNew {
		return e.applicationAdd(st, name)
	}
	return 0
}

// updateAppRule regenerates every stored rule group referencing `name`
// from the current profile (backend.update_app_rule): the first rule of
// each app-tuple group is the template; the group is replaced by the
// profile's current expansion spliced at the same position. Returns the
// result string and whether any group was found.
func updateAppRule(st *store.State, profiles []*appprof.Profile, name string) (string, bool) {
	var up4, up6 []rule.Rule
	updated := false
	found := false
	lastTuple := ""

	for _, r := range combined(st) {
		if r.Dapp != name && r.Sapp != name {
			up4, up6 = appendRule(up4, up6, r)
			continue
		}
		found = true
		tupl := r.AppTuple()
		if tupl == lastTuple {
			continue // group already regenerated
		}
		tmpl := r.Clone()
		tmpl.Proto = "any"
		if tmpl.Dapp != "" {
			tmpl.Dst.Ports = nil
		}
		if tmpl.Sapp != "" {
			tmpl.Src.Ports = nil
		}
		newRules := expandAppTemplate(tmpl, profiles)
		if len(newRules) == 0 {
			// Profile vanished or invalid: keep the old rules.
			for _, rr := range combined(st) {
				if rr.AppTuple() == tupl {
					up4, up6 = appendRule(up4, up6, rr)
				}
			}
			lastTuple = tupl
			continue
		}
		for _, nr := range newRules {
			nr.ID = rule.NewID() // fresh ID per member (per-rule toggle)
			nr.Normalize()
			up4, up6 = appendRule(up4, up6, nr)
		}
		lastTuple = tupl
		updated = true
	}

	if !found {
		return "", false
	}
	st.Rules4, st.Rules6 = up4, up6
	markFamilies(st)
	if updated {
		return fmt.Sprintf("Rules updated for profile '%s'", name), true
	}
	return "", true
}

// appendRule appends a rule to the family list matching its V6 flag.
func appendRule(r4, r6 []rule.Rule, r *rule.Rule) ([]rule.Rule, []rule.Rule) {
	if r.V6() {
		return r4, append(r6, *r)
	}
	return append(r4, *r), r6
}

// expandAppTemplate regenerates the rule group for one app tuple from the
// current profiles (backend.get_app_rules_from_template): one rule per
// dapp port item, cross-product with sapp items when both are set; proto
// comes from the port item, "any" stays "any" (tcp+udp at compile).
func expandAppTemplate(tmpl *rule.Rule, profiles []*appprof.Profile) []*rule.Rule {
	var dspecs, sspecs []appprof.PortSpec
	if tmpl.Dapp != "" {
		p := appprof.Find(profiles, tmpl.Dapp)
		if p == nil {
			return nil
		}
		dspecs = p.Expand()
	}
	if tmpl.Sapp != "" {
		p := appprof.Find(profiles, tmpl.Sapp)
		if p == nil {
			return nil
		}
		sspecs = p.Expand()
	}
	return appRulesFromSpecs(tmpl, dspecs, sspecs)
}

// appRulesFromSpecs mirrors ufw backend.get_app_rules_from_template: one
// rule per dapp item; when both endpoints are profiles, cross-product
// (with the same-profile special case pairing item i↔i). The sapp item's
// proto wins; the dapp item's proto applies only when sapp's is "any".
// Empty spec list = endpoint untouched (ports already on tmpl or "any").
func appRulesFromSpecs(tmpl *rule.Rule, dspecs, sspecs []appprof.PortSpec) []*rule.Rule {
	var out []*rule.Rule
	sameProfile := tmpl.Dapp != "" && tmpl.Dapp == tmpl.Sapp

	mk := func(ds, ss appprof.PortSpec) *rule.Rule {
		nr := tmpl.Clone()
		if ds.Ports != "" {
			nr.Dst.Ports = specPorts(ds)
		}
		if ss.Ports != "" {
			nr.Src.Ports = specPorts(ss)
		}
		// sapp proto wins; inherit dapp's only when sapp's is "any".
		switch {
		case ss.Proto != "any":
			nr.Proto = ss.Proto
		case ds.Proto != "any":
			nr.Proto = ds.Proto
		default:
			nr.Proto = "any"
		}
		return nr
	}

	if len(dspecs) > 0 && len(sspecs) > 0 {
		for _, ds := range dspecs {
			if sameProfile {
				// Same profile both sides: pair item i with item i.
				out = append(out, mk(ds, ds))
				continue
			}
			for _, ss := range sspecs {
				out = append(out, mk(ds, ss))
			}
		}
	} else if len(dspecs) > 0 {
		for _, ds := range dspecs {
			out = append(out, mk(ds, appprof.PortSpec{Proto: "any"}))
		}
	} else if len(sspecs) > 0 {
		for _, ss := range sspecs {
			out = append(out, mk(appprof.PortSpec{Proto: "any"}, ss))
		}
	}
	return out
}

// specPorts parses one profile port item ("56,78:90") into PortRanges
// stamped with the item's protocol. "any" → nil (wildcard).
func specPorts(spec appprof.PortSpec) []rule.PortRange {
	if spec.Ports == "any" || spec.Ports == "" {
		return nil
	}
	prs, err := parsePortRanges(spec.Ports)
	if err != nil {
		return nil
	}
	for i := range prs {
		prs[i].Proto = spec.Proto
	}
	return prs
}

// applicationAdd implements `app update --add-new`: maps the default
// application policy to a rule action and adds the profile as a rule
// (frontend.application_add).
func (e *Env) applicationAdd(st *store.State, profile string) int {
	if profile == "all" {
		return e.Errorf("Cannot specify 'all' with '--add-new'")
	}
	var policy string
	switch st.AppPolicy {
	case "skip":
		return 0
	case "allow":
		policy = "allow"
	case "deny":
		policy = "deny"
	case "reject":
		policy = "reject"
	default:
		return e.Errorf("Unknown policy '%s'", st.AppPolicy)
	}
	r := &rule.Rule{
		Action:    policy,
		Direction: rule.DirIn,
		Proto:     "any",
		Src:       rule.AddrSpec{IP: "any"},
		Dst:       rule.AddrSpec{IP: "any"},
		Dapp:      profile,
	}
	return e.runRuleOp(&ParsedRuleOp{
		Kind:   OpAdd,
		Action: policy,
		Rule:   r,
		IPType: "both",
	})
}

// appDefault writes DEFAULT_APPLICATION_POLICY (backend.
// set_default_application_policy).
func (e *Env) appDefault(policy string) int {
	var target string
	switch policy {
	case "allow":
		target = "ACCEPT"
	case "deny":
		target = "DROP"
	case "reject":
		target = "REJECT"
	case "skip":
		target = "SKIP"
	default:
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.DryRun {
		if err := e.Store.WriteEtcDefault("DEFAULT_APPLICATION_POLICY", target); err != nil {
			return e.Errorf("%s", err)
		}
		st, err := e.Store.Load()
		if err != nil {
			return e.Errorf("%s", err)
		}
		st.AppPolicy = policy
		if err := e.Store.Save(st); err != nil {
			return e.Errorf("%s", err)
		}
	}
	e.Msg("Default application policy changed to '%s'", policy)
	return 0
}
