package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tmih06/better-firewall/internal/protect"
	"github.com/tmih06/better-firewall/internal/store"
)

func (e *Env) cmdProtect(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if e.DryRun {
		return e.Errorf("protect cannot run with --dry-run")
	}
	if !e.checkRoot() {
		return 1
	}
	if err := e.Store.EnsureDefaults(); err != nil {
		return e.Errorf("%s", err)
	}
	cfg, err := protect.LoadConfig(e.Store.ProtectPath())
	if err != nil {
		return e.Errorf("%s", err)
	}
	detector, err := protect.NewDetector(cfg)
	if err != nil {
		return e.Errorf("%s", err)
	}
	pollInterval, err := cfg.CrowdSec.PollIntervalDuration()
	if err != nil {
		return e.Errorf("%s", err)
	}
	var crowdSec *protect.CrowdSecClient
	if cfg.CrowdSec.URL != "" {
		crowdSec, err = protect.NewCrowdSecClient(cfg.CrowdSec, e.Version)
		if err != nil {
			return e.Errorf("%s", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var journalDone <-chan error
	if len(cfg.Jails) > 0 {
		cmd := exec.CommandContext(ctx, "journalctl", journalctlArgs(cfg)...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return e.Errorf("starting journal reader: %s", err)
		}
		cmd.Stderr = e.Stderr
		if err := cmd.Start(); err != nil {
			return e.Errorf("starting journalctl: %s", err)
		}
		done := make(chan error, 1)
		journalDone = done
		go func() {
			scanErr := protect.ScanJournal(stdout, detector, func(ban store.ThreatBan) error {
				return e.applyThreatUpdate(protect.Update{Add: []store.ThreatBan{ban}})
			}, e.Warnf)
			waitErr := cmd.Wait()
			if scanErr != nil {
				done <- fmt.Errorf("journal reader: %w", scanErr)
				return
			}
			if waitErr != nil {
				done <- fmt.Errorf("journalctl: %w", waitErr)
				return
			}
			done <- fmt.Errorf("journalctl stream ended unexpectedly")
		}()
	}
	if crowdSec != nil {
		go e.pollCrowdSec(ctx, crowdSec, pollInterval)
	}
	e.Msg("Protection service running (jails=%d, crowdsec=%t)", len(cfg.Jails), crowdSec != nil)
	select {
	case <-ctx.Done():
		return 0
	case err := <-journalDone:
		return e.Errorf("%s", err)
	}
}

func journalctlArgs(cfg protect.Config) []string {
	args := []string{"--follow", "--lines=0", "--output=json", "--no-pager"}
	seen := map[string]bool{}
	for _, jail := range cfg.Jails {
		for _, id := range jail.Identifiers {
			if !seen[id] {
				args = append(args, "--identifier="+id)
				seen[id] = true
			}
		}
	}
	return args
}

func (e *Env) pollCrowdSec(ctx context.Context, client *protect.CrowdSecClient, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	startup := true
	var pending *protect.Update
	for {
		if pending == nil {
			response, err := client.Stream(ctx, startup)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				e.Warnf("CrowdSec stream failed: %s", err)
			} else {
				update, err := crowdSecUpdate(response, startup, time.Now())
				if err != nil {
					e.Warnf("invalid CrowdSec decision batch: %s; requesting a fresh snapshot", err)
					startup = true
				} else {
					pending = &update
				}
			}
		}
		if pending != nil {
			if ctx.Err() != nil {
				return
			}
			if err := e.applyThreatUpdate(*pending); err != nil {
				e.Warnf("could not apply CrowdSec decisions: %s; retrying the batch", err)
			} else {
				startup = false
				pending = nil
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func crowdSecUpdate(response protect.CrowdSecResponse, startup bool, now time.Time) (protect.Update, error) {
	update := protect.Update{Snapshot: startup}
	for _, decision := range response.New {
		if !strings.EqualFold(decision.Type, "ban") {
			continue
		}
		if decision.ID <= 0 {
			return protect.Update{}, fmt.Errorf("ban decision has no positive id")
		}
		address, err := crowdSecAddress(decision.Scope, decision.Value)
		if err != nil {
			return protect.Update{}, fmt.Errorf("decision %d: %w", decision.ID, err)
		}
		duration, err := time.ParseDuration(decision.Duration)
		if err != nil {
			return protect.Update{}, fmt.Errorf("decision %d has invalid duration %q", decision.ID, decision.Duration)
		}
		if duration <= 0 {
			continue
		}
		update.Add = append(update.Add, store.ThreatBan{
			Address: address, Source: "crowdsec", Reason: decision.Scenario,
			DecisionID: decision.ID, ExpiresAt: now.Add(duration).Unix(),
		})
	}
	if !startup {
		for _, decision := range response.Deleted {
			if decision.ID <= 0 {
				return protect.Update{}, fmt.Errorf("deleted decision has no positive id")
			}
			update.DeleteIDs = append(update.DeleteIDs, decision.ID)
		}
	}
	return update, nil
}

func crowdSecAddress(scope, value string) (string, error) {
	switch strings.ToLower(scope) {
	case "ip":
		if ip, err := netip.ParseAddr(value); err == nil {
			return ip.WithZone("").Unmap().String(), nil
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", fmt.Errorf("IP decision value %q is not an IP address or prefix", value)
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return "", fmt.Errorf("IP decision prefix %q is broader than IPv4", value)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		return prefix.String(), nil
	case "range":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", fmt.Errorf("range decision value %q is not a CIDR prefix", value)
		}
		return prefix.Masked().String(), nil
	default:
		return "", fmt.Errorf("unsupported decision scope %q", scope)
	}
}

func (e *Env) applyThreatUpdate(update protect.Update) error {
	release, code := e.acquireLock()
	if release == nil {
		return fmt.Errorf("could not lock firewall state (exit %d)", code)
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return err
	}
	changed, err := applyThreatUpdateToState(st, update, time.Now().Unix())
	if err != nil || !changed {
		return err
	}
	if code := e.commitState(st, "Threat-ban state updated"); code != 0 {
		return fmt.Errorf("could not commit threat-ban state (exit %d)", code)
	}
	return nil
}

func applyThreatUpdateToState(st *store.State, update protect.Update, now int64) (bool, error) {
	bans := append([]store.ThreatBan(nil), st.Bans...)
	if update.Snapshot {
		kept := bans[:0]
		for _, ban := range bans {
			if ban.Source != "crowdsec" {
				kept = append(kept, ban)
			}
		}
		bans = kept
	}
	for _, ban := range update.Add {
		if ban.ExpiresAt <= now {
			return false, fmt.Errorf("threat ban for %q is already expired", ban.Address)
		}
		address, err := canonicalBanAddress(ban.Address)
		if err != nil {
			return false, err
		}
		ban.Address = address
		if ban.Source == "crowdsec" {
			if ban.DecisionID <= 0 {
				return false, fmt.Errorf("CrowdSec ban requires a positive decision id")
			}
		} else if !strings.HasPrefix(ban.Source, "ssh:") || strings.TrimPrefix(ban.Source, "ssh:") == "" || ban.DecisionID != 0 {
			return false, fmt.Errorf("unsupported threat-ban source %q", ban.Source)
		}
		index := -1
		for i, old := range bans {
			if ban.Source == "crowdsec" && old.Source == "crowdsec" && old.DecisionID == ban.DecisionID ||
				ban.Source != "crowdsec" && old.Source == ban.Source && old.Address == ban.Address {
				index = i
				break
			}
		}
		if index < 0 {
			bans = append(bans, ban)
		} else {
			bans[index] = ban
		}
	}
	if !update.Snapshot && len(update.DeleteIDs) > 0 {
		deleted := make(map[int64]struct{}, len(update.DeleteIDs))
		for _, id := range update.DeleteIDs {
			if id <= 0 {
				return false, fmt.Errorf("deleted CrowdSec decision requires a positive id")
			}
			deleted[id] = struct{}{}
		}
		kept := bans[:0]
		for _, ban := range bans {
			if ban.Source == "crowdsec" {
				if _, ok := deleted[ban.DecisionID]; ok {
					continue
				}
			}
			kept = append(kept, ban)
		}
		bans = kept
	}
	if sameThreatBans(st.Bans, bans) {
		return false, nil
	}
	st.Bans = bans
	return true, nil
}

func canonicalBanAddress(raw string) (string, error) {
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return "", fmt.Errorf("threat-ban prefix %q is broader than IPv4", raw)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		return prefix.String(), nil
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("threat-ban address %q is invalid", raw)
	}
	return ip.WithZone("").Unmap().String(), nil
}

func sameThreatBans(a, b []store.ThreatBan) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
