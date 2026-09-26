PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR ?= $(SYSCONFDIR)/systemd/system
BFW_BIN ?= bfw

.PHONY: build install uninstall test test-integration check benchmark-protect charts package clean

build:
	go build -o "$(BFW_BIN)" ./cmd/bfw

install: build
	install -Dm755 "$(BFW_BIN)" $(DESTDIR)$(SBINDIR)/bfw
	install -dm755 $(DESTDIR)$(SYSCONFDIR)/better-firewall/applications.d
	install -Dm644 packaging/better-firewall.service $(DESTDIR)$(UNITDIR)/better-firewall.service
	install -Dm644 packaging/better-firewall-sweep.service $(DESTDIR)$(UNITDIR)/better-firewall-sweep.service
	install -Dm644 packaging/better-firewall-sweep.timer $(DESTDIR)$(UNITDIR)/better-firewall-sweep.timer
	install -Dm644 packaging/better-firewall-protect.service $(DESTDIR)$(UNITDIR)/better-firewall-protect.service
ifeq ($(strip $(DESTDIR)),)
	-systemctl daemon-reload
endif

uninstall:
ifeq ($(strip $(DESTDIR)),)
	-systemctl disable better-firewall.service better-firewall-sweep.timer better-firewall-protect.service
endif
	rm -f $(DESTDIR)$(SBINDIR)/bfw
	rm -f $(DESTDIR)$(UNITDIR)/better-firewall.service $(DESTDIR)$(UNITDIR)/better-firewall-sweep.service $(DESTDIR)$(UNITDIR)/better-firewall-sweep.timer $(DESTDIR)$(UNITDIR)/better-firewall-protect.service
ifeq ($(strip $(DESTDIR)),)
	-systemctl daemon-reload
endif

test:
	go test ./...

charts:
	python3 scripts/charts/charts.py

benchmark-protect:
	go test ./internal/protect ./internal/backend/nft ./internal/rule -run '^$$' -bench 'Benchmark(JournalFailureDetection|CrowdSecDecisionDecode|ThreatBanSetCompile|RulesetCompile|LimitRulesetCompile|RulesetRender|LimitRulesetRender|RuleMatch1000|TupleKey1000|AppTuple1000)$$' -benchmem

# Privileged tests run only on disposable GitHub-hosted CI runners through the
# fail-closed namespace wrapper. Never run them locally; the wrapper refuses
# outside CI, and no workstation opt-in is provided.
test-integration:
	scripts/ci/isolate.sh go test -tags=integration ./tests/... ./internal/backend/nft/...

check:
	scripts/ci/check.sh

package:
	scripts/ci/package.sh

clean:
	rm -f bfw
