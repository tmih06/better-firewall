PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR ?= $(SYSCONFDIR)/systemd/system
BFW_BIN ?= bfw

.PHONY: build install uninstall test test-integration check package clean

build:
	go build -o "$(BFW_BIN)" ./cmd/bfw

install: build
	install -Dm755 "$(BFW_BIN)" $(DESTDIR)$(SBINDIR)/bfw
	install -dm755 $(DESTDIR)$(SYSCONFDIR)/bfirewall/applications.d
	install -Dm644 packaging/bfirewall.service $(DESTDIR)$(UNITDIR)/bfirewall.service
	install -Dm644 packaging/bfirewall-sweep.service $(DESTDIR)$(UNITDIR)/bfirewall-sweep.service
	install -Dm644 packaging/bfirewall-sweep.timer $(DESTDIR)$(UNITDIR)/bfirewall-sweep.timer
ifeq ($(strip $(DESTDIR)),)
	-systemctl daemon-reload
endif

uninstall:
ifeq ($(strip $(DESTDIR)),)
	-systemctl disable bfirewall bfirewall-sweep.timer
endif
	rm -f $(DESTDIR)$(SBINDIR)/bfw
	rm -f $(DESTDIR)$(UNITDIR)/bfirewall.service $(DESTDIR)$(UNITDIR)/bfirewall-sweep.service $(DESTDIR)$(UNITDIR)/bfirewall-sweep.timer
ifeq ($(strip $(DESTDIR)),)
	-systemctl daemon-reload
endif

test:
	go test ./...

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
