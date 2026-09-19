PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR ?= $(SYSCONFDIR)/systemd/system

.PHONY: build install uninstall test clean

build:
	go build -o bfw ./cmd/bfw

install: build
	install -Dm755 bfw $(DESTDIR)$(SBINDIR)/bfw
	install -dm755 $(DESTDIR)$(SYSCONFDIR)/bfirewall/applications.d
	install -Dm644 packaging/bfirewall.service $(DESTDIR)$(UNITDIR)/bfirewall.service
	install -Dm644 packaging/bfirewall-sweep.service $(DESTDIR)$(UNITDIR)/bfirewall-sweep.service
	install -Dm644 packaging/bfirewall-sweep.timer $(DESTDIR)$(UNITDIR)/bfirewall-sweep.timer
	-systemctl daemon-reload

uninstall:
	-systemctl disable bfirewall bfirewall-sweep.timer
	rm -f $(DESTDIR)$(SBINDIR)/bfw
	rm -f $(DESTDIR)$(UNITDIR)/bfirewall{,-sweep}.service $(DESTDIR)$(UNITDIR)/bfirewall-sweep.timer
	-systemctl daemon-reload

test:
	go test ./...

test-integration:
	go test -tags=integration ./tests/...

clean:
	rm -f bfw
