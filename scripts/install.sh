#!/bin/sh
set -eu

fail() {
	printf 'bfw installer: %s\n' "$*" >&2
	exit 1
}

[ "$(uname -s)" = Linux ] || fail "Linux is required"
case "$(uname -m)" in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*) fail "unsupported architecture: $(uname -m) (supported: x86_64, aarch64)" ;;
esac

version=${BFW_VERSION:-latest}
case "$version" in
	latest) ;;
	v*) case "$version" in *[!A-Za-z0-9._-]*) fail "invalid BFW_VERSION" ;; esac ;;
	*) fail "BFW_VERSION must be latest or a v-prefixed release tag" ;;
esac

root=${DESTDIR:-}
if [ -z "$root" ]; then
	[ "$(id -u)" -eq 0 ] || fail "run as root (or set DESTDIR for a staged install)"
	command -v systemctl >/dev/null 2>&1 || fail "systemd is required for this installer"
fi
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to verify the release"

release_root=${BFW_RELEASE_BASE:-https://github.com/tmih06/bfirewall/releases}
if [ "$version" = latest ]; then
	release_url="$release_root/latest/download"
else
	release_url="$release_root/download/$version"
fi
asset="better-firewall-linux-$arch.tar.gz"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/bfw-install.XXXXXX")
trap 'rm -rf "$tmp"' 0 HUP INT TERM

fetch() {
	url=$1
	dest=$2
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url" -o "$dest"
	elif command -v wget >/dev/null 2>&1; then
		wget -q "$url" -O "$dest"
	else
		fail "curl or wget is required to download the release"
	fi
}

fetch "$release_url/$asset" "$tmp/$asset" || fail "could not download $asset from $release_url"
fetch "$release_url/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download release checksums"
grep -E "^[[:xdigit:]]{64}  $asset\$" "$tmp/SHA256SUMS" > "$tmp/selected.SHA256SUMS" || fail "release checksum missing for $asset"
(cd "$tmp" && sha256sum -c selected.SHA256SUMS) || fail "release checksum verification failed"

tar -tzf "$tmp/$asset" > "$tmp/members" || fail "release bundle is not a valid tar archive"
while IFS= read -r member; do
	case "$member" in
		bfw|packaging/|packaging/better-firewall.service|packaging/better-firewall-sweep.service|packaging/better-firewall-sweep.timer) ;;
		*) fail "unexpected path in release bundle: $member" ;;
	esac
done < "$tmp/members"
for member in bfw packaging/better-firewall.service packaging/better-firewall-sweep.service packaging/better-firewall-sweep.timer; do
	grep -Fxq "$member" "$tmp/members" || fail "release bundle is missing $member"
done
tar -xOzf "$tmp/$asset" bfw > "$tmp/bfw" || fail "could not extract bfw"
tar -xOzf "$tmp/$asset" packaging/better-firewall.service > "$tmp/better-firewall.service" || fail "could not extract service unit"
tar -xOzf "$tmp/$asset" packaging/better-firewall-sweep.service > "$tmp/better-firewall-sweep.service" || fail "could not extract sweep service"
tar -xOzf "$tmp/$asset" packaging/better-firewall-sweep.timer > "$tmp/better-firewall-sweep.timer" || fail "could not extract sweep timer"

install -d -m 0755 "$root/usr/sbin" \
	"$root/etc/systemd/system" \
	"$root/etc/better-firewall/applications.d"
install -m 0755 "$tmp/bfw" "$root/usr/sbin/.bfw.$$"
mv -f "$root/usr/sbin/.bfw.$$" "$root/usr/sbin/bfw"
install -m 0644 "$tmp/better-firewall.service" "$root/etc/systemd/system/better-firewall.service"
install -m 0644 "$tmp/better-firewall-sweep.service" "$root/etc/systemd/system/better-firewall-sweep.service"
install -m 0644 "$tmp/better-firewall-sweep.timer" "$root/etc/systemd/system/better-firewall-sweep.timer"

if [ -z "$root" ]; then
	systemctl daemon-reload
fi
printf 'Installed bfw (%s, linux/%s). Existing firewall services were not changed.\n' "$version" "$arch"
printf 'Review migration with: sudo bfw --dry-run migrate --from auto --replace\n'
