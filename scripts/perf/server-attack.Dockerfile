FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Dropbear provides a real SSH password-auth endpoint for the brute-force
# jail. OpenSSH cannot run under this container's cap_drop ALL profile —
# its mandatory preauth privilege separation needs SYS_CHROOT, SETGID and
# SETUID. Dropbear authenticates without privsep chroot/setgroups, so the
# attack stays real (sshpass over the SSH protocol) without weakening the
# lab's capability isolation. Its log format is covered by the same
# "failed password" jail pattern the sshd jail uses.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends iptables nftables ufw dropbear-bin curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/dropbear \
    && printf 'labpassword\nlabpassword\n' | passwd root \
    && dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key

COPY bfw /usr/local/bin/bfw
COPY scripts/perf/server.py /usr/local/lib/bfw-perf/server.py
COPY scripts/perf/apply_rules.py /usr/local/lib/bfw-perf/apply_rules.py
COPY scripts/perf/fake_lapi.py /usr/local/lib/bfw-perf/fake_lapi.py
COPY scripts/perf/journalctl-shim.sh /usr/local/bin/journalctl
RUN chmod 0755 /usr/local/bin/bfw /usr/local/lib/bfw-perf/apply_rules.py /usr/local/bin/journalctl

EXPOSE 22 8080 8081
CMD ["python3", "/usr/local/lib/bfw-perf/server.py", "--host", "0.0.0.0", "--port", "8080", "--denied-port", "8081"]
