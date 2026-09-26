FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Adds openssh-server over the perf server image so the attack lab can run a
# real SSH brute-force jail: sshd logs to a file, and the journalctl shim
# (mounted at runtime) re-emits those lines as journald JSON for bfw protect.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends iptables nftables ufw openssh-server curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /root/.ssh \
    && ssh-keygen -A \
    && printf 'labpassword\nlabpassword\n' | passwd root \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/; s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY bfw /usr/local/bin/bfw
COPY scripts/perf/server.py /usr/local/lib/bfw-perf/server.py
COPY scripts/perf/apply_rules.py /usr/local/lib/bfw-perf/apply_rules.py
COPY scripts/perf/fake_lapi.py /usr/local/lib/bfw-perf/fake_lapi.py
COPY scripts/perf/journalctl-shim.sh /usr/local/bin/journalctl
RUN chmod 0755 /usr/local/bin/bfw /usr/local/lib/bfw-perf/apply_rules.py /usr/local/bin/journalctl

EXPOSE 22 8080 8081
CMD ["python3", "/usr/local/lib/bfw-perf/server.py", "--host", "0.0.0.0", "--port", "8080", "--denied-port", "8081"]
