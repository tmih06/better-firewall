FROM debian:12-slim

# hping3: raw SYN/UDP floods; nmap: port-scan attack; python3 drives the
# legitimate-traffic and connect-flood generators. Everything runs on the
# internal-only benchmark network; NET_RAW is the only granted capability.
    && apt-get install -y --no-install-recommends hping3 nmap python3 iproute2 openssh-client sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
CMD ["sleep", "infinity"]
