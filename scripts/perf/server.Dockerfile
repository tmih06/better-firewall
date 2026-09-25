FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends iptables nftables ufw \
    && rm -rf /var/lib/apt/lists/*

COPY bfw /usr/local/bin/bfw
COPY scripts/perf/server.py /usr/local/lib/bfw-perf/server.py
COPY scripts/perf/apply_rules.py /usr/local/lib/bfw-perf/apply_rules.py
RUN chmod 0755 /usr/local/bin/bfw /usr/local/lib/bfw-perf/apply_rules.py

EXPOSE 8080 8081
CMD ["python3", "/usr/local/lib/bfw-perf/server.py", "--host", "0.0.0.0", "--port", "8080", "--denied-port", "8081"]
