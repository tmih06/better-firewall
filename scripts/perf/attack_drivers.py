#!/usr/bin/env python3
"""Attack-lab traffic drivers, run inside the attacker container.

Subcommands:
  probe <host> <port>            - single TCP connect; prints 1/0
  legit <host> <port> <secs> [n] - keep-alive HTTP requests; prints JSON stats
  connectflood <host> <port> <secs> - TCP connect() hammer; prints JSON stats

JSON stats share a schema so run_attack.sh can merge them without knowing
which driver produced them.
"""
import asyncio
import json
import socket
import sys
import time

GET = b"GET /small HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"


def probe(argv):
    try:
        socket.create_connection((argv[0], int(argv[1])), 1.5).close()
        print(1)
    except OSError:
        print(0)


async def _legit_worker(host, port, deadline, st):
    while time.monotonic() < deadline:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 2)
        except Exception:
            st["connect_fail"] += 1
            await asyncio.sleep(0.05)
            continue
        try:
            while time.monotonic() < deadline:
                t0 = time.monotonic()
                w.write(GET)
                await asyncio.wait_for(w.drain(), 2)
                data = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 2)
                if not data:
                    break
                try:
                    n = int(data.split(b"Content-Length: ")[1].split(b"\r\n")[0])
                    await asyncio.wait_for(r.readexactly(n), 2)
                except Exception:
                    pass
                st["ok"] += 1
                st["lat_ms"].append((time.monotonic() - t0) * 1000)
        except Exception:
            st["req_fail"] += 1
        finally:
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass


def _finish(st):
    lat = sorted(st.pop("lat_ms", []))
    if lat:
        st["p50_ms"] = round(lat[len(lat) // 2], 3)
        st["p95_ms"] = round(lat[min(int(len(lat) * 0.95), len(lat) - 1)], 3)
        st["max_ms"] = round(lat[-1], 3)
    st["requests"] = st.get("ok", 0) + st.get("req_fail", 0)
    print(json.dumps(st))


async def _legit(host, port, secs, conns):
    st = {"ok": 0, "req_fail": 0, "connect_fail": 0, "lat_ms": []}
    deadline = time.monotonic() + secs
    await asyncio.gather(*[_legit_worker(host, port, deadline, st) for _ in range(conns)])
    _finish(st)


async def _connect_worker(host, port, deadline, st):
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 2)
            st["ok"] += 1
            st["lat_ms"].append((time.monotonic() - t0) * 1000)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
        except Exception:
            st["connect_fail"] += 1


async def _connectflood(host, port, secs, conns):
    st = {"ok": 0, "connect_fail": 0, "lat_ms": []}
    deadline = time.monotonic() + secs
    await asyncio.gather(*[_connect_worker(host, port, deadline, st) for _ in range(conns)])
    _finish(st)


def main():
    cmd, argv = sys.argv[1], sys.argv[2:]
    if cmd == "probe":
        probe(argv)
    elif cmd == "legit":
        asyncio.run(_legit(argv[0], int(argv[1]), float(argv[2]), int(argv[3]) if len(argv) > 3 else 8))
    elif cmd == "connectflood":
        asyncio.run(_connectflood(argv[0], int(argv[1]), float(argv[2]), int(argv[3]) if len(argv) > 3 else 32))
    else:
        raise SystemExit(f"unknown driver {cmd}")


if __name__ == "__main__":
    main()
