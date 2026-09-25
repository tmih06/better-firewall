#!/usr/bin/env python3
"""
High-performance asynchronous HTTP server for firewall benchmarking.
Runs inside the defended server container, serving constant HTTP payloads
on one permitted and one denied port for k6 reachability controls.
"""

import argparse
import asyncio
import os
import signal
import sys

RESPONSE_BODY = b'{"status":"ok","firewall_benchmark":true}\n'
RESPONSE_DATA = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(RESPONSE_BODY)).encode("ascii") + b"\r\n"
    b"Connection: keep-alive\r\n"
    b"Server: bfw-perf-server/1.0\r\n"
    b"\r\n"
    + RESPONSE_BODY
)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle HTTP requests on a keep-alive connection."""
    try:
        while not reader.at_eof():
            line = await reader.readline()
            if not line:
                break

            # Read headers until end-of-headers (\r\n or \n)
            while line and line not in (b"\r\n", b"\n"):
                line = await reader.readline()

            if not line:
                break

            writer.write(RESPONSE_DATA)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    parser = argparse.ArgumentParser(description="Firewall benchmark HTTP server")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8080, help="Primary HTTP port")
    parser.add_argument("--denied-port", type=int, default=8081, help="Secondary port for negative control")
    parser.add_argument("--pid-file", default="", help="Path to write server PID")
    args = parser.parse_args()

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda _s, _f: stop_event.set())

    if args.pid_file:
        os.makedirs(os.path.dirname(os.path.abspath(args.pid_file)), exist_ok=True)
        with open(args.pid_file, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))

    servers = []
    try:
        s1 = await asyncio.start_server(handle_client, args.host, args.port, reuse_address=True)
        servers.append(s1)

        if args.denied_port and args.denied_port != args.port:
            s2 = await asyncio.start_server(handle_client, args.host, args.denied_port, reuse_address=True)
            servers.append(s2)

        sys.stdout.write(f"READY ports={args.port},{args.denied_port}\n")
        sys.stdout.flush()

        await stop_event.wait()
    finally:
        for s in servers:
            s.close()
            await s.wait_closed()
        if args.pid_file and os.path.exists(args.pid_file):
            try:
                os.remove(args.pid_file)
            except OSError:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
