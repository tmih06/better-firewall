#!/usr/bin/env python3
"""
High-performance asynchronous HTTP server for firewall benchmarking.
Runs inside the defended server container, serving sized HTTP payloads
on one permitted and one denied port for k6 reachability controls.

Response paths:
  /        and /small   -> 200-byte JSON body
  /medium               -> 32 KiB body
  /large                -> 256 KiB body
  anything else         -> 404 with a small JSON body
The mixed k6 profile exercises a 70/20/10 small/medium/large request mix.
"""

import argparse
import asyncio
import os
import signal
import sys


def _json_body(size: int) -> bytes:
    """Build a JSON object body of exactly `size` bytes."""
    template = b'{"status":"ok","firewall_benchmark":true,"pad":"'
    suffix = b'"}\n'
    pad_len = size - len(template) - len(suffix)
    if pad_len < 0:
        raise ValueError(f"requested body size {size} too small for JSON envelope")
    return template + (b"x" * pad_len) + suffix


def _build_response(status_line: bytes, body: bytes, content_type: bytes) -> bytes:
    return (
        b"HTTP/1.1 "
        + status_line
        + b"\r\nContent-Type: "
        + content_type
        + b"\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\nConnection: keep-alive\r\nServer: bfw-perf-server/1.0\r\n\r\n"
        + body
    )


RESPONSES = {
    b"/": _build_response(b"200 OK", _json_body(200), b"application/json"),
    b"/small": _build_response(b"200 OK", _json_body(200), b"application/json"),
    b"/medium": _build_response(b"200 OK", _json_body(32 * 1024), b"application/json"),
    b"/large": _build_response(b"200 OK", _json_body(256 * 1024), b"application/json"),
}
NOT_FOUND_RESPONSE = _build_response(
    b"404 Not Found", b'{"status":"not_found"}\n', b"application/json"
)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle HTTP requests on a keep-alive connection."""
    try:
        while not reader.at_eof():
            line = await reader.readline()
            while line in (b"\r\n", b"\n"):
                # Tolerate stray CRLF keep-alive probes between requests.
                line = await reader.readline()
            if not line:
                break

            path = b"/"
            parts = line.split(b" ", 2)
            if len(parts) >= 2:
                path = parts[1].split(b"?", 1)[0]

            # Consume request headers until the blank line terminator.
            while line and line not in (b"\r\n", b"\n"):
                line = await reader.readline()

            if not line:
                break

            writer.write(RESPONSES.get(path, NOT_FOUND_RESPONSE))
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
