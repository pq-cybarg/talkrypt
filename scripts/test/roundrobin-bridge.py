#!/usr/bin/env python3
"""Round-robin TCP relay for emulator<->real-hardware bilateral testing.

Bridges talkrypt peers that cannot reach each other directly (Android emulators
behind the AVD NAT vs. real USB-attached devices) through the Mac host that both
can reach. Each *new* inbound connection is spliced to the next backend in a
rotating pool, so N emulators and M devices form a round-robin mesh via one
listener. See docs/testing/emulator-hardware-bridge.md for the full recipe.

  python3 roundrobin-bridge.py --listen 127.0.0.1:9779 \
      --backends 127.0.0.1:19001,127.0.0.1:19002   # adb-forwarded device ports

Pure stdlib (asyncio); no deps. The rotation is deliberately connection-level
(not packet-level) so each talkrypt session is pinned to one backend for its life.
"""
import argparse
import asyncio
import itertools
import sys


def parse_hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"bad host:port {s!r}")
    return host, int(port)


class RoundRobin:
    """Connection-level round-robin selector over a fixed backend list."""

    def __init__(self, backends: list[tuple[str, int]]):
        if not backends:
            raise ValueError("need at least one backend")
        self._backends = list(backends)
        self._cycle = itertools.cycle(range(len(self._backends)))

    def next(self) -> tuple[str, int]:
        return self._backends[next(self._cycle)]


async def _splice(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def _handle(rr: RoundRobin, cin: asyncio.StreamReader, cout: asyncio.StreamWriter) -> None:
    host, port = rr.next()
    peer = cout.get_extra_info("peername")
    try:
        bin_, bout = await asyncio.open_connection(host, port)
    except OSError as e:
        print(f"bridge: backend {host}:{port} unreachable for {peer}: {e}", file=sys.stderr)
        cout.close()
        return
    print(f"bridge: {peer} <-> {host}:{port}", file=sys.stderr)
    await asyncio.gather(_splice(cin, bout), _splice(bin_, cout))


async def _main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:9779")
    ap.add_argument("--backends", required=True, help="comma-separated host:port list")
    args = ap.parse_args()

    lhost, lport = parse_hostport(args.listen)
    rr = RoundRobin([parse_hostport(b) for b in args.backends.split(",") if b.strip()])

    server = await asyncio.start_server(lambda r, w: _handle(rr, r, w), lhost, lport)
    print(f"bridge: listening {lhost}:{lport} -> round-robin {args.backends}", file=sys.stderr)
    async with server:
        await server.serve_forever()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    except KeyboardInterrupt:
        pass
