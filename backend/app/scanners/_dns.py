"""Tiny UDP DNS client for CNAME/A lookups (no third-party dependency).

Subdomain-takeover detection needs the CNAME target even when the A record is
missing (the dangling case), which ``socket.getaddrinfo`` cannot surface. This
builds and parses a minimal DNS query against public resolvers.
"""
from __future__ import annotations

import asyncio
import struct

_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
_TYPE = {"A": 1, "CNAME": 5}
_TYPE_NAME = {1: "A", 5: "CNAME"}


def _encode(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        label_bytes = label.encode("idna") if label else b""
        out.append(len(label_bytes))
        out += label_bytes
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("latin1"))
        offset += length
    if not jumped:
        end = offset
    return ".".join(labels), end


def _build_query(name: str, qtype: int) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + _encode(name) + struct.pack(">HH", qtype, 1)


def _parse(data: bytes) -> list[tuple[str, str]]:
    qd, an = struct.unpack(">H", data[4:6])[0], struct.unpack(">H", data[6:8])[0]
    offset = 12
    for _ in range(qd):  # skip question section
        _, offset = _read_name(data, offset)
        offset += 4
    records: list[tuple[str, str]] = []
    for _ in range(an):
        _, offset = _read_name(data, offset)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtype == _TYPE["A"] and rdlen == 4:
            records.append(("A", ".".join(str(b) for b in rdata)))
        elif rtype == _TYPE["CNAME"]:
            target, _ = _read_name(data, offset)
            records.append(("CNAME", target))
        offset += rdlen
    return records


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future):
        self.fut = fut

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc) -> None:
        if not self.fut.done():
            self.fut.set_exception(exc)


async def _query(name: str, qtype: str, resolver: str, timeout: float) -> list[tuple[str, str]]:
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _Proto(fut), remote_addr=(resolver, 53)
    )
    try:
        transport.sendto(_build_query(name, _TYPE[qtype]))
        data = await asyncio.wait_for(fut, timeout)
        return _parse(data)
    finally:
        transport.close()


async def resolve(name: str, qtype: str = "A", timeout: float = 4.0) -> list[tuple[str, str]]:
    """Return a list of (record_type, value); empty on failure/NXDOMAIN."""
    for resolver in _RESOLVERS:
        try:
            return await _query(name, qtype, resolver, timeout)
        except (asyncio.TimeoutError, OSError):
            continue
    return []


async def cname_chain(name: str) -> list[str]:
    """Return the CNAME target(s) for a name, if any."""
    records = await resolve(name, "CNAME")
    return [value for rtype, value in records if rtype == "CNAME"]
