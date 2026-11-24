"""Resolve configured sources into concrete IP networks."""

from __future__ import annotations

import ipaddress
import logging
import socket

from tailsafe.config import SourceConfig

log = logging.getLogger(__name__)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ResolveError(Exception):
    pass


def _matches_family(net: Network, family: str) -> bool:
    return family == "any" or (family == "ipv4") == (net.version == 4)


def resolve_source(src: SourceConfig) -> list[Network]:
    if src.type == "cidr":
        nets = [ipaddress.ip_network(src.value, strict=False)]
    elif src.type == "dns":
        nets = _resolve_dns(src.value)
    else:
        raise ResolveError(f"unsupported source type {src.type!r}")
    nets = sorted({n for n in nets if _matches_family(n, src.family)}, key=lambda n: (n.version, n))
    if not nets:
        raise ResolveError(f"source {src.name!r} produced no {src.family} addresses")
    return nets


def _resolve_dns(host: str) -> list[Network]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ResolveError(f"DNS lookup for {host!r} failed: {exc}") from exc
    nets = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0].split("%", 1)[0]  # strip IPv6 zone id
        nets.append(ipaddress.ip_network(addr))
    return nets
