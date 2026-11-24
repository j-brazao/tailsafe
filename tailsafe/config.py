"""Configuration loading and validation."""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/etc/tailsafe/config.toml")
DEFAULT_STATE_PATH = Path("/var/lib/tailsafe/state.json")

SOURCE_TYPES = ("cidr", "dns")
FAMILIES = ("any", "ipv4", "ipv6")
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SourceConfig:
    name: str
    type: str
    value: str
    family: str = "any"


@dataclass(frozen=True)
class TailscaleConfig:
    binary: str = "tailscale"
    timeout: float = 10.0
    # Also require the node to be reported Online by the coordination server.
    require_online: bool = True


@dataclass(frozen=True)
class FirewallConfig:
    type: str = "ufw"
    options: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Config:
    sources: tuple[SourceConfig, ...]
    tailscale: TailscaleConfig = TailscaleConfig()
    firewall: FirewallConfig = FirewallConfig()
    ssh_port: int = 22
    # Consecutive failed checks required before opening SSH.
    failure_threshold: int = 3
    # Consecutive successful checks required before restoring the firewall.
    recovery_threshold: int = 1
    # Seconds between checks in daemon mode.
    interval: float = 30.0
    state_file: Path = DEFAULT_STATE_PATH


def _require(table: dict, key: str, typ, where: str):
    if key not in table:
        raise ConfigError(f"{where}: missing required key '{key}'")
    value = table[key]
    if not isinstance(value, typ):
        raise ConfigError(f"{where}: '{key}' must be of type {typ.__name__}")
    return value


def _parse_source(raw: dict, index: int) -> SourceConfig:
    where = f"sources[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: must be a table")
    name = _require(raw, "name", str, where)
    if not _NAME_RE.match(name):
        raise ConfigError(f"{where}: name must match {_NAME_RE.pattern}")
    stype = _require(raw, "type", str, where)
    if stype not in SOURCE_TYPES:
        raise ConfigError(f"{where}: type must be one of {SOURCE_TYPES}")
    value = _require(raw, "value", str, where)
    family = raw.get("family", "any")
    if family not in FAMILIES:
        raise ConfigError(f"{where}: family must be one of {FAMILIES}")
    if stype == "cidr":
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ConfigError(f"{where}: invalid network '{value}': {exc}") from exc
    elif not value or any(c.isspace() for c in value):
        raise ConfigError(f"{where}: invalid hostname '{value}'")
    return SourceConfig(name=name, type=stype, value=value, family=family)


def parse_config(data: dict) -> Config:
    raw_sources = data.get("sources", [])
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ConfigError("at least one [[sources]] entry is required")
    sources = tuple(_parse_source(s, i) for i, s in enumerate(raw_sources))
    names = [s.name for s in sources]
    if len(set(names)) != len(names):
        raise ConfigError("source names must be unique")

    ts = data.get("tailscale", {})
    tailscale = TailscaleConfig(
        binary=str(ts.get("binary", "tailscale")),
        timeout=float(ts.get("timeout", 10.0)),
        require_online=bool(ts.get("require_online", True)),
    )

    fw = dict(data.get("firewall", {}))
    fw_type = fw.pop("type", "ufw")
    firewall = FirewallConfig(type=str(fw_type), options=fw)

    ssh = data.get("ssh", {})
    port = ssh.get("port", 22)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError("ssh.port must be an integer between 1 and 65535")

    check = data.get("check", {})
    failure_threshold = int(check.get("failure_threshold", 3))
    recovery_threshold = int(check.get("recovery_threshold", 1))
    interval = float(check.get("interval", 30.0))
    if failure_threshold < 1 or recovery_threshold < 1:
        raise ConfigError("check thresholds must be >= 1")
    if interval <= 0:
        raise ConfigError("check.interval must be > 0")

    state_file = Path(data.get("state_file", DEFAULT_STATE_PATH))

    return Config(
        sources=sources,
        tailscale=tailscale,
        firewall=firewall,
        ssh_port=port,
        failure_threshold=failure_threshold,
        recovery_threshold=recovery_threshold,
        interval=interval,
        state_file=state_file,
    )


def load_config(path: Path) -> Config:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    return parse_config(data)
