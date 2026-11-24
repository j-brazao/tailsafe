"""Persistent state shared between runs (cron) and across daemon restarts."""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)


@dataclass
class State:
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_check: float | None = None
    last_connected: bool | None = None
    # Time SSH fallback was opened, or None while the firewall is restored.
    opened_at: float | None = None

    @classmethod
    def load(cls, path: Path) -> State:
        try:
            data = json.loads(path.read_text())
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.warning("ignoring unreadable state file %s: %s", path, exc)
            return cls()
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2) + "\n")
        os.replace(tmp, path)

    def record(self, connected: bool) -> None:
        self.last_check = time.time()
        self.last_connected = connected
        if connected:
            self.consecutive_successes += 1
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
            self.consecutive_successes = 0


@contextlib.contextmanager
def locked(path: Path) -> Iterator[None]:
    """Exclusive lock so cron runs and a daemon never act concurrently."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.with_suffix(path.suffix + ".lock"), "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
