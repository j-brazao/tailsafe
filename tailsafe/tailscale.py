"""Tailscale connectivity check."""

from __future__ import annotations

import json
import logging
import subprocess

from tailsafe.config import TailscaleConfig

log = logging.getLogger(__name__)


class TailscaleChecker:
    def __init__(self, cfg: TailscaleConfig):
        self.cfg = cfg

    def is_connected(self) -> bool:
        try:
            proc = subprocess.run(
                [self.cfg.binary, "status", "--json"],
                capture_output=True,
                text=True,
                timeout=self.cfg.timeout,
            )
        except FileNotFoundError:
            log.warning("tailscale binary not found: %s", self.cfg.binary)
            return False
        except subprocess.TimeoutExpired:
            log.warning("tailscale status timed out after %ss", self.cfg.timeout)
            return False

        # `tailscale status` exits non-zero when stopped/logged out, but still
        # prints JSON, so parse first and only fall back to the exit code.
        try:
            status = json.loads(proc.stdout)
        except json.JSONDecodeError:
            log.warning("tailscale status returned %d: %s", proc.returncode, proc.stderr.strip())
            return False
        return self.evaluate(status)

    def evaluate(self, status: dict) -> bool:
        state = status.get("BackendState")
        if state != "Running":
            log.info("tailscale backend state is %r", state)
            return False
        if self.cfg.require_online:
            online = (status.get("Self") or {}).get("Online")
            if online is False:
                log.info("tailscale backend running but node is offline")
                return False
        return True
