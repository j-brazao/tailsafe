"""Command line entry point."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from pathlib import Path

from tailsafe import __version__, engine
from tailsafe.config import DEFAULT_CONFIG_PATH, Config, ConfigError, load_config
from tailsafe.firewall import CommandRunner, Firewall, FirewallError, get_firewall
from tailsafe.state import State, locked
from tailsafe.tailscale import TailscaleChecker

log = logging.getLogger("tailsafe")


def _build(cfg: Config, dry_run: bool) -> tuple[TailscaleChecker, Firewall]:
    return TailscaleChecker(cfg.tailscale), get_firewall(cfg.firewall, CommandRunner(dry_run=dry_run))


def _cycle(cfg: Config, checker: TailscaleChecker, firewall: Firewall, dry_run: bool) -> int:
    with locked(cfg.state_file):
        state = State.load(cfg.state_file)
        try:
            engine.run_once(cfg, state, checker, firewall)
        finally:
            if not dry_run:
                state.save(cfg.state_file)
    return 0


def cmd_check(cfg: Config, args: argparse.Namespace) -> int:
    checker, firewall = _build(cfg, args.dry_run)
    return _cycle(cfg, checker, firewall, args.dry_run)


def cmd_daemon(cfg: Config, args: argparse.Namespace) -> int:
    checker, firewall = _build(cfg, args.dry_run)
    stop = threading.Event()

    def handle(signum, _frame):
        log.info("received %s, exiting (firewall left as is)", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)
    log.info("tailsafe %s started: firewall=%s interval=%ss", __version__, firewall.name, cfg.interval)
    while not stop.is_set():
        try:
            _cycle(cfg, checker, firewall, args.dry_run)
        except Exception:
            log.exception("check cycle failed")
        stop.wait(cfg.interval)
    return 0


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    checker, firewall = _build(cfg, dry_run=True)
    state = State.load(cfg.state_file)
    connected = checker.is_connected()
    print(f"tailscale:          {'connected' if connected else 'DISCONNECTED'}")
    print(f"fallback open:      {'yes' if state.opened_at else 'no'}")
    print(f"failures/successes: {state.consecutive_failures}/{state.consecutive_successes}"
          f" (thresholds {cfg.failure_threshold}/{cfg.recovery_threshold})")
    print(f"firewall:           {firewall.name} ({'active' if firewall.is_active() else 'inactive'})")
    managed = sorted(firewall.managed_rules())
    print(f"managed rules:      {len(managed)}")
    for rule in managed:
        print(f"  allow {rule.proto}/{rule.port} from {rule.source}  [{rule.tag}]")
    return 0


def cmd_plan(cfg: Config, args: argparse.Namespace) -> int:
    _checker, firewall = _build(cfg, dry_run=True)
    plan = engine.plan_open(cfg, firewall.list_rules())
    print("Changes if tailscale goes down:")
    for rule in plan.add:
        print(f"  + allow {rule.proto}/{rule.port} from {rule.source}  [{rule.tag}]")
    for rule in plan.delete:
        print(f"  - allow {rule.proto}/{rule.port} from {rule.source}  [{rule.tag}]")
    for rule in plan.covered:
        print(f"  = {rule.source}  [{rule.tag}] already allowed by an existing rule")
    if plan.empty and not plan.covered:
        print("  (none)")
    return 0


def cmd_restore(cfg: Config, args: argparse.Namespace) -> int:
    _checker, firewall = _build(cfg, args.dry_run)
    with locked(cfg.state_file):
        plan = engine.plan_restore(firewall.list_rules())
        engine.apply(firewall, plan)
        if not args.dry_run:
            state = State.load(cfg.state_file)
            state.opened_at = None
            state.save(cfg.state_file)
    print(f"removed {len(plan.delete)} rule(s)")
    return 0


COMMANDS = {
    "check": (cmd_check, "run a single check and reconcile the firewall (for cron)"),
    "daemon": (cmd_daemon, "check continuously (for a systemd service)"),
    "status": (cmd_status, "show tailscale, state and managed firewall rules"),
    "plan": (cmd_plan, "show the rules that would be added if tailscale went down"),
    "restore": (cmd_restore, "remove all tailsafe rules now, restoring the original firewall"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tailsafe",
        description="Open inbound SSH in the firewall when Tailscale is down; restore it when Tailscale is back.",
    )
    parser.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("-n", "--dry-run", action="store_true", help="log firewall changes instead of applying them")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, (_func, help_text) in COMMANDS.items():
        sub.add_parser(name, help=help_text)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        cfg = load_config(args.config)
        return COMMANDS[args.command][0](cfg, args)
    except (ConfigError, FirewallError, RuntimeError) as exc:
        log.error("%s", exc)
        return 1
