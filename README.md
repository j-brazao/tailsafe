# tailsafe

Keeps a fallback SSH path into a host whose normal access is over Tailscale.

- When Tailscale is **down** (for `failure_threshold` consecutive checks), tailsafe
  adds firewall rules allowing inbound SSH from the configured sources.
- When Tailscale is **back** (for `recovery_threshold` consecutive checks), it
  removes those rules, restoring the firewall to its original rule set.

Pure Python (3.11+), no dependencies. Must run as root to manage the firewall.

## How it works

Each check runs `tailscale status --json`. Tailscale counts as connected when
`BackendState` is `Running` (and, with `require_online`, the node is online).
A missing binary, timeout or bad output counts as disconnected.

Every rule tailsafe creates is tagged (for ufw, `comment 'tailsafe:<source>'`).
On recovery only tagged rules are deleted, so rules created by anyone else are
never touched. If an existing rule already allows SSH from a source (for example
`ufw allow 22/tcp`, or a broader network), tailsafe skips that source rather
than adding a duplicate that would later be deleted.

While SSH is open, every check reconciles the rules with the config:

- **cidr** sources become one rule each.
- **dns** sources are resolved on every check (A and/or AAAA, see `family`).
  If the address changes, the new rule is added before the old one is removed.
  If a lookup fails, the rules from the last good lookup are kept.

State (failure/success counters) lives in `/var/lib/tailsafe/state.json`.
A lock file stops a cron run and the daemon from acting at the same time.

## Install

```sh
sudo pip install .                        # installs /usr/local/bin/tailsafe
sudo install -Dm600 config.example.toml /etc/tailsafe/config.toml
sudoedit /etc/tailsafe/config.toml
sudo tailsafe plan                        # preview the rules for an outage
```

Then pick **one** of the two ways to run it:

**systemd service** (checks every `check.interval` seconds):

```sh
sudo cp packaging/tailsafe.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tailsafe
journalctl -u tailsafe -f
```

**cron** (one check per run, every minute):

```sh
sudo cp packaging/tailsafe.cron /etc/cron.d/tailsafe
```

With cron, `failure_threshold` counts cron runs: 3 means about 3 minutes.

## Commands

| Command            | Purpose                                                      |
|--------------------|--------------------------------------------------------------|
| `tailsafe check`   | One check and reconcile (used by cron)                       |
| `tailsafe daemon`  | Loop forever (used by the systemd service)                   |
| `tailsafe status`  | Tailscale state, counters, managed rules                     |
| `tailsafe plan`    | Rules that would be added/removed if Tailscale went down     |
| `tailsafe restore` | Remove all tailsafe rules now                                |

Global options: `-c/--config PATH`, `-v/--verbose`, `-n/--dry-run` (log firewall
changes instead of applying them; state is not saved in dry-run mode).

Stopping the daemon leaves the firewall as it is. If SSH is open when you stop
it, it stays open. Run `tailsafe restore` to close it.

## Firewall backends

Set `firewall.type` in the config. Supported: `ufw`.

ufw options (in `[firewall]`):

- `binary` — path to `ufw` (default `ufw`).
- `position` — `append` (default) or `prepend`. Use `prepend` if you have deny
  rules for the SSH port that would otherwise match first.

If ufw is inactive, tailsafe still adds the rules (and logs a warning). An
inactive ufw doesn't filter traffic, so SSH is reachable anyway.

### Adding a backend

1. Subclass `tailsafe.firewall.base.Firewall` and implement `is_active`,
   `list_rules`, `add_rule` and `delete_rule`. `list_rules` must return every
   inbound allow rule it can parse, with `tag` set only on rules this backend
   created, using the `TAG_PREFIX` marker (`tailsafe:`).
2. Register the class in `BACKENDS` in `tailsafe/firewall/__init__.py`.
3. Backend-specific settings arrive as `self.options` (everything in
   `[firewall]` except `type`).

## Development

```sh
python3 -m unittest discover -s tests -t .
```
