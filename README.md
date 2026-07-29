# sudoerslint

Flag dangerous rules in sudoers files. `visudo -c` tells you a file *parses*; it
does not tell you the rule you just added lets a user become root.

sudoerslint is a single Python file with no dependencies. It reads files only,
resolves `Cmnd_Alias` definitions, and exits non-zero on any HIGH or CRITICAL
finding — so it works as a pre-commit hook on the sudoers you keep in config
management.

## What it catches

- **`NOPASSWD: ALL`** — passwordless full root. CRITICAL.
- **A grant to a shell-escape binary** — the subtle one. Being allowed to run
  `sudo vim` (or `less`, `find`, `tar`, `awk`, `python`, `systemctl`,
  `journalctl`, `git`, `docker`, …) is being allowed to run `sudo` *anything*,
  because every one of those can spawn a shell. sudoerslint knows the
  GTFOBins-style breakouts and flags them — HIGH when `NOPASSWD`, MEDIUM when a
  password is still required (the user has it anyway).
- **`Defaults !authenticate`** and **`Defaults !env_reset`** — disabling the
  password prompt or keeping the caller's environment.
- **`env_keep`** entries that preserve `LD_PRELOAD`, `LD_LIBRARY_PATH`,
  `PYTHONPATH`, `PATH`, … — a classic way to hijack a privileged process.
- **Wildcards in a command path** (`/bin/cat /var/log/*`) — routinely abused to
  run unintended commands.

It resolves `Cmnd_Alias`, so a rule that grants an alias is checked against the
commands the alias expands to. `root`'s own `ALL` rule is not flagged, and an
unknown binary is not treated as a shell escape — so the output stays signal.

## Usage

```sh
sudoerslint /etc/sudoers
sudoerslint /etc/sudoers.d/*
```

Example:

```
$ sudoerslint /etc/sudoers.d/ops
  CRITICAL ops:3: deploy: passwordless full sudo (NOPASSWD: ALL) - complete root access, no password
  HIGH     ops:5: backup: NOPASSWD sudo to 'tar' allows a shell escape (--checkpoint-action=exec) = root shell
  HIGH     ops:1: Defaults !authenticate disables the sudo password prompt
```

## Caveat

The shell-escape list is a curated, GTFOBins-informed subset, not exhaustive —
absence of a finding is not proof a rule is safe, and a legitimate rule can still
be flagged (a backup job may genuinely need `sudo tar`). Read each finding and
decide; combine it with `visudo -c` for syntax.

## Tests

```sh
./tests/run.sh
```

Builds throwaway sudoers fixtures in a temp dir, asserts the findings — including
the guards that keep `root` and unknown binaries quiet — and cleans up.

## License

MIT. See `LICENSE`.
