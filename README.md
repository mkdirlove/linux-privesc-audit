# linux-privesc-audit

A **read-only, multi-method Linux privilege-escalation auditor**. It enumerates common Linux privilege-escalation vectors and reports findings with severity, evidence, and remediation pointers — without exploiting, modifying, or escalating anything.

> **Scope:** This tool is intended strictly for **authorized security testing, CTF labs, and hardening reviews**. See the [Legal & Ethical Use](#legal--ethical-use) section before running it.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Legal & Ethical Use](#legal--ethical-use)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-line options](#command-line-options)
  - [Examples](#examples)
  - [Environment variables](#environment-variables)
- [Audit Methods](#audit-methods)
- [Output](#output)
  - [Human-readable report](#human-readable-report)
  - [JSON report](#json-report)
  - [Guided recipes](#guided-recipes)
- [Severity levels](#severity-levels)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

`linux-privesc-audit.sh` is a single-file Bash script (currently **v1.1.0**) that runs a suite of **28 independent check methods** against the local Linux host. For each check it collects *candidate* misconfigurations and prints them in a structured report.

Every finding includes:

| Field | Description |
|-------|-------------|
| **Severity** | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| **Method** | The check that produced the finding |
| **Title** | Short description of the potential issue |
| **Evidence** | The raw data that triggered the finding (sanitized, truncated to 400 chars) |
| **Remediation** | A concrete pointer to fix or verify the issue |

The tool **reports candidates, not confirmed exploits** — every finding is meant to be reviewed and validated by a human.

---

## Features

- 🔍 **28 audit methods** covering sudo, SUID/SGID, capabilities, cron, PATH hijacking, containers, kernel, credentials, systemd, SSH, and more.
- 📊 **Three output modes**: colorized human report, machine-readable JSON, and optional step-by-step *guided recipes*.
- 🎯 **Target a single method** with `--method NAME` for focused checks.
- 🔒 **Strictly read-only** — no exploitation, no file modification, no privilege escalation performed.
- 🎨 **TTY-aware**: colors auto-disable when piped, when `NO_COLOR` is set, or in `--json` mode.
- 🪶 **Minimal dependencies**: pure Bash with optional external tools (`sudo`, `getcap`, `ss`, `systemctl`, `showmount`, `getfacl`, …); missing tools are reported as notes rather than errors.
- 🧭 **Remediation-focused**: every finding carries a fix hint, and recipes reference resources such as GTFOBins and common CTF privesc notes.

---

## Legal & Ethical Use

> **⚠️ Important**
>
> - Only run this tool on systems you **own** or have **explicit, written authorization** to test.
> - The guided recipes (`--recipes`) describe exploitation steps for educational use in **labs and authorized engagements only**. The script itself never executes them.
> - Finding a weakness does not authorize exploitation. Always follow your engagement's scope and rules of engagement.
> - The authors and maintainers assume **no liability** for misuse. Unauthorized scanning or exploitation may be illegal in your jurisdiction.

---

## Requirements

- **Bash** (the script uses Bash arrays, `[[`-style features, and `declare -A`; run it with `bash`, not `sh`).
- Standard GNU/Linux userland: `find`, `stat`, `grep`, `awk`, `sed`, `id`, `hostname`, `date`.
- Some methods gracefully skip if optional tools are missing:

| Tool | Package hint | Used by |
|------|--------------|---------|
| `sudo` | `sudo` | `sudo`, `sudo_samedit`, `misc` |
| `getcap` | `libcap2-bin` | `capabilities` |
| `getfacl` | `acl` | `acls` |
| `ss` | `iproute2` | `services` |
| `systemctl` | `systemd` | `cron`, `services` |
| `showmount` | `nfs-common` | `nfs` |
| `pkexec` | `polkit` | `polkit`, `misc` |
| `atq` | `at` | `misc` |

The script sets `set -u` (fail on unset variables) but does **not** use `set -e`, so a failing method won't abort the whole audit.

---

## Installation

```bash
# Clone or copy the repository, then make the script executable
chmod +x linux-privesc-audit.sh

# Run it
./linux-privesc-audit.sh
```

No build step, no dependencies to install for the core audit.

---

## Usage

```
linux-privesc-audit v1.1.0 — multi-method Linux privilege escalation auditor (read-only)

Usage:
  ./linux-privesc-audit.sh                run all methods, human-readable report
  ./linux-privesc-audit.sh --json        emit JSON report
  ./linux-privesc-audit.sh --method NAME run one method (see --list)
  ./linux-privesc-audit.sh --recipes     after the audit, print manual exploitation recipes per finding
  ./linux-privesc-audit.sh --no-banner   suppress the startup banner
  ./linux-privesc-audit.sh --list        list method names
  ./linux-privesc-audit.sh -h|--help     this help
  ./linux-privesc-audit.sh -v|--version  version
```

### Command-line options

| Option | Description |
|--------|-------------|
| *(none)* | Run all methods and print a colorized human-readable report. |
| `--json` | Emit a single JSON document to stdout (colors and banner are disabled automatically). |
| `--method NAME` | Run only the named method (must match a name from `--list`). |
| `--recipes` | After the audit, print manual exploitation recipes matched to each finding. |
| `--no-banner` | Suppress the ASCII-art startup banner. |
| `--list` | Print the available method names, one per line, and exit. |
| `-h`, `--help` | Print usage help and exit. |
| `-v`, `--version` | Print the version string and exit. |

Unknown options produce an error on stderr and exit with status `2`.

### Examples

```bash
# Full human-readable audit
./linux-privesc-audit.sh

# Machine-readable output (great for piping into jq)
./linux-privesc-audit.sh --json | jq '.findings[] | select(.severity == "CRITICAL")'

# Focus on one method
./linux-privesc-audit.sh --method sudo

# Audit + manual recipes (labs / authorized engagements only)
./linux-privesc-audit.sh --recipes

# Clean output for logs / CI
./linux-privesc-audit.sh --no-banner --json > audit.json

# Discover available methods
./linux-privesc-audit.sh --list

# Show version / help
./linux-privesc-audit.sh -v
./linux-privesc-audit.sh --help
```

### Environment variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | When non-empty, disables all ANSI colors (also honored by `--json`). |
| `NO_BANNER` | When set to `1`, suppresses the banner (equivalent to `--no-banner`). |

---

## Audit Methods

Use `--method <name>` to run a single check. Available methods:

| # | Method | What it checks |
|---|--------|----------------|
| 1 | `sudo` | Passwordless/`ALL` sudo, GTFOBins-listed commands, wildcards, preserved env vars |
| 2 | `suid` | SUID/SGID binaries, abuse-prone binaries, SUID files outside standard paths |
| 3 | `capabilities` | Powerful file capabilities (`cap_setuid`, `cap_dac_override`, `cap_net_raw`, …) |
| 4 | `cron` | World-writable cron locations, root cron jobs calling writable scripts, systemd timers |
| 5 | `writable_paths` | Writable sensitive files, writable PATH dirs, world-writable dirs without sticky bit |
| 6 | `groups` | Risky group memberships (`docker`, `lxd`/`lxc`, `disk`, `shadow`, `adm`, …) |
| 7 | `nfs` | Permissive / `no_root_squash` NFS exports |
| 8 | `kernel` | Kernel/OS version heuristics, unprivileged user namespaces |
| 9 | `credentials` | Readable `/etc/shadow`, private SSH keys, secrets in configs, auth commands in history |
| 10 | `services` | Listening sockets, DB/cache services bound to all interfaces, exposed Docker API |
| 11 | `ld_preload` | Writable `/etc/ld.so.preload`, writable library directories |
| 12 | `misc` | Permissive umask, pending `at` jobs, readable passwd-like files, sudo/pkexec versions |
| 13 | `docker_sock` | Writable Docker/container runtime sockets, host filesystem mounted in container |
| 14 | `polkit` | `pkexec` version in PwnKit (CVE-2021-4034) range, writable polkit rules dirs |
| 15 | `sudo_samedit` | sudo version in Baron Samedit (CVE-2021-3156) range |
| 16 | `sysctl` | `core_pattern` piped dumps, `suid_dumpable`, `ptrace_scope` |
| 17 | `mounts` | User-writable mounts without `nosuid`/`noexec`, network filesystem mounts |
| 18 | `home_loot` | World-readable home dirs, readable token/key files under `/home` |
| 19 | `gecos` | Empty password fields, suspicious GECOS fields, non-root uid-0 accounts |
| 20 | `suid_shells` | Shells/interpreters with SUID/SGID bits, `/bin/sh` not root-owned |
| 21 | `path_hijack` | Relative/tilde/empty PATH entries, world-writable PATH directories |
| 22 | `systemd_units` | World-writable systemd units and drop-in overrides |
| 23 | `modprobe` | World-writable modprobe/modules-load configs, writable `install` helpers |
| 24 | `ssh_config` | Root login, password auth, empty passwords, weak host-key permissions |
| 25 | `lxd_sock` | Writable LXD/LXC unix sockets, `lxd`/`lxc` group membership |
| 26 | `acls` | Non-root ACL grants on sensitive files |
| 27 | `shell_rc` | World-writable shell startup files (global, root, and user) |
| 28 | `env_secrets` | Secret-like variables in the process environment (values redacted) |

Run `./linux-privesc-audit.sh --list` for the authoritative, current list of method names.

---

## Output

### Human-readable report

The default report prints a banner, host/user metadata, one section per method, and a severity summary:

```
  ▄▄▄▄ ▄▄ ▄▄ ▄▄▄▄  ...

linux-privesc-audit v1.1.0 — read-only audit
host: example  user: alice (uid=1000)  date: ...

== sudo misconfiguration ==
  [CRITICAL] Unrestricted sudo (ALL) granted
      evidence: (ALL : ALL) NOPASSWD: ALL
      fix: Remove ALL=(ALL) grants; use command-scoped sudoers entries

...

== summary ==
findings: 7  (duration: 3s)
  CRITICAL: 1
  HIGH: 3
  MEDIUM: 2
  LOW: 1
review each item; this tool reports candidates, not confirmed exploits.
```

### JSON report

`--json` emits a single document suitable for `jq` or ingestion by other tooling:

```json
{
  "tool": "linux-privesc-audit",
  "version": "1.1.0",
  "host": "example",
  "user": "alice",
  "uid": 1000,
  "duration_sec": 3,
  "findings": [
    {
      "severity": "CRITICAL",
      "method": "sudo",
      "title": "Unrestricted sudo (ALL) granted",
      "evidence": "(ALL : ALL) NOPASSWD: ALL",
      "remediation": "Remove ALL=(ALL) grants; use command-scoped sudoers entries"
    }
  ],
  "finding_count": 1
}
```

Notes on JSON output:

- The banner, colors, and all informational `note`/`section` lines are suppressed — only findings and metadata are emitted.
- Strings are escaped for backslashes and double quotes (`json_esc`). Evidence is already sanitized (delimiters converted to `;`, truncated to 400 chars).
- `finding_count` reflects the number of entries in `findings`.

### Guided recipes

`--recipes` appends a **manual** recipe for each finding. These are printed for reference only and are never executed by the script. They reference techniques such as GTFOBins shell escapes, docker group abuse, PwnKit, wildcard sudo injection, cron hijacking, and LPE PoC workflows — with repeated reminders to verify authorization and test only in labs.

---

## Severity levels

| Severity | Meaning |
|----------|---------|
| `CRITICAL` | Near-direct path to root/host compromise (e.g. writable docker socket, writable systemd unit, unrestricted sudo). |
| `HIGH` | Strong escalation primitive or powerful misconfiguration (e.g. dangerous groups, `cap_setuid`, writable sensitive files). |
| `MEDIUM` | Useful foothold or information disclosure (e.g. GTFOBins-listed sudo binary, secrets in configs, permissive NFS). |
| `LOW` | Hardening / defense-in-depth issue (e.g. permissive umask, `ptrace_scope=0`, weak mount options). |

The summary counts findings per severity so you can prioritize remediation.

---

## How it works

1. **Initialization** — captures `VERSION`, host/user/UID metadata, start timestamp, and color settings.
2. **Argument parsing** — supports JSON mode, a single-method filter, recipes, banner control, list/help/version.
3. **Method dispatch** — iterates the `METHODS` array, invoking `method_<name>` for each selected check. A method that returns non-zero is reported as a note and does not stop the run.
4. **Finding collection** — the `finding()` helper appends a pipe-delimited record to the `FINDINGS` array and, in human mode, prints it immediately.
5. **Reporting** — renders either the colorized human summary or the JSON document; optionally appends recipes.

All checks use read-only commands (`stat`, `find`, `grep`, `/proc`, `sudo -n -l`, etc.). The script does not write files, spawn shells for exploitation, or change system state.

---

## Limitations

- **Heuristics, not proof.** Version-based checks (kernel, sudo Samedit, polkit PwnKit) are crude and can produce false positives/negatives — distro backports are not detected. Always confirm against vendor advisories.
- **Context-dependent.** Findings depend on the user, groups, and environment the script runs under. Running as root vs. an unprivileged user yields different results.
- **Optional tooling.** Some methods silently skip when helper binaries are absent (e.g. `getcap`, `showmount`, `getfacl`).
- **Local host only.** It audits the machine it runs on; it is not a network scanner or a remote exploit framework.
- **Read-only by design.** It will not validate a finding by exploiting it — manual verification is up to the operator.
- **Bash required.** The script relies on Bash-specific features and should be invoked with `bash`/`./` rather than `sh`.

---

## Contributing

Contributions are welcome. When adding or changing a method:

- Keep all checks **read-only** — never add code that exploits or modifies the system.
- Use the `finding <severity> <method> <title> <evidence> <remediation>` helper so records stay consistent across output modes.
- Keep evidence human-readable and bounded (the helper truncates to 400 chars).
- Gracefully handle missing tools with `have <cmd>` and a `note`.
- Update the `METHODS` array and this README (including the method table) when adding a new method.
- Test both `./linux-privesc-audit.sh` and `./linux-privesc-audit.sh --json` before submitting.

---

## License

Specify your preferred license here (for example MIT, GPL-3.0, or Apache-2.0) and add the corresponding `LICENSE` file to the repository.
