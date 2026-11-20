#!/usr/bin/env bash
#
# linux-privesc-audit — multi-method Linux privilege escalation AUDITOR.
#
# Read-only. Enumerates common privilege-escalation vectors and reports
# findings with severity, evidence, and remediation pointers. It does NOT
# exploit, modify, or escalate anything. Intended for authorized security
# testing, CTF labs, and hardening reviews.
#
# Usage:
#   ./linux-privesc-audit.sh                # human-readable report
#   ./linux-privesc-audit.sh --json         # machine-readable JSON report
#   ./linux-privesc-audit.sh --method sudo  # run a single method
#   ./linux-privesc-audit.sh --list         # list available methods
#
set -u

VERSION="1.1.0"
FINDINGS=()          # collected finding records (pipe-delimited)
FINDINGS_COUNT=0
JSON_OUT=0
ONLY_METHOD=""
RECIPES=0
START_TS=$(date +%s)
USER_NAME=$(id -un)
UID_NUM=$(id -u)
HOST_NAME=$(hostname 2>/dev/null)

# ---------------------------------------------------------------------------
# colors (auto-disabled when not a tty, when NO_COLOR is set, or in --json mode)
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_BRED=$'\033[1;31m'
  C_YELLOW=$'\033[33m'
  C_GREEN=$'\033[32m'
  C_CYAN=$'\033[36m'
  C_MAGENTA=$'\033[35m'
else
  C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_BRED='' C_YELLOW='' C_GREEN='' C_CYAN='' C_MAGENTA=''
fi

sev_color() {
  case "$1" in
    CRITICAL) printf '%s' "$C_BRED" ;;
    HIGH)     printf '%s' "$C_RED" ;;
    MEDIUM)   printf '%s' "$C_YELLOW" ;;
    LOW)      printf '%s' "$C_CYAN" ;;
    *)        printf '%s' "$C_RESET" ;;
  esac
}

print_banner() {
  [ "${NO_BANNER:-0}" = "1" ] && return
  local g1=$'\033[38;5;51m' g2=$'\033[38;5;45m' g3=$'\033[38;5;39m' \
        g4=$'\033[38;5;99m' g5=$'\033[38;5;135m' r="$C_RESET" b="$C_BOLD"
  if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then g1=''; g2=''; g3=''; g4=''; g5=''; fi
  printf '\n'
  printf '%s  ▄▄▄▄ ▄▄ ▄▄ ▄▄▄▄  ▄▄ ▄▄  ▄▄ ▄▄▄▄▄▄   ▄▄▄▄   ▄▄▄  ▄▄ ▄▄ ▄▄▄▄▄ %s\n' "$g1" "$r"
  printf '%s ██▀▀▀ ▀███▀ ██▄██ ██ ███▄██   ██     ██▄██ ██▀██ ▀███▀   ▄█▀ %s\n' "$g2" "$r"
  printf '%s ▀████   █   ██▄█▀ ██ ██ ▀██   ██     ██▄█▀ ▀███▀   █   ▄██▄▄ %s\n' "$g3" "$r"
  printf '\n'
  printf '%s  [Alex]%s  -  %s[Syd]%s  -  %s[KaitoX]%s  -  %s[Kuneh0]%s  -  %s[MR.$UD0]%s\n' \
    "$b$g4" "$r" "$b$g3" "$r" "$b$g5" "$r" "$b$g2" "$r" "$b$g1" "$r"
  printf '\n'
}

# ---------------------------------------------------------------------------
# reporting & string helpers
# ---------------------------------------------------------------------------

# finding <severity> <method> <title> <evidence> <remediation>
finding() {
  local sev="$1" method="$2" title="$3" evidence="$4" remediation="$5"
  # pure-bash sanitize: delimiters -> ';', truncate to 400 chars
  evidence="${evidence//|/;}"
  evidence="${evidence//$'\n'/;}"
  evidence=${evidence:0:400}
  FINDINGS+=("${sev}|${method}|${title}|${evidence}|${remediation}")
  FINDINGS_COUNT=$((FINDINGS_COUNT + 1))
  if [ "$JSON_OUT" -eq 0 ]; then
    printf '  [%s%s%s] %s\n      %sevidence:%s %s\n      %sfix:%s %s\n' \
      "$(sev_color "$sev")" "$sev" "$C_RESET" "$title" \
      "$C_DIM" "$C_RESET" "$evidence" \
      "$C_DIM" "$C_RESET" "$remediation"
  fi
}

note()    { [ "$JSON_OUT" -eq 0 ] && printf '      %s- %s%s\n' "$C_DIM" "$*" "$C_RESET"; }
section() { [ "$JSON_OUT" -eq 0 ] && printf '\n%s%s== %s ==%s\n' "$C_BOLD" "$C_CYAN" "$*" "$C_RESET"; }

have() { command -v "$1" >/dev/null 2>&1; }

# collapse newline-separated stdin into a ';'-joined single line (pure bash)
join_lines() {
  local line out=()
  while IFS= read -r line; do [ -n "$line" ] && out+=("$line"); done
  local IFS=';'
  printf '%s' "${out[*]}"
}

# count non-empty lines from stdin
count_nonempty() { grep -c . || true; }

# world-writable check following symlinks (symlink mode is always 777 and must not count)
ww_file() { [ -f "$1" ] && [ $(( 8#$(stat -L -c %a "$1" 2>/dev/null || echo 0) & 2 )) -ne 0 ]; }
ww_dir()  { [ -d "$1" ] && [ $(( 8#$(stat -L -c %a "$1" 2>/dev/null || echo 0) & 2 )) -ne 0 ]; }

# check special permission bits without forking find: has_special_perm <file> <mask>
has_special_perm() {
  [ -e "$1" ] || return 1
  [ $(( 8#$(stat -L -c %a "$1" 2>/dev/null || echo 0) & $2 )) -ne 0 ]
}

# minimal JSON string escaping
json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r//g'; }

# shared GTFOBins-style binary list
GTFO_BINARIES='vim vi nano less more man awk find nmap env python python2 python3 perl ruby lua tclsh node php tar cp mv chmod chown dd tee tcpdump file ftp rsync git ssh wget curl apt yum pip pip3 gem'
GTFO_BINARIES_SUID="$GTFO_BINARIES bash dash sh (s|nc)at service systemctl journalctl"

# ---------------------------------------------------------------------------
# method: sudo
# ---------------------------------------------------------------------------
method_sudo() {
  section "sudo misconfiguration"
  if ! have sudo; then note "sudo not installed"; return; fi

  local out
  out=$(sudo -n -l 2>&1)
  if printf '%s' "$out" | grep -qE 'not allowed|Sorry|may not run|password is required'; then
    note "passwordless sudo not available (or requires password)"
    return
  fi

  if printf '%s' "$out" | grep -qE 'NOPASSWD'; then
    finding HIGH "sudo" "Passwordless sudo entries present" \
      "$(printf '%s' "$out" | grep NOPASSWD | head -3 | join_lines)" \
      "Review sudoers; restrict NOPASSWD to least-privilege commands; see GTFOBins for abuse-prone binaries"
  fi

  if printf '%s' "$out" | grep -qE '\(ALL(:ALL)?\)\s*(NOPASSWD:)?\s*ALL'; then
    finding CRITICAL "sudo" "Unrestricted sudo (ALL) granted" \
      "$(printf '%s' "$out" | grep -E '\(ALL' | head -3 | join_lines)" \
      "Remove ALL=(ALL) grants; use command-scoped sudoers entries"
  fi

  local b
  for b in $GTFO_BINARIES; do
    if printf '%s' "$out" | grep -qE "(^|[/ ])${b}([ ,]|$)"; then
      finding MEDIUM "sudo" "Sudo rule allows GTFOBins-listed binary: $b" \
        "sudo -l output contains '$b'" \
        "Check https://gtfobins.github.io/gtfobins/$b/ for shell-escape vectors; drop or wrap the rule"
    fi
  done

  # wildcard rules are fnmatch-injectable
  if printf '%s' "$out" | grep -qE '\*'; then
    finding HIGH "sudo" "Wildcard in sudo rule (fnmatch injection risk)" \
      "$(printf '%s' "$out" | grep '\*' | head -3 | join_lines)" \
      "Remove '*' from sudoers commands or anchor with exact arguments; sudo fnmatch(3) matches across spaces"
  fi

  # env_keep / LD_PRELOAD style preserved environment
  if printf '%s' "$out" | grep -qiE 'env_keep|LD_PRELOAD|LD_LIBRARY_PATH|SETENV'; then
    finding HIGH "sudo" "Sudo preserves dangerous environment variables" \
      "$(printf '%s' "$out" | grep -iE 'env_keep|LD_PRELOAD|SETENV' | head -3 | join_lines)" \
      "Remove env_keep/SETENV for LD_* and PATH; set 'Defaults env_reset'"
  fi
}

# ---------------------------------------------------------------------------
# method: suid
# ---------------------------------------------------------------------------
method_suid() {
  section "SUID/SGID binaries"
  local found
  found=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
  local count
  count=$(printf '%s\n' "$found" | count_nonempty)
  note "$count SUID/SGID files found (non-mount-crossing)"

  local b hits
  for b in $GTFO_BINARIES_SUID; do
    hits=$(printf '%s\n' "$found" | grep -E "/(usr/)?(s?bin/)?[^/]*${b}$" | head -2)
    [ -n "$hits" ] && finding MEDIUM "suid" "SUID/SGID abuse-prone binary: $b" \
      "$(printf '%s' "$hits" | join_lines)" \
      "Remove the SUID/SGID bit if unneeded (chmod u-s/g-s); consult GTFOBins"
  done

  # unusual SUID outside standard directories
  local unusual
  unusual=$(printf '%s\n' "$found" | grep -vE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec|lib)/' | head -5)
  [ -n "$unusual" ] && finding MEDIUM "suid" "SUID/SGID files outside standard paths" \
    "$(printf '%s' "$unusual" | join_lines)" \
    "Audit each file; third-party SUID binaries are prime tamper targets"
}

# ---------------------------------------------------------------------------
# method: capabilities
# ---------------------------------------------------------------------------
method_capabilities() {
  section "file capabilities"
  if ! have getcap; then note "getcap not installed (libcap2-bin)"; return; fi
  local caps
  caps=$(getcap -r / 2>/dev/null | grep -vE '^\s*$')
  note "$(printf '%s\n' "$caps" | count_nonempty) capability entries found"
  if printf '%s\n' "$caps" | grep -qE 'cap_(setuid|dac_override|dac_read_search|sys_admin|sys_ptrace|net_raw|chown|fowner|mknod)'; then
    finding HIGH "capabilities" "Powerful file capabilities set" \
      "$(printf '%s\n' "$caps" | grep -E 'cap_(setuid|dac_override|dac_read_search|sys_admin|sys_ptrace)' | head -3 | join_lines)" \
      "Drop with setcap -r; cap_setuid on interpreters (python, perl, node) is effectively root"
  fi
  if printf '%s\n' "$caps" | grep -qE 'cap_net_raw'; then
    finding LOW "capabilities" "cap_net_raw present (packet capture possible)" \
      "$(printf '%s\n' "$caps" | grep cap_net_raw | head -3 | join_lines)" \
      "Remove unless required; allows sniffing loopback credentials"
  fi
}

# ---------------------------------------------------------------------------
# method: cron
# ---------------------------------------------------------------------------
method_cron() {
  section "cron / systemd timers"
  local cronfiles='/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs'
  local f ww
  for f in $cronfiles; do
    [ -e "$f" ] || continue
    ww=$(find "$f" -maxdepth 1 \( -type f -o -type d \) -perm -0002 -print 2>/dev/null)
    if [ -n "$ww" ]; then
      finding CRITICAL "cron" "World-writable cron location: $f" \
        "$(printf '%s' "$ww" | join_lines)" \
        "chmod o-w and review contents; cron runs as root"
    fi
  done

  # root cron jobs calling scripts/binaries that are writable by others
  if [ -r /etc/crontab ]; then
    local lines l script
    lines=$(grep -E '^(\*|[0-9]|@)' /etc/crontab 2>/dev/null)
    while IFS= read -r l; do
      for script in $(printf '%s' "$l" | grep -oE '/[A-Za-z0-9_./-]+' | grep -vE '^/(dev|proc|sys)'); do
        if [ -e "$script" ] && [ -w "$script" ]; then
          finding HIGH "cron" "Root cron references writable path: $script" \
            "crontab line: $l" \
            "chown/chmod the target root-owned 0755; audit for hijack"
        fi
      done
    done <<< "$lines"
  fi

  note "manual review advised: grep -R 'PATH=' /etc/cron* for writable dirs"
  if have systemctl; then
    local timers
    timers=$(systemctl list-timers --all --no-legend 2>/dev/null | head -5)
    [ -n "$timers" ] && note "systemd timers present — verify each ExecStart target's permissions"
  fi
}

# ---------------------------------------------------------------------------
# method: writable_paths
# ---------------------------------------------------------------------------
method_writable_paths() {
  section "writable sensitive files & PATH hijack"
  local targets='/etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d /etc/crontab /etc/hosts /etc/ld.so.preload /root/.ssh/authorized_keys'
  local t d
  for t in $targets; do
    if [ -e "$t" ] && [ -w "$t" ]; then
      finding CRITICAL "writable_paths" "Writable sensitive file: $t" \
        "$t is writable by $USER_NAME" \
        "chown root:root && chmod 600/640 immediately; audit for tampering"
    fi
  done

  local IFS=':'
  for d in $PATH; do
    [ -d "$d" ] || continue
    if [ -w "$d" ] && ! printf '%s' "$d" | grep -qE '^(/home|/tmp|/var/tmp|/dev/shm)'; then
      finding HIGH "writable_paths" "Root-relevant PATH directory writable: $d" \
        "$d in PATH of $USER_NAME is writable" \
        "chmod 755 or remove from PATH; prefer absolute paths in root scripts"
    fi
  done
  unset IFS

  # world-writable dirs with sticky bit missing (symlink attacks)
  local ww
  ww=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -vE '^/(proc|sys|dev)' | head -5)
  [ -n "$ww" ] && finding MEDIUM "writable_paths" "World-writable dirs without sticky bit" \
    "$(printf '%s' "$ww" | join_lines)" \
    "chmod +t; prevents file-replacement/symlink attacks"
}

# ---------------------------------------------------------------------------
# method: groups
# ---------------------------------------------------------------------------
method_groups() {
  section "group membership"
  local groups
  groups=$(id -nG 2>/dev/null)
  note "groups: $groups"
  local g
  for g in $groups; do
    case "$g" in
      docker) finding CRITICAL "groups" "User in docker group" \
        "id -nG includes docker" \
        "Docker group == root-equivalent; remove user or use rootless docker + userns-remap" ;;
      lxd|lxc) finding HIGH "groups" "User in $g group (container root-equivalence)" \
        "id -nG includes $g" \
        "LXD/LXC membership allows mounting host fs as root; remove membership" ;;
      disk) finding HIGH "groups" "User in disk group (raw device read)" \
        "id -nG includes disk" \
        "disk group can read /dev/sda*; remove membership" ;;
      adm) finding MEDIUM "groups" "User in adm group (log access)" \
        "id -nG includes adm" \
        "Logs may leak credentials/tokens; restrict to trusted admins" ;;
      shadow) finding HIGH "groups" "User in shadow group (password hashes readable)" \
        "id -nG includes shadow" \
        "Shadow group can read /etc/shadow; crack offline; remove membership" ;;
      video|audio) note "$g group — generally low risk" ;;
      sudo|wheel|admin) note "$g group — sudo-capable; see sudo method" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# method: nfs
# ---------------------------------------------------------------------------
method_nfs() {
  section "NFS exports"
  if ! have showmount; then note "showmount not installed (nfs-common)"; return; fi
  local exports
  exports=$(showmount -e localhost 2>/dev/null | tail -n +2)
  [ -z "$exports" ] && exports=$(showmount -e 127.0.0.1 2>/dev/null | tail -n +2)
  if [ -z "$exports" ]; then note "no NFS exports visible on localhost"; return; fi
  if printf '%s\n' "$exports" | grep -qE '\*|0\.0\.0\.0|/24|no_root_squash'; then
    finding HIGH "nfs" "Permissive or no_root_squash NFS export" \
      "$exports" \
      "Export only to specific hosts; never combine '*' with no_root_squash; use root_squash"
  else
    note "exports found but not obviously permissive: $exports"
  fi
  if [ -r /etc/exports ] && grep -qE 'no_root_squash' /etc/exports 2>/dev/null; then
    finding HIGH "nfs" "/etc/exports contains no_root_squash" \
      "$(grep no_root_squash /etc/exports | join_lines)" \
      "Change to root_squash; no_root_squash + writable share = trivial root"
  fi
}

# ---------------------------------------------------------------------------
# method: kernel
# ---------------------------------------------------------------------------
method_kernel() {
  section "kernel / OS version"
  local krel
  krel=$(uname -r)
  note "kernel: $krel"
  note "os: $( . /etc/os-release 2>/dev/null && printf '%s %s' "${NAME:-?}" "${VERSION_ID:-?}" )"

  # crude EOL/exposure heuristics against known-bad ranges
  if printf '%s' "$krel" | grep -qE '^2\.6\.'; then
    finding HIGH "kernel" "Ancient kernel (2.6.x) — many public LPE exploits" \
      "uname -r = $krel" \
      "Upgrade kernel; audit with a CVE database (e.g. linux-exploit-suggester) for confirmation"
  elif printf '%s' "$krel" | grep -qE '^3\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13)(\.|-)'; then
    finding MEDIUM "kernel" "Kernel 3.x — check for dirtycow/overlayfs-class LPEs" \
      "uname -r = $krel" \
      "Confirm exposure with a CVE matcher; patch or backport fixes"
  elif printf '%s' "$krel" | grep -qE '^4\.[0-9](\.|-)|^4\.1[0-5]\.'; then
    finding LOW "kernel" "Kernel 4.x — some LPEs apply (overlayfs, etc.)" \
      "uname -r = $krel" \
      "Verify patch level against your distro's advisory tracker"
  fi

  if [ -r /proc/sys/kernel/unprivileged_userns_clone ] && [ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = "1" ]; then
    finding LOW "kernel" "Unprivileged user namespaces enabled" \
      "kernel.unprivileged_userns_clone = 1" \
      "Needed by some exploits (overlayfs/fuse); consider =0 if not required"
  fi
}

# ---------------------------------------------------------------------------
# method: credentials
# ---------------------------------------------------------------------------
method_credentials() {
  section "credential leakage"
  if [ -r /etc/shadow ]; then
    local owner perm
    owner=$(stat -c %U /etc/shadow 2>/dev/null); perm=$(stat -c %a /etc/shadow 2>/dev/null)
    finding HIGH "credentials" "/etc/shadow readable by current user" \
      "owner=$owner mode=$perm; user=$USER_NAME" \
      "Restrict to root:shadow 640; rotate any exposed password hashes"
  fi

  # private keys in common locations
  local k
  for k in /home/*/.ssh/id_rsa /home/*/.ssh/id_ed25519 /root/.ssh/id_rsa /etc/ssh/*_key; do
    if [ -r "$k" ]; then
      finding HIGH "credentials" "Readable private SSH key: $k" \
        "$k readable by $USER_NAME" \
        "chmod 600; investigate unauthorized access; rotate keys"
    fi
  done

  # interesting config files with secrets
  local hits
  hits=$(grep -rIl --exclude-dir={proc,sys,dev,usr,lib,share} -iE '(password|passwd|secret|api[_-]?key|token)\s*[:=]' /etc /opt /srv /var/www /home 2>/dev/null | head -10)
  [ -n "$hits" ] && finding MEDIUM "credentials" "Config files may contain secrets" \
    "$(printf '%s' "$hits" | join_lines)" \
    "Review for plaintext credentials; move to vault/secret manager; chmod 600"

  # history files with commands containing passwords
  local hh
  for hh in /home/*/.bash_history /root/.bash_history; do
    [ -r "$hh" ] || continue
    if grep -qiE '(mysql|psql|sshpass|curl.*-u|aws.*secret)' "$hh" 2>/dev/null; then
      finding MEDIUM "credentials" "Shell history may contain credentials: $hh" \
        "$hh readable; matched auth-related commands" \
        "Educate users; set HISTFILE=/dev/null or histappend off; scrub history"
    fi
  done
}

# ---------------------------------------------------------------------------
# method: services
# ---------------------------------------------------------------------------
method_services() {
  section "listening services & local exposure"
  if have ss; then
    local listen
    listen=$(ss -tulnH 2>/dev/null | head -20)
    note "listening sockets (first 20):"
    [ "$JSON_OUT" -eq 0 ] && printf '%s\n' "$listen" | sed 's/^/        /'
    # common local-only admin interfaces that shouldn't be world-reachable
    if printf '%s\n' "$listen" | grep -E ':(3306|5432|6379|27017|9200|11211|2379)\b' | grep -qE '0\.0\.0\.0|\*|::'; then
      finding MEDIUM "services" "Database/cache service bound to all interfaces" \
        "$(printf '%s\n' "$listen" | grep -E ':(3306|5432|6379|27017|9200|11211|2379)\b' | join_lines)" \
        "Bind to 127.0.0.1 or unix socket; enforce auth; firewall"
    fi
    if printf '%s\n' "$listen" | grep -qE ':(2375|2376)\b'; then
      finding CRITICAL "services" "Docker API exposed on TCP" \
        "$(printf '%s\n' "$listen" | grep -E ':(2375|2376)\b' | join_lines)" \
        "Disable TCP docker socket or require TLS client certs; exposed socket == root"
    fi
  else
    note "ss not available"
  fi

  have pgrep && note "review root processes: ps -eo user,pid,comm,args | grep ^root"
}

# ---------------------------------------------------------------------------
# method: ld_preload
# ---------------------------------------------------------------------------
method_ld_preload() {
  section "ld.so preload / shared library hijack"
  if [ -f /etc/ld.so.preload ]; then
    local preload
    preload=$(cat /etc/ld.so.preload 2>/dev/null | join_lines)
    if [ -w /etc/ld.so.preload ]; then
      finding CRITICAL "ld_preload" "/etc/ld.so.preload is writable" \
        "$preload" \
        "chmod 644 root:root; a writable preload file = arbitrary code in every process"
    else
      note "/etc/ld.so.preload exists (root-owned): $preload"
    fi
  fi
  # writable library directories
  local libdir
  for libdir in /lib /usr/lib /lib64 /usr/lib64 /usr/lib/x86_64-linux-gnu; do
    if ww_dir "$libdir"; then
      finding HIGH "ld_preload" "Writable library directory: $libdir" \
        "world-writable entries in $libdir" \
        "chmod 755; root processes load libraries from here"
    fi
  done
}

# ---------------------------------------------------------------------------
# method: misc
# ---------------------------------------------------------------------------
method_misc() {
  section "misc checks"
  local um
  um=$(umask)
  if [ "$um" = "0000" ] || [ "$um" = "0002" ]; then
    finding LOW "misc" "Permissive umask ($um)" \
      "umask $um for $USER_NAME" \
      "Set umask 022/077 in shell profiles and systemd units"
  fi
  # at / batch jobs
  if have atq; then
    local jobs
    jobs=$(atq 2>/dev/null | head -5)
    [ -n "$jobs" ] && note "pending at jobs: $jobs"
  fi
  # world-writable /etc/passwd backup or copies
  local pwbak
  pwbak=$(find /etc /root /home -maxdepth 2 -name '*passwd*' -perm -0004 -print 2>/dev/null | head -5)
  [ -n "$pwbak" ] && note "readable passwd-like files: $pwbak"
  have sudo && note "sudo version: $(sudo -V 2>/dev/null | head -1) — cross-check against advisories (Baron Samedit, etc.)"
  have pkexec && note "pkexec present: $(pkexec --version 2>/dev/null | head -1) — check polkit CVE status for your distro"
}

# ---------------------------------------------------------------------------
# guided recipes (human-in-the-loop; executes nothing)
# ---------------------------------------------------------------------------
recipe() {
  # recipe <method> <title-match-substring> <recipe-text...>
  printf '\n%s%s--- recipe: %s / %s ---%s\n' "$C_BOLD" "$C_CYAN" "$1" "$2" "$C_RESET"
  shift 2
  printf '%s\n' "$*"
}

print_recipes() {
  [ "$FINDINGS_COUNT" -eq 0 ] && { echo "no findings — nothing to guide."; return; }
  printf '\n%s%s== guided exploitation recipes (manual — verify authorization, then run steps yourself) ==%s\n' "$C_BOLD" "$C_MAGENTA" "$C_RESET"
  local f sev method title evidence remediation
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev method title evidence remediation <<< "$f"
    case "$method:$title" in
      docker_sock:*)
        recipe docker_sock writable_socket \
          "1. Confirm: ls -l /var/run/docker.sock; id | grep docker
2. Lab/authorized host only: docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
3. You are root on the host fs; grab the flag / fix the socket group.
Reference: GTFOBins docker; ctf-misc 'Docker Group Privilege Escalation'." ;;
      "gecos:*uid 0*")
        recipe gecos uid0 \
          "1. awk -F: '\$3==0 {print \$1}' /etc/passwd — list uid-0 accounts
2. For any non-root uid-0: inspect its authorized_keys, cron, and recent logins
3. In a lab, 'su <that-account>' if you hold its credential; otherwise report as persistence." ;;
      polkit:*)
        recipe polkit pwnkit \
          "1. Confirm version: pkexec --version (vulnerable <0.120 modulo distro backports)
2. In a lab VM only: CVE-2021-4034 (PwnKit) PoC if version confirmed vulnerable
3. Production fix is patching polkit — never run PoCs outside the lab." ;;
      groups:*docker*)
        recipe groups docker \
          "1. Confirm: id | grep docker
2. Lab/authorized host only: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
3. Inside: you are root on the host filesystem (read /mnt/etc/shadow, etc.)
Reference: GTFOBins docker; ctf-misc 'Docker Group Privilege Escalation'." ;;
      sudo:*NOPASSWD*|sudo:*ALL*)
        recipe sudo unrestricted \
          "1. sudo -l   (note exact allowed commands)
2. Cross-reference each binary against gtfobins.github.io
3. Run only the specific documented shell-escape for that binary, e.g. sudo vim -> :!sh
4. In labs, verify you can id && cat /root/flag*
Reference: linux-privesc.md (sudo sections) in ctf-misc." ;;
      sudo:*GTFOBins*)
        recipe sudo gtfobins \
          "1. sudo -l, pick the allowed binary
2. Open https://gtfobins.github.io/gtfobins/<binary>/#sudo
3. Apply the documented sudo invocation manually." ;;
      sudo:*Wildcard*)
        recipe sudo wildcard \
          "1. Read the exact sudoers entry with the '*'
2. Craft extra args so fnmatch(3) absorbs them (no FNM_PATHNAME — spaces match)
3. See ctf-misc linux-privesc.md 'Sudo Wildcard Parameter Injection' for a worked tcpdump example
4. Validate in a lab VM first — wildcard injection can corrupt target files." ;;
      suid:*)
        recipe suid gtfobins \
          "1. ls -l <flagged binary>  (confirm owner root + s bit)
2. Look up the binary at gtfobins.github.io (#suid section)
3. Invoke the documented SUID escape manually; e.g. find . -exec /bin/sh -p \\; -quit
4. Verify effective uid with id." ;;
      capabilities:*)
        recipe capabilities cap \
          "1. getcap <binary>  (confirm the exact capability)
2. cap_setuid on an interpreter -> run the GTFOBins cap_setuid snippet manually (e.g. python -c 'os.setuid(0);os.system(\"/bin/sh\")')
3. cap_dac_read_search -> read any file via tar/python; cap_net_raw -> sniff traffic
Reference: GTFOBins capabilities pages." ;;
      cron:*)
        recipe cron writable \
          "1. Identify the writable script/path the root cron executes
2. In a lab, append a harmless proof (id > /tmp/proof) rather than a payload first
3. Wait for the cron interval (or trigger the systemd timer) and check the result
Reference: ctf-misc 'Backup Cronjob SUID Abuse' for the classic SUID-copy pattern." ;;
      writable_paths:*ld.so.preload*|ld_preload:*)
        recipe ld_preload \
          "1. Confirm writability: ls -l /etc/ld.so.preload
2. Lab only: a malicious shared object placed here is loaded by EVERY process — never test on production
3. Prefer the hardening fix: chown root:root /etc/ld.so.preload && chmod 644" ;;
      writable_paths:*)
        recipe writable_paths \
          "1. Confirm with ls -l <path>
2. /etc/passwd writable -> append a uid-0 line ONLY in a disposable lab VM
3. PATH dir writable -> place a shadowing binary with the same name as one the root process calls unqualified
4. Always restore original permissions afterward." ;;
      nfs:*)
        recipe nfs \
          "1. showmount -e <host>
2. no_root_squash + writable export: mount locally, copy in a SUID-root binary (chmod u+s), execute on host
3. Reference: ctf-misc linux-privesc.md 'NFS Share Exploitation'." ;;
      credentials:*shadow*)
        recipe credentials shadow \
          "1. cp /etc/shadow /tmp/shadow.$$
2. john /tmp/shadow.$$ (or hashcat -m 1800) — crack offline in the lab
3. Report weak hashes; do not reuse credentials elsewhere." ;;
      kernel:*)
        recipe kernel \
          "1. Confirm exact version: uname -a; check distro backports (distro kernels often patched)
2. Use linux-exploit-suggester to list candidate LPEs — confirm each manually
3. Compile/run a specific PoC only against a lab VM running that kernel." ;;
      *)
        recipe "$method" "$title" \
          "No canned recipe for this finding. Review the evidence, consult GTFOBins/HackTricks for '$method', and verify authorization before acting." ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# method: docker_sock
# ---------------------------------------------------------------------------
method_docker_sock() {
  section "docker socket & runtime misconfiguration"
  local sock
  for sock in /var/run/docker.sock /run/docker.sock; do
    if [ -e "$sock" ]; then
      if [ -w "$sock" ]; then
        finding CRITICAL "docker_sock" "Writable docker socket: $sock" \
          "$sock writable by $USER_NAME; runtime API reachable" \
          "Root-equivalent via runtime API (run a host-mount container). Restrict socket to a docker admin group; prefer rootless docker"
      else
        note "$sock exists (not writable by $USER_NAME)"
      fi
    fi
  done
  for sock in /run/containerd/containerd.sock /run/crio/crio.sock /run/cri-dockerd.sock; do
    if [ -w "$sock" ]; then
      finding CRITICAL "docker_sock" "Writable container runtime socket: $sock" \
        "$sock writable by $USER_NAME" \
        "Runtime socket == host root. Restrict to root-only (0600) or a dedicated group"
    fi
  done
  # mounted host root inside a container?
  if grep -qE ' /host | /mnt/host | /hostroot' /proc/mounts 2>/dev/null; then
    finding HIGH "docker_sock" "Host filesystem appears mounted inside this environment" \
      "$(grep -E ' /host | /mnt/host | /hostroot' /proc/mounts | join_lines)" \
      "If this is a container, the host fs mount defeats its boundary; unmount or re-create without it"
  fi
}

# ---------------------------------------------------------------------------
# method: polkit
# ---------------------------------------------------------------------------
method_polkit() {
  section "polkit / pkexec (PwnKit-class)"
  if have pkexec; then
    local ver
    ver=$(pkexec --version 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)*' | head -1)
    note "pkexec version: ${ver:-unknown}"
    # crude heuristic only: real verification needs distro changelogs
    # handles both "pkexec version 120" (flat) and "0.105" (dotted) schemes
    if [ -n "$ver" ]; then
      local core verdict=0
      case "$ver" in
        0.*) core=${ver#0.}; core=${core%%.*} ;;
        *)   core=${ver%%.*} ;;
      esac
      case "$core" in
        ''|*[!0-9]*) : ;;                          # unparseable — stay silent
        *) [ "$core" -lt 120 ] && verdict=1 ;;     # below the PwnKit fix boundary
      esac
      if [ "$verdict" -eq 1 ]; then
        finding HIGH "polkit" "pkexec possibly older than 0.120 (PwnKit / CVE-2021-4034 range)" \
          "pkexec --version = $ver (distro backports may patch; verify against your vendor advisory)" \
          "Update polkit via distro packages (>=0.120 or backported fix); until then pkexec is high-risk"
      fi
    fi
  else
    note "pkexec not installed"
  fi
  # polkit local authority rules writable?
  local rulesdir ww
  for rulesdir in /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d; do
    ww=$(find "$rulesdir" -maxdepth 1 -perm -0002 -print 2>/dev/null)
    [ -n "$ww" ] && finding HIGH "polkit" "World-writable polkit rules directory: $rulesdir" \
      "$(printf '%s' "$ww" | join_lines)" \
      "chmod 755; polkit rules run with elevated privilege"
  done
}

# ---------------------------------------------------------------------------
# method: sudo_samedit
# ---------------------------------------------------------------------------
method_sudo_samedit() {
  section "sudo Baron Samedit heuristic (CVE-2021-3156)"
  if ! have sudo; then note "sudo not installed"; return; fi
  local ver
  ver=$(sudo -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?(p[0-9]+)?')
  note "sudo version: ${ver:-unknown}"
  case "$ver" in
    1.8.2*|1.8.3*|1.8.4*|1.8.5*|1.8.6*|1.8.7*|1.8.8*|1.8.9*|1.8.1[0-9]*|1.8.2[0-1]*|1.9.[0-4]*|1.9.5p1)
      finding MEDIUM "sudo_samedit" "sudo in a CVE-2021-3156-adjacent version range" \
        "sudo $ver (1.8.2–1.9.5p1 line) — heuristic; distro backports often patch" \
        "Check your distro advisory; upgrade sudo. Do NOT run 'sudoedit -s' tests on production" ;;
    *)
      note "version not in the naive vulnerable range (still verify distro backport status)" ;;
  esac
}

# ---------------------------------------------------------------------------
# method: sysctl
# ---------------------------------------------------------------------------
method_sysctl() {
  section "sysctl exploitation primitives"
  local core dumpable ptrace
  core=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
  if printf '%s' "$core" | grep -qE '^\|'; then
    finding MEDIUM "sysctl" "core_pattern pipes dumps to a helper program" \
      "kernel.core_pattern = $core" \
      "Piped core_pattern is a building block for some LPE chains; confirm the helper is root-owned and non-writable, or set core_pattern back to a plain path"
  fi
  dumpable=$(cat /proc/sys/fs/suid_dumpable 2>/dev/null)
  [ "$dumpable" = "1" ] && finding LOW "sysctl" "suid_dumpable = 1 (SUID processes dump core)" \
    "fs.suid_dumpable = 1" \
    "Set fs.suid_dumpable=0 (or 2 with restricted core dir); core dumps of SUID binaries leak privileged memory"
  ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
  [ "$ptrace" = "0" ] && finding LOW "sysctl" "ptrace_scope = 0 (any process may ptrace same-uid children/others)" \
    "kernel.yama.ptrace_scope = 0" \
    "Set kernel.yama.ptrace_scope = 1 unless a debugger workflow requires 0"
  if [ -w /proc/sysrq-trigger ] && [ "$(cat /proc/sys/kernel/sysrq 2>/dev/null)" != "0" ]; then
    note "sysrq enabled and /proc/sysrq-trigger writable — generally fine for root only; no finding"
  fi
}

# ---------------------------------------------------------------------------
# method: mounts
# ---------------------------------------------------------------------------
method_mounts() {
  section "mount table misconfigurations"
  # noexec/nosuid absent on user-writable mount points
  local mp line netmp
  for mp in /tmp /var/tmp /dev/shm /home /mnt /media; do
    line=$(awk -v t="$mp" '$2==t {print $2" "$4}' /proc/mounts 2>/dev/null | head -1)
    [ -z "$line" ] && continue
    case "$line" in
      *nosuid*|*noexec*) note "$line — restricted, good" ;;
      *) [ -w "$mp" ] && finding LOW "mounts" "User-writable mount without nosuid/noexec: $mp" \
           "$line" \
           "Add nosuid,nodev,noexec to mount options where workloads allow" ;;
    esac
  done
  # sensitive mounts from network filesystems that might be spoofed
  netmp=$(awk '$3 ~ /^(nfs|cifs|smbfs)$/ {print $2" "$3}' /proc/mounts 2>/dev/null)
  [ -n "$netmp" ] && finding LOW "mounts" "Network filesystem mounted locally" \
    "$(printf '%s' "$netmp" | join_lines)" \
    "Network-mounted binaries/configs may be tampered if the server is compromised; enforce nosuid and root_squash/sec=krb5"
}

# ---------------------------------------------------------------------------
# method: home_loot
# ---------------------------------------------------------------------------
method_home_loot() {
  section "world-readable home directories & token files"
  local d perm owner tok
  for d in /home/*; do
    [ -d "$d" ] || continue
    perm=$(stat -c %a "$d" 2>/dev/null); owner=$(stat -c %U "$d" 2>/dev/null)
    case "$perm" in
      *7|*5|*1)
        finding LOW "home_loot" "World-readable/executable home directory: $d" \
          "owner=$owner mode=$perm" \
          "chmod 700/750; home dirs may contain .ssh, .aws, .config tokens" ;;
    esac
    # token-like files readable inside, not owned by us
    tok=$(find "$d" -maxdepth 3 -type f \( -name '.env' -o -name 'credentials' -o -name 'settings.json' -o -name '.npmrc' -o -name '.pypirc' -o -name 'id_rsa' -o -name 'id_ed25519' \) ! -user "$UID_NUM" -readable 2>/dev/null | head -3)
    [ -n "$tok" ] && finding MEDIUM "home_loot" "Sensitive token/key files readable under $d" \
      "$(printf '%s' "$tok" | join_lines)" \
      "chmod 600 the files and 700 the dirs; rotate any exposed tokens"
  done
}

# ---------------------------------------------------------------------------
# method: gecos
# ---------------------------------------------------------------------------
method_gecos() {
  section "GECOS-field passwords & empty passwords"
  local empty suspicious uid0
  empty=$(awk -F: '($2=="" || $2=="::") {print $1": uid "$3}' /etc/passwd 2>/dev/null)
  [ -n "$empty" ] && finding HIGH "gecos" "Account(s) with empty password field" \
    "$(printf '%s' "$empty" | join_lines)" \
    "Set a password or lock the account (passwd -l); empty field may allow passwordless login"
  # GECOS starts with the literal password (classic misconfig): contains ':' pattern is normal; check for password-like prefix
  suspicious=$(awk -F: '$5 ~ /^[^:,]{4,}/ && $5 !~ /^(Room|Office|Work|Phone|Email|User|\\(|[0-9]{2,5}$)/ {print $1": "$5}' /etc/passwd 2>/dev/null | head -5)
  [ -n "$suspicious" ] && note "review GECOS fields manually for embedded secrets: $suspicious"
  # accounts with uid 0 other than root
  uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
  [ -n "$uid0" ] && finding HIGH "gecos" "Non-root account(s) with uid 0" \
    "uid-0 accounts: $uid0" \
    "There should be exactly one uid 0 (root); remove or renumber extras and audit their activity"
}

# ---------------------------------------------------------------------------
# method: suid_shells
# ---------------------------------------------------------------------------
method_suid_shells() {
  section "shells & interpreters with SUID/SGID or odd perms"
  local s
  for s in /bin/bash /bin/dash /bin/sh /bin/zsh /usr/bin/python* /usr/bin/perl* /usr/bin/ruby* /usr/bin/node* /usr/bin/php*; do
    [ -e "$s" ] || continue
    if has_special_perm "$s" $((8#4000 | 8#2000)); then
      finding CRITICAL "suid_shells" "Shell/interpreter has SUID/SGID bit: $s" \
        "$(ls -l "$s")" \
        "chmod u-s,g-s immediately; a SUID shell/interpreter is a one-command root oracle"
    fi
  done
  # /bin/sh not root-owned?
  if [ -e /bin/sh ] && [ "$(stat -c %U /bin/sh 2>/dev/null)" != "root" ]; then
    finding HIGH "suid_shells" "/bin/sh not owned by root" \
      "$(ls -l /bin/sh)" \
      "chown root:root /bin/sh; investigate how ownership changed"
  fi
}

# ---------------------------------------------------------------------------
# method: path_hijack
# ---------------------------------------------------------------------------
method_path_hijack() {
  section "PATH hygiene"
  local IFS=':'
  local d idx=0 empty=0
  for d in $PATH; do
    idx=$((idx + 1))
    if [ -z "$d" ]; then
      empty=1
      continue
    fi
    case "$d" in
      .|./|~*|"~"*)
        finding HIGH "path_hijack" "Relative/expansion entry in PATH: position $idx = '$d'" \
          "PATH=$PATH" \
          "Remove relative/tilde PATH entries; they enable binary shadowing when cwd is attacker-influenced" ;;
      *)
        if [ ! -d "$d" ]; then
          note "PATH entry $idx does not exist: $d (dead entry — noise, and may hint typosquatting setups)"
        elif ww_dir "$d"; then
          finding HIGH "path_hijack" "World-writable PATH directory: $d" \
            "$d (position $idx) is writable by all" \
            "chmod 755 $d; shadowing a root-called binary here wins code exec whenever it runs"
        fi ;;
    esac
  done
  [ "$empty" -eq 1 ] && finding HIGH "path_hijack" "Empty PATH component (current directory)" \
    "PATH=$PATH" \
    "Empty components resolve to the current directory — remove them"
  unset IFS
}

# ---------------------------------------------------------------------------
# method: systemd_units
# ---------------------------------------------------------------------------
method_systemd_units() {
  section "systemd unit & drop-in writability"
  local dir f ov
  for dir in /etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
    [ -d "$dir" ] || continue
    f=$(find "$dir" -maxdepth 3 \( -name '*.service' -o -name '*.timer' -o -name '*.path' -o -name '*.socket' \) -type f -perm -0002 -print 2>/dev/null | head -5)
    [ -n "$f" ] && finding CRITICAL "systemd_units" "World-writable systemd unit(s) in $dir" \
      "$(printf '%s' "$f" | join_lines)" \
      "chown root:root && chmod 644; a writable root service/timer/path unit is arbitrary code as root at next start/trigger"
    # writable drop-in overrides
    ov=$(find "$dir" -path '*.d/*.conf' -type f -perm -0002 -print 2>/dev/null | head -5)
    [ -n "$ov" ] && finding HIGH "systemd_units" "World-writable systemd drop-in(s) in $dir" \
      "$(printf '%s' "$ov" | join_lines)" \
      "chmod 644 drop-ins; ExecStart overrides there win over packaged units"
  done
}

# ---------------------------------------------------------------------------
# method: modprobe
# ---------------------------------------------------------------------------
method_modprobe() {
  section "modprobe/modules-load drop-ins"
  local dir f inst h
  for dir in /etc/modprobe.d /etc/modules-load.d /run/modprobe.d /usr/lib/modprobe.d; do
    [ -d "$dir" ] || continue
    f=$(find "$dir" -maxdepth 1 -type f -perm -0002 -print 2>/dev/null | head -5)
    [ -n "$f" ] && finding HIGH "modprobe" "World-writable modprobe/module-load config in $dir" \
      "$(printf '%s' "$f" | join_lines)" \
      "chmod 644; modprobe.d 'install' lines execute arbitrary commands as root on module load"
  done
  # install lines referencing world-writable helpers
  if ls /etc/modprobe.d/*.conf >/dev/null 2>&1; then
    inst=$(grep -RH '^install ' /etc/modprobe.d/*.conf 2>/dev/null | grep -oE '/[A-Za-z0-9_./-]+' | sort -u)
    for h in $inst; do
      if [ -e "$h" ] && [ -w "$h" ]; then
        finding HIGH "modprobe" "modprobe 'install' helper is writable: $h" \
          "/etc/modprobe.d references writable helper $h" \
          "chown root:root && chmod 755 $h; it runs as root whenever the module loads"
      fi
    done
  fi
}

# ---------------------------------------------------------------------------
# method: ssh_config
# ---------------------------------------------------------------------------
method_ssh_config() {
  section "SSH server configuration"
  if ! [ -r /etc/ssh/sshd_config ]; then
    note "sshd_config not readable by $USER_NAME"
    return
  fi
  local cfg=/etc/ssh/sshd_config effective hk perm
  effective=$(grep -vE '^\s*(#|$)' "$cfg" 2>/dev/null)
  if printf '%s\n' "$effective" | grep -qiE '^\s*PermitRootLogin\s+(yes|prohibit-password)\b'; then
    finding MEDIUM "ssh_config" "Root SSH login permitted" \
      "$(printf '%s\n' "$effective" | grep -iE '^\s*PermitRootLogin' | join_lines)" \
      "Set PermitRootLogin no; use named accounts + sudo for admin access"
  fi
  if printf '%s\n' "$effective" | grep -qiE '^\s*PasswordAuthentication\s+yes\b'; then
    finding LOW "ssh_config" "Password authentication enabled for SSH" \
      "$(printf '%s\n' "$effective" | grep -iE '^\s*PasswordAuthentication' | join_lines)" \
      "Prefer key-only auth; disable password auth and disable unused challenge-response"
  fi
  if printf '%s\n' "$effective" | grep -qiE '^\s*(PermitEmptyPasswords\s+yes|UsePAM\s+no)\b'; then
    finding HIGH "ssh_config" "Weak SSH password handling (empty passwords or no PAM)" \
      "$(printf '%s\n' "$effective" | grep -iE 'PermitEmptyPasswords|UsePAM' | join_lines)" \
      "PermitEmptyPasswords no; keep UsePAM yes unless you know exactly why not"
  fi
  if printf '%s\n' "$effective" | grep -qiE '^\s*(X11Forwarding\s+yes|ForwardAgent\s+yes)\b'; then
    note "X11/agent forwarding enabled — reduces client-side attack surface if disabled"
  fi
  # host keys world-readable? private host keys should be 600 root
  for hk in /etc/ssh/*_key; do
    [ -e "$hk" ] || continue
    perm=$(stat -c %a "$hk" 2>/dev/null)
    case "$perm" in
      *00) : ;;
      *) finding MEDIUM "ssh_config" "Weak permissions on SSH host key: $hk ($perm)" \
           "chmod candidate: 600" \
           "chmod 600 $hk; host private keys must be root-only" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# method: lxd_sock
# ---------------------------------------------------------------------------
method_lxd_sock() {
  section "LXD/LXC socket & group"
  local sock
  for sock in /var/snap/lxd/common/lxd/unix.socket /run/lxd/unix.socket /var/lib/lxd/unix.socket; do
    if [ -w "$sock" ]; then
      finding CRITICAL "lxd_sock" "Writable LXD unix socket: $sock" \
        "$sock writable by $USER_NAME" \
        "LXD socket == host root (launch privileged container with host rootfs); restrict to lxd group admins or use rootless mode"
    fi
  done
  if id -nG 2>/dev/null | tr ' ' '\n' | grep -qxE 'lxd|lxc'; then
    note "lxd/lxc group membership — see 'groups' method; socket check above is authoritative"
  fi
}

# ---------------------------------------------------------------------------
# method: acls
# ---------------------------------------------------------------------------
method_acls() {
  section "ACLs granting access on sensitive files"
  if ! have getfacl; then note "getfacl not installed (acl package)"; return; fi
  local t acl
  for t in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/ld.so.preload /root; do
    [ -e "$t" ] || continue
    acl=$(getfacl -p "$t" 2>/dev/null | grep -E '^(user|group):[^:]+:.*(rw|rwx)' | head -3)
    [ -n "$acl" ] && finding MEDIUM "acls" "Non-root ACL grants on $t" \
      "$(printf '%s' "$acl" | join_lines)" \
      "getfacl $t; remove unexpected entries with setfacl -b or -x; ACL rw on shadow/sudoers is game over"
  done
}

# ---------------------------------------------------------------------------
# method: shell_rc
# ---------------------------------------------------------------------------
method_shell_rc() {
  section "writable shell startup files"
  local f ff
  # root/global and user startup files writable by others?
  for f in /etc/profile /etc/bash.bashrc /etc/zshrc /etc/profile.d/*.sh /root/.bashrc /root/.profile \
           /home/*/.bashrc /home/*/.profile /home/*/.zshrc /home/*/.bash_profile; do
    for ff in $f; do
      [ -e "$ff" ] || continue
      if ww_file "$ff"; then
        case "$ff" in
          /etc/*|/root/*)
            finding CRITICAL "shell_rc" "Root/global shell startup file writable: $ff" \
              "$(ls -l "$ff")" \
              "chown root:root && chmod 644; it executes on every login/shell spawn as its owner" ;;
          *)
            finding MEDIUM "shell_rc" "User shell startup file writable by others: $ff" \
              "$(ls -l "$ff")" \
              "chmod 644; attacker-controlled startup files run on next login" ;;
        esac
      fi
    done
  done
}

# ---------------------------------------------------------------------------
# method: env_secrets
# ---------------------------------------------------------------------------
method_env_secrets() {
  section "secrets in process environment"
  local envf=/proc/self/environ hit
  [ -r "$envf" ] || return
  hit=$(tr '\0' '\n' < "$envf" 2>/dev/null | grep -iE '^(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN|NPM_TOKEN|DOCKER_PASSWORD|KUBECONFIG|SLACK_TOKEN|API_KEY|SECRET_KEY|PASSWORD|PASSWD|TOKEN|PRIVATE_KEY)=' | sed 's/=.*/=<redacted>/' | head -10)
  [ -n "$hit" ] && finding MEDIUM "env_secrets" "Secret-like variables present in shell environment" \
    "$(printf '%s' "$hit" | join_lines)" \
    "Move secrets to a vault or 0600 files; environment leaks via /proc, crash dumps, and child processes"
}

# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
METHODS=(sudo suid capabilities cron writable_paths groups nfs kernel credentials services ld_preload misc docker_sock polkit sudo_samedit sysctl mounts home_loot gecos suid_shells path_hijack systemd_units modprobe ssh_config lxd_sock acls shell_rc env_secrets)

list_methods() { printf '%s\n' "${METHODS[@]}"; }

usage() {
  cat <<EOF
linux-privesc-audit v$VERSION — multi-method Linux privilege escalation auditor (read-only)

Usage:
  $0                run all methods, human-readable report
  $0 --json         emit JSON report
  $0 --method NAME  run one method (see --list)
  $0 --recipes      after the audit, print manual exploitation recipes per finding
  $0 --no-banner    suppress the startup banner
  $0 --list         list method names
  $0 -h|--help      this help
  $0 -v|--version   version
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON_OUT=1; shift ;;
    --method) ONLY_METHOD="${2:-}"; shift 2 ;;
    --recipes) RECIPES=1; shift ;;
    --no-banner) NO_BANNER=1; shift ;;
    --list) list_methods; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "linux-privesc-audit $VERSION"; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ "$JSON_OUT" -eq 0 ] && {
  print_banner
  printf '%s%slinux-privesc-audit v%s%s — read-only audit\n' "$C_BOLD" "$C_MAGENTA" "$VERSION" "$C_RESET"
  printf 'host: %s  user: %s (uid=%s)  date: %s\n' "$HOST_NAME" "$USER_NAME" "$UID_NUM" "$(date)"
}

for m in "${METHODS[@]}"; do
  if [ -n "$ONLY_METHOD" ] && [ "$ONLY_METHOD" != "$m" ]; then continue; fi
  "method_$m" || note "method $m failed (continuing)"
done

END_TS=$(date +%s)

if [ "$JSON_OUT" -eq 1 ]; then
  printf '{\n  "tool": "linux-privesc-audit",\n  "version": "%s",\n  "host": "%s",\n  "user": "%s",\n  "uid": %s,\n  "duration_sec": %s,\n  "findings": [\n' \
    "$VERSION" "$HOST_NAME" "$USER_NAME" "$UID_NUM" "$((END_TS - START_TS))"
  local_i=0
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev method title evidence remediation <<< "$f"
    local_i=$((local_i + 1))
    [ "$local_i" -gt 1 ] && printf ',\n'
    printf '    {"severity": "%s", "method": "%s", "title": "%s", "evidence": "%s", "remediation": "%s"}' \
      "$(json_esc "$sev")" "$(json_esc "$method")" "$(json_esc "$title")" "$(json_esc "$evidence")" "$(json_esc "$remediation")"
  done
  printf '\n  ],\n  "finding_count": %d\n}\n' "$FINDINGS_COUNT"
else
  echo
  printf '%s%s== summary ==%s\n' "$C_BOLD" "$C_MAGENTA" "$C_RESET"
  echo "findings: $FINDINGS_COUNT  (duration: $((END_TS - START_TS))s)"
  declare -A sev_count=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0)
  for f in "${FINDINGS[@]}"; do
    sev="${f%%|*}"
    [ -n "${sev_count[$sev]+x}" ] && sev_count[$sev]=$((sev_count[$sev] + 1))
  done
  for sev in CRITICAL HIGH MEDIUM LOW; do
    printf '  %s%s: %s%s\n' "$(sev_color "$sev")" "$sev" "${sev_count[$sev]}" "$C_RESET"
  done
  [ "$FINDINGS_COUNT" -gt 0 ] && echo "review each item; this tool reports candidates, not confirmed exploits."
  [ "$RECIPES" -eq 1 ] && print_recipes
fi
