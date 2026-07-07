#!/bin/bash
#
# machunt.sh — macOS Threat Hunting & Compromise Assessment Tool
# Author: Mobin Erteghaie  •  License: MIT  •  https://github.com/mobinert/machunt
# -------------------------------------------------------------------
# A READ-ONLY scanner. It inspects the places macOS malware actually
# hides (persistence, signatures, network, system integrity) and writes
# a timestamped report. It NEVER deletes, quarantines, or modifies
# anything — every finding is for YOU to review and act on.
#
# Usage:
#   chmod +x machunt.sh
#   ./machunt.sh                  # scan as your user
#   sudo ./machunt.sh             # deeper scan (system LaunchDaemons, TCC, etc.)
#   ./machunt.sh --html --json    # also write a visual HTML report + JSON summary
#   ./machunt.sh --deep           # add unified-log triage (slower)
#
# Every run prints a 0–100 security-posture score with a letter grade.
#
# Tested on macOS 12–15 (Intel & Apple Silicon). Pure bash + built-ins,
# no dependencies, nothing installed.
# -------------------------------------------------------------------

# Do NOT use `set -e`: many probes legitimately fail (permissions, missing
# files) and we want to keep scanning and report what we can.
set -o pipefail 2>/dev/null

MACHUNT_VERSION="2.0.0"

# ----- Command-line options ------------------------------------------
WANT_JSON=0
WANT_HTML=0
WANT_DEEP=0
NO_DESKTOP=0
for arg in "$@"; do
  case "$arg" in
    --json)        WANT_JSON=1 ;;
    --html)        WANT_HTML=1 ;;
    --deep)        WANT_DEEP=1 ;;
    --no-desktop)  NO_DESKTOP=1 ;;
    -v|--version)
      printf 'machunt v%s\n' "$MACHUNT_VERSION"; exit 0 ;;
    -h|--help)
      printf 'machunt v%s — macOS Threat Hunt & Compromise Assessment (read-only)\n\n' "$MACHUNT_VERSION"
      cat <<'EOF'
Usage:
  ./machunt.sh [options]
  sudo ./machunt.sh [options]      # deeper coverage (system daemons, TCC, ports)

Options:
  --html          Also write a designed, self-contained HTML report
                  (score gauge, severity grouping) — open it in any browser
  --json          Also write a machine-readable JSON summary of findings
  --deep          Enable slower deep checks (unified-log triage of the
                  last 12h for suspicious process spawns)
  --no-desktop    Do not place a copy of the report on the Desktop
  -h, --help      Show this help

The full text report is saved in the directory you run the tool from,
and (unless --no-desktop) a copy is placed on your Desktop. Every run also
prints a 0–100 security-posture score with a letter grade.
EOF
      exit 0 ;;
    *) printf 'Unknown option: %s (try --help)\n' "$arg" >&2; exit 2 ;;
  esac
done

# ----- Output setup --------------------------------------------------
TS="$(date +%Y%m%d_%H%M%S)"
# Save the report in the directory the tool is run from (the current
# working directory), not the home folder.
RUN_DIR="$(pwd)"
REPORT="${RUN_DIR}/machunt_report_${TS}.txt"
: > "$REPORT" 2>/dev/null || { echo "Cannot write report to $RUN_DIR — run from a writable directory."; exit 1; }

# Findings are recorded — with a severity and the module that raised them —
# to a single temp file so that counts and grouping survive subshells (many
# probes run inside pipes / while-read loops). Format is TAB-delimited:
#   severity<TAB>module<TAB>message      severity ∈ crit | high | med | low
FIND_FILE="$(mktemp "${TMPDIR:-/tmp}/machunt_find.XXXXXX")"
cleanup() { rm -f "$FIND_FILE" 2>/dev/null; }
trap cleanup EXIT

CURRENT_MODULE="startup"

# Colors (only when writing to a terminal)
if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; M=$'\e[35m'; BOLD=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; C=""; M=""; BOLD=""; N=""
fi

# log: echo to screen AND append to report (stripped of color)
log() { printf '%s\n' "$*" | tee -a "$REPORT" >/dev/null; printf '%s\n' "$*"; }
section() {
  CURRENT_MODULE="$*"
  log ""
  log "${BOLD}${B}══════════════════════════════════════════════════════════════${N}"
  log "${BOLD}${B}  $*${N}"
  log "${BOLD}${B}══════════════════════════════════════════════════════════════${N}"
}
ok()    { log "  ${G}[ ok ]${N} $*"; }
info()  { log "  ${C}[info]${N} $*"; }

# record <severity> <message> — remember a finding for the summary/JSON/HTML.
record() {
  local sev="$1"; shift
  local msg="$*"
  msg="${msg//$'\t'/ }"        # keep the TAB delimiter clean
  printf '%s\t%s\t%s\n' "$sev" "$CURRENT_MODULE" "$msg" >> "$FIND_FILE"
}
# Finding severities, worst → mildest:
crit()  { log "  ${R}${BOLD}[CRIT]${N} $*"; record crit "$*"; }   # weakened defenses / active-compromise signal
alert() { log "  ${R}[FLAG]${N} $*";       record high "$*"; }   # look at this — anomalous but not proof
warn()  { log "  ${Y}[ ?? ]${N} $*";       record med  "$*"; }   # lower-priority note to confirm

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

# check_sig <path>: classify a binary/bundle's code signature.
# Returns via echo: "apple" | "devid:<team>" | "adhoc" | "unsigned" | "invalid"
check_sig() {
  local p="$1" out
  out="$(codesign -dvv "$p" 2>&1)"
  if echo "$out" | grep -q "Authority=Apple"; then echo "apple"
  elif echo "$out" | grep -q "Authority=Developer ID"; then
    echo "devid:$(echo "$out" | grep -m1 'TeamIdentifier=' | cut -d= -f2)"
  elif echo "$out" | grep -q "Signature=adhoc"; then echo "adhoc"
  elif echo "$out" | grep -qi "code object is not signed"; then echo "unsigned"
  else echo "invalid"; fi
}

# Pull the program path out of a launchd plist
plist_program() {
  local plist="$1" prog
  prog="$(/usr/libexec/PlistBuddy -c 'Print :Program' "$plist" 2>/dev/null)"
  [ -z "$prog" ] && prog="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$plist" 2>/dev/null)"
  echo "$prog"
}

# notarized <path>: best-effort Gatekeeper assessment of a binary/bundle.
# Notarization means Apple scanned it for malware. A Developer-ID target that
# is NOT notarized is more worth a look. Echoes: "yes" | "no" | "?"
notarized() {
  local out
  out="$(spctl --assess --type execute -v "$1" 2>&1)"
  if echo "$out" | grep -qi "accepted"; then echo "yes"
  elif echo "$out" | grep -qi "rejected\|denied\|unnotarized"; then echo "no"
  else echo "?"; fi
}

# run_capped <seconds> <outfile> <command...>: run a command, redirecting its
# stdout to <outfile>, but hard-stop it after <seconds> (macOS has no
# `timeout`). Used to keep the optional unified-log scan bounded.
run_capped() {
  local secs="$1" out="$2"; shift 2
  "$@" > "$out" 2>/dev/null &
  local cpid=$!
  ( sleep "$secs"; kill -TERM "$cpid" 2>/dev/null; sleep 2; kill -KILL "$cpid" 2>/dev/null ) &
  local wpid=$!
  wait "$cpid" 2>/dev/null
  kill "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
}

# =====================================================================
clear 2>/dev/null
log "${BOLD}${C}"
log "   ███╗   ███╗ █████╗  ██████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗"
log "   ████╗ ████║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝"
log "   ██╔████╔██║███████║██║     ███████║██║   ██║██╔██╗ ██║   ██║"
log "   ██║╚██╔╝██║██╔══██║██║     ██╔══██║██║   ██║██║╚██╗██║   ██║"
log "   ██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║╚██████╔╝██║ ╚████║   ██║"
log "   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝"
log "${N}"
log "   macOS Threat Hunt & Compromise Assessment  v${MACHUNT_VERSION} — READ-ONLY"
log "   Host: $(scutil --get ComputerName 2>/dev/null || hostname)   User: $(whoami)   Date: $(date)"
log "   Privilege: $( [ $IS_ROOT -eq 1 ] && echo 'ROOT (deep scan)' || echo 'user (run with sudo for full coverage)')"
log "   Report file: $REPORT"

# =====================================================================
section "1. SYSTEM SECURITY POSTURE"
# These are the baseline defenses. If any are OFF, that's the first thing to fix.

sip="$(csrutil status 2>/dev/null)"
echo "$sip" | grep -qi "enabled" && ok "System Integrity Protection (SIP): enabled" || crit "SIP is DISABLED — a major red flag if you didn't do it: $sip"

fv="$(fdesetup status 2>/dev/null)"
echo "$fv" | grep -qi "On" && ok "FileVault disk encryption: On" || warn "FileVault is Off — disk not encrypted: $fv"

fw="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)"
echo "$fw" | grep -qi "enabled" && ok "Application Firewall: enabled" || warn "Application Firewall is OFF: $fw"

gk="$(spctl --status 2>/dev/null)"
echo "$gk" | grep -qi "enabled" && ok "Gatekeeper: enabled" || crit "Gatekeeper is DISABLED — unsigned apps run freely: $gk"

# Stealth mode / remote login / screen sharing
ssh_on="$(systemsetup -getremotelogin 2>/dev/null)"
echo "$ssh_on" | grep -qi "On" && warn "Remote Login (SSH) is ON — confirm this is you: $ssh_on" || ok "Remote Login (SSH): off"

ard="$(launchctl list 2>/dev/null | grep -i 'ARDAgent\|screensharing' )"
[ -n "$ard" ] && warn "Screen Sharing / Remote Management agent is loaded — confirm you enabled it" || ok "No remote management agent loaded"

# =====================================================================
section "2. PERSISTENCE — LaunchAgents & LaunchDaemons"
# THE #1 place macOS malware lives. Each plist points to a program that
# runs automatically. We verify the signature of every target binary.
# Apple-signed = expected. Developer ID = a real vendor (check it's one
# you know). adhoc/unsigned/invalid = suspicious.

LAUNCH_DIRS=(
  "/Library/LaunchAgents"
  "/Library/LaunchDaemons"
  "$HOME/Library/LaunchAgents"
)
[ $IS_ROOT -eq 1 ] && LAUNCH_DIRS+=("/System/Library/LaunchAgents" "/System/Library/LaunchDaemons")

for dir in "${LAUNCH_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  log ""
  info "Scanning ${BOLD}$dir${N}"
  found=0
  for plist in "$dir"/*.plist; do
    [ -e "$plist" ] || continue
    found=1
    prog="$(plist_program "$plist")"
    label="$(basename "$plist")"
    if [ -z "$prog" ]; then
      info "$label → (no program path / uses other key)"
      continue
    fi
    # System/Apple dirs are expected-clean; focus scrutiny on /Library & ~/Library
    sig="$(check_sig "$prog")"
    case "$sig" in
      apple)        ok "$label → $prog [Apple-signed]" ;;
      devid:*)
        # A real vendor — but check Apple actually notarized it (scanned for malware)
        if [ "$(notarized "$prog")" = "no" ]; then
          warn "$label → $prog [Developer ID ${sig#devid:}, NOT notarized] — verify this vendor"
        else
          info "$label → $prog [Developer ID ${sig#devid:}] — confirm vendor is known"
        fi ;;
      adhoc)        alert "$label → $prog [AD-HOC signed — common in malware]" ;;
      unsigned)     alert "$label → $prog [UNSIGNED]" ;;
      invalid)      alert "$label → $prog [signature INVALID/broken]" ;;
    esac
    # Bonus heuristics: programs running from sketchy locations
    case "$prog" in
      /tmp/*|/private/tmp/*|/var/tmp/*|*/Users/Shared/*|/Users/*/Library/Application\ Support/.*|*/.hidden/*)
        alert "   ↳ runs from a suspicious/temp/hidden location: $prog" ;;
    esac
    # RunAtLoad + KeepAlive on an unknown binary = aggressive persistence
    if /usr/libexec/PlistBuddy -c 'Print :RunAtLoad' "$plist" 2>/dev/null | grep -qi true; then
      [ "$sig" = "unsigned" -o "$sig" = "adhoc" -o "$sig" = "invalid" ] && \
        log "       (RunAtLoad=true on a non-validly-signed binary)"
    fi
  done
  [ $found -eq 0 ] && ok "(empty)"
done

# =====================================================================
section "3. PERSISTENCE — Login Items & Background Tasks"

info "User login items (System Settings → General → Login Items):"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | tr ',' '\n' | sed 's/^ */    /' | tee -a "$REPORT"

# Modern background task agents (macOS 13+)
if command -v sfltool >/dev/null 2>&1; then
  info "Registered background items (sfltool):"
  sfltool dumpbtm 2>/dev/null | grep -iE 'Name:|Developer Name:|Type:|Disposition:' | sed 's/^/    /' | tee -a "$REPORT"
fi

# =====================================================================
section "4. PERSISTENCE — Cron, periodic, at, login hooks, emond"

info "User crontab:"
crontab -l 2>/dev/null | grep -v '^#' | sed 's/^/    /' | tee -a "$REPORT" || ok "    none"

for f in /etc/crontab /usr/lib/cron/tabs/* /var/at/tabs/*; do
  [ -e "$f" ] && warn "Cron/at entry present: $f" && cat "$f" 2>/dev/null | sed 's/^/      /' | tee -a "$REPORT"
done

# Legacy LoginHook / LogoutHook (almost always malicious on modern macOS)
lh="$(defaults read /var/root/Library/Preferences/com.apple.loginwindow LoginHook 2>/dev/null)"
[ -n "$lh" ] && crit "LoginHook set (legacy, rarely legitimate): $lh"
# Read the global hook directly when root (no mid-scan sudo prompt — this tool
# never elevates on its own; run the whole thing under sudo for deep coverage).
if [ $IS_ROOT -eq 1 ]; then
  glh="$(defaults read /Library/Preferences/com.apple.loginwindow LoginHook 2>/dev/null)"
  [ -n "$glh" ] && crit "Global LoginHook set: $glh"
fi

# emond (event monitor) — deprecated, abused for persistence
if [ -d /etc/emond.d/rules ] && ls -A /etc/emond.d/rules 2>/dev/null | grep -qv SampleRules; then
  warn "Non-sample emond rules present in /etc/emond.d/rules — inspect"
  ls -la /etc/emond.d/rules 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
fi

# periodic scripts that aren't Apple's
info "Custom /etc/periodic scripts (Apple ships a known set):"
find /etc/periodic -type f 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"

# =====================================================================
section "5. CONFIGURATION PROFILES (MDM / forced settings)"
# Malware & stalkerware install profiles to force proxies, trust certs,
# or lock settings. On a personal Mac you usually expect ZERO.
prof="$(profiles list -all 2>/dev/null; profiles show 2>/dev/null)"
if echo "$prof" | grep -qiE 'attribute|profileIdentifier|_computerlevel'; then
  alert "Configuration profile(s) installed — review carefully:"
  echo "$prof" | sed 's/^/    /' | tee -a "$REPORT"
else
  ok "No configuration profiles installed"
fi

# =====================================================================
section "6. KERNEL & SYSTEM EXTENSIONS"
info "Third-party kernel extensions (non-Apple kexts):"
kextstat 2>/dev/null | grep -v com.apple | sed 's/^/    /' | tee -a "$REPORT" || ok "    none (or restricted)"

if command -v systemextensionsctl >/dev/null 2>&1; then
  info "System extensions:"
  systemextensionsctl list 2>/dev/null | grep -iE 'enabled|activated' | sed 's/^/    /' | tee -a "$REPORT"
fi

# =====================================================================
section "7. RUNNING PROCESSES — unsigned & suspicious origins"
# Walk live processes; verify the on-disk binary's signature. Anything
# unsigned/adhoc running from a user-writable or temp dir is worth a look.
info "Checking signatures of running process executables (this takes a moment)..."
ps -axo pid=,user=,comm= 2>/dev/null | while read -r pid user comm; do
  # only check absolute paths to real files
  case "$comm" in
    /*) : ;;
    *) continue ;;
  esac
  [ -f "$comm" ] || continue
  case "$comm" in /System/*|/usr/lib/*|/usr/libexec/*|/usr/sbin/*|/usr/bin/*) continue ;; esac
  sig="$(check_sig "$comm")"
  case "$sig" in
    unsigned|adhoc|invalid)
      alert "pid $pid ($user): $comm  [$sig]"
      ;;
  esac
  case "$comm" in
    /tmp/*|/private/tmp/*|/var/tmp/*|/Users/Shared/*|*/.Trash/*)
      alert "pid $pid ($user) runs from temp/shared: $comm" ;;
  esac
done

# =====================================================================
section "8. NETWORK — listening ports & active connections"
info "Processes LISTENING for inbound connections:"
if [ $IS_ROOT -eq 1 ]; then
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR==1 || $1 !~ /^(rapportd|sharingd|ControlCe|launchd)$/' | sed 's/^/    /' | tee -a "$REPORT"
else
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
  info "(run with sudo to see ports owned by other users)"
fi

log ""
info "Established OUTBOUND connections (where is your Mac talking to?):"
lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR==1{print;next} {print}' | sed 's/^/    /' | tee -a "$REPORT"

# =====================================================================
section "9. DNS & HOSTS FILE TAMPERING"
info "/etc/hosts non-default entries (redirects can hijack traffic):"
grep -vE '^\s*#|^\s*$|^(127\.0\.0\.1|255\.255\.255\.255|::1|fe80|ff00|ff02)\b' /etc/hosts 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
[ "$(grep -vcE '^\s*#|^\s*$|127\.0\.0\.1|255\.255|::1|fe80|ff00|ff02' /etc/hosts 2>/dev/null)" -gt 0 ] && warn "Custom hosts entries above — confirm you added them"

info "Configured DNS servers (rogue DNS = silent redirection):"
scutil --dns 2>/dev/null | grep 'nameserver\[' | sort -u | sed 's/^/    /' | tee -a "$REPORT"

info "Network proxies (malware sets proxies to intercept traffic):"
scutil --proxy 2>/dev/null | grep -iE 'Enable|Proxy|HTTPS|HTTP ' | sed 's/^/    /' | tee -a "$REPORT"

# =====================================================================
section "10. BROWSER EXTENSIONS"
# Adware/hijackers love browser extensions.
info "Safari extensions:"
ls "$HOME/Library/Safari/Extensions/" 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT" || ok "    none"
for chromedir in "$HOME/Library/Application Support/Google/Chrome" "$HOME/Library/Application Support/BraveSoftware/Brave-Browser" "$HOME/Library/Application Support/Microsoft Edge"; do
  if [ -d "$chromedir" ]; then
    info "Chromium extensions in $(basename "$(dirname "$chromedir")")/$(basename "$chromedir"):"
    find "$chromedir"/*/Extensions -maxdepth 2 -name manifest.json 2>/dev/null | while read -r m; do
      name="$(grep -o '"name"[^,]*' "$m" 2>/dev/null | head -1)"
      log "    $(dirname "$m")  $name"
    done
  fi
done

# =====================================================================
section "11. SUID/SGID BINARIES outside system paths"
# A SUID binary in a user-writable location is a classic privilege backdoor.
info "Searching common writable areas (this can take a moment)..."
find /Applications /Users /tmp /private/tmp /var/tmp /Library \
     -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
  | grep -v '/System/' | while read -r s; do
      alert "SUID/SGID binary: $s  ($(ls -l "$s" 2>/dev/null | awk '{print $1,$3,$4}'))"
    done

# =====================================================================
section "12. RECENTLY MODIFIED FILES in sensitive locations"
# Files changed in the last 7 days where persistence/config lives.
info "Changed in last 7 days under persistence / config dirs:"
find /Library/LaunchAgents /Library/LaunchDaemons "$HOME/Library/LaunchAgents" \
     /etc /Library/PrivilegedHelperTools "$HOME/Library/Preferences" \
     -maxdepth 2 -type f -mtime -7 2>/dev/null \
  | grep -vE '\.plist\.lockfile$|/com\.apple\.' | sed 's/^/    /' | tee -a "$REPORT"

# =====================================================================
section "13. SHELL & ENVIRONMENT TAMPERING"
# Backdoors often add a line to your shell startup to re-launch on login.
for rc in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile" /etc/zshrc /etc/profile; do
  [ -f "$rc" ] || continue
  # Look for download-and-execute / reverse-shell patterns, but ignore
  # Apple's stock path_helper line and obvious comments.
  hits="$(grep -nE 'curl .*\|.*sh|wget .*\|.*sh|base64 .*-d|/dev/tcp/|nc -|python[0-9]? -c|osascript -e .*(do shell|curl|http)' "$rc" 2>/dev/null \
          | grep -v 'path_helper')"
  if [ -n "$hits" ]; then
    warn "Suspicious commands in $rc:"
    echo "$hits" | sed 's/^/      /' | tee -a "$REPORT"
  fi
done

# =====================================================================
section "14. KNOWN MALWARE / IOC PATH CHECK"
# Spot-check paths used by well-documented macOS malware families
# (Silver Sparrow, Shlayer, XCSSET, OSX/CrescentCore, Bundlore,
# AdLoad, MacStealer, Atomic Stealer, etc.). Presence != infection,
# but any hit deserves investigation.
IOCS=(
  "$HOME/Library/._insu"
  "/tmp/agent.sh"
  "$HOME/.ss"
  "/Library/Application Support/Bundlore"
  "$HOME/Library/LaunchAgents/com.apple.softwareupdate.plist"   # AdLoad-style masquerade
  "/private/tmp/Updater.app"
  "$HOME/Library/Application Support/.lock"
  "/usr/local/bin/xpcproxy"
)
hit=0
for ioc in "${IOCS[@]}"; do
  [ -e "$ioc" ] && { crit "Known-bad path present: $ioc"; hit=1; }
done
# Apple-masquerade heuristic: anything named like Apple but NOT Apple-signed
find "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons -name '*apple*' 2>/dev/null | while read -r f; do
  prog="$(plist_program "$f")"
  [ -n "$prog" ] && [ "$(check_sig "$prog")" != "apple" ] && \
    alert "plist masquerades as Apple but target isn't Apple-signed: $f → $prog"
done
[ $hit -eq 0 ] && ok "No known-bad IOC paths matched"

# =====================================================================
section "15. PRIVACY PERMISSIONS (TCC) — camera, mic, screen, full-disk"
# Spyware/stalkerware must hold these grants to watch/listen. Reading the
# TCC database requires your terminal to have Full Disk Access; the system
# DB additionally needs sudo. A grant to an app you don't recognize — or to
# a generic "Terminal"/"Script Editor" you didn't authorize — is a red flag.
dump_tcc() {
  local db="$1" scope="$2"
  if [ -r "$db" ]; then
    info "$scope privacy grants (service → app):"
    sqlite3 "$db" "SELECT service, client, CASE auth_value WHEN 2 THEN 'ALLOW' WHEN 3 THEN 'ALLOW' WHEN 0 THEN 'deny' ELSE 'set' END FROM access WHERE auth_value>0 ORDER BY service;" 2>/dev/null \
      | sed 's/kTCCService//; s/|/  →  /g; s/^/    /' | tee -a "$REPORT"
  else
    warn "$scope TCC DB not readable — grant your terminal Full Disk Access (System Settings → Privacy & Security → Full Disk Access) or run with sudo to inspect camera/mic/screen grants"
  fi
}
if command -v sqlite3 >/dev/null 2>&1; then
  dump_tcc "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "User"
  [ $IS_ROOT -eq 1 ] && dump_tcc "/Library/Application Support/com.apple.TCC/TCC.db" "System"
else
  warn "sqlite3 not found — cannot read TCC privacy database"
fi

# =====================================================================
section "16. RECENTLY DOWNLOADED EXECUTABLES (quarantine xattr)"
# Files from the internet carry a com.apple.quarantine attribute recording
# where they came from. A freshly-downloaded script or binary is exactly how
# most Mac infections start.
info "Apps/scripts/binaries downloaded in last 14 days:"
any=0
find "$HOME/Downloads" "$HOME/Desktop" -maxdepth 2 -type f -mtime -14 \
     \( -name '*.app' -o -name '*.dmg' -o -name '*.pkg' -o -name '*.sh' \
        -o -name '*.command' -o -name '*.scpt' -o -perm -111 \) 2>/dev/null | while read -r f; do
  q="$(xattr -p com.apple.quarantine "$f" 2>/dev/null | head -1)"
  if [ -n "$q" ]; then log "    $f"; log "        ↳ source: ${q##*;}"; fi
done

# =====================================================================
section "17. BASELINE DIFF — change detection across runs"
# The single best way to "make sure everything stays fine": the first run
# fingerprints your persistence + login items; every later run flags anything
# ADDED since. A brand-new LaunchAgent between runs is a textbook implant.
BASE="$HOME/.machunt_baseline.txt"
CUR="$(mktemp "${TMPDIR:-/tmp}/machunt_cur.XXXXXX")"
{
  for d in /Library/LaunchAgents /Library/LaunchDaemons "$HOME/Library/LaunchAgents"; do
    [ -d "$d" ] && find "$d" -name '*.plist' 2>/dev/null
  done
  osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | tr ',' '\n' | sed 's/^ *//'
} | sort -u > "$CUR"
if [ -f "$BASE" ]; then
  added="$(comm -13 "$BASE" "$CUR")"
  removed="$(comm -23 "$BASE" "$CUR")"
  if [ -n "$added" ]; then
    alert "NEW persistence / login items appeared since your baseline:"
    echo "$added" | sed 's/^/      + /' | tee -a "$REPORT"
  else
    ok "No new persistence or login items since last baseline"
  fi
  [ -n "$removed" ] && { info "Items removed since baseline (usually fine):"; echo "$removed" | sed 's/^/      - /' | tee -a "$REPORT"; }
  info "Accept current state as the new baseline:  cp \"$CUR\" \"$BASE\""
  info "Reset the baseline entirely:  rm \"$BASE\""
else
  cp "$CUR" "$BASE"
  ok "Baseline saved to $BASE — future runs will alert you to anything new"
fi
rm -f "$CUR"

# =====================================================================
section "18. LOCAL ACCOUNTS & SUDO PRIVILEGES"
# Attackers add hidden/admin users or grant themselves passwordless sudo.
info "Admin-group members (can sudo):"
dscl . -read /Groups/admin GroupMembership 2>/dev/null | tr ' ' '\n' | grep -v '^GroupMembership:$' | sed 's/^/    /' | tee -a "$REPORT"

info "Real login accounts (UID >= 501):"
dscl . -list /Users UniqueID 2>/dev/null | awk '$2>=501 {print "    "$1" (uid "$2")"}' | tee -a "$REPORT"

# Hidden users (IsHidden=1) that can still log in are suspicious
for u in $(dscl . -list /Users 2>/dev/null); do
  hidden="$(dscl . -read /Users/"$u" IsHidden 2>/dev/null | awk '{print $2}')"
  shell="$(dscl . -read /Users/"$u" UserShell 2>/dev/null | awk '{print $2}')"
  uid="$(dscl . -read /Users/"$u" UniqueID 2>/dev/null | awk '{print $2}')"
  if [ "$hidden" = "1" ] && [ "$uid" -ge 500 ] 2>/dev/null && [ "$shell" != "/usr/bin/false" ] && [ "$shell" != "/sbin/nologin" ]; then
    crit "Hidden user '$u' (uid $uid) has a real login shell ($shell)"
  fi
done

info "Custom sudoers drop-ins (/etc/sudoers.d — Apple ships almost none):"
if [ $IS_ROOT -eq 1 ]; then
  for sf in /etc/sudoers.d/*; do
    [ -e "$sf" ] || continue
    case "$(basename "$sf")" in README) continue ;; esac
    if grep -qE 'NOPASSWD|ALL *= *\(ALL' "$sf" 2>/dev/null; then
      crit "Permissive sudoers rule in $sf:"; grep -vE '^\s*#|^\s*$' "$sf" 2>/dev/null | sed 's/^/        /' | tee -a "$REPORT"
    else
      info "    $sf"
    fi
  done
else
  warn "Run with sudo to inspect /etc/sudoers.d for passwordless-sudo backdoors"
fi

# =====================================================================
section "19. SSH TRUST — authorized keys & remote access"
# A planted public key in authorized_keys is silent, persistent remote access.
for akf in /var/root/.ssh/authorized_keys "$HOME/.ssh/authorized_keys"; do
  [ -r "$akf" ] || continue
  n="$(grep -cvE '^\s*#|^\s*$' "$akf" 2>/dev/null)"
  if [ "$n" -gt 0 ] 2>/dev/null; then
    warn "$akf contains $n authorized key(s) — confirm every one is yours:"
    grep -vE '^\s*#|^\s*$' "$akf" 2>/dev/null | awk '{print "        "$1" ... "$NF}' | tee -a "$REPORT"
  fi
done
[ -r "$HOME/.ssh/authorized_keys" ] || [ -r /var/root/.ssh/authorized_keys ] || ok "No authorized_keys files present (no key-based SSH access configured)"

# =====================================================================
section "20. NETWORK NEIGHBORHOOD — gateway, ARP & Wi-Fi (MITM check)"
# A rogue default gateway or spoofed ARP entry = someone intercepting traffic.
gw="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')"
[ -n "$gw" ] && info "Default gateway: $gw" || info "No default gateway (offline?)"

info "Current Wi-Fi network:"
ssid="$(ipconfig getsummary en0 2>/dev/null | awk -F' SSID : ' '/ SSID :/{print $2; exit}')"
[ -n "$ssid" ] && log "    $ssid" || log "    (not on Wi-Fi or undetectable)"

info "ARP neighbors (watch for the gateway IP mapped to an odd/duplicate MAC):"
arp -an 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
# Duplicate MACs across different IPs can indicate ARP-spoofing
dupmac="$(arp -an 2>/dev/null | grep -oE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}' | sort | uniq -d)"
[ -n "$dupmac" ] && warn "Same MAC appears for multiple IPs (possible ARP spoofing): $dupmac"

# =====================================================================
section "21. XPROTECT & SECURITY-UPDATE FRESHNESS"
# XProtect is Apple's built-in malware-signature engine. Malware sometimes
# tries to freeze it by disabling automatic security-data updates so new
# signatures never arrive. These should be current and enabled.
xp_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
[ -f "$xp_plist" ] || xp_plist="/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
if [ -f "$xp_plist" ]; then
  xpv="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$xp_plist" 2>/dev/null)"
  [ -n "$xpv" ] && info "XProtect signature bundle version: $xpv"
fi
xpr_plist="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
[ -f "$xpr_plist" ] && info "XProtect Remediator version: $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$xpr_plist" 2>/dev/null)"

auto_cfg="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null)"
auto_crit="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)"
if [ "$auto_cfg" = "0" ] || [ "$auto_crit" = "0" ]; then
  alert "Automatic security-data / critical updates are DISABLED (ConfigDataInstall=${auto_cfg:-?} CriticalUpdateInstall=${auto_crit:-?}) — malware often turns these off so XProtect can't catch it"
else
  ok "Automatic security-data updates appear enabled"
fi

# =====================================================================
section "22. DYLD INJECTION & ENVIRONMENT PERSISTENCE"
# Two stealthy tricks: forcing a library into other processes via
# DYLD_INSERT_LIBRARIES, and the legacy ~/.MacOSX/environment.plist which
# sets environment variables for every app you launch.
envp="$HOME/.MacOSX/environment.plist"
if [ -f "$envp" ]; then
  alert "Legacy environment.plist present (classic injection vector): $envp"
  /usr/libexec/PlistBuddy -c 'Print' "$envp" 2>/dev/null | sed 's/^/      /' | tee -a "$REPORT"
else
  ok "No ~/.MacOSX/environment.plist"
fi
dyld_hit=0
for dir in "${LAUNCH_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  for plist in "$dir"/*.plist; do
    [ -e "$plist" ] || continue
    envblock="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables' "$plist" 2>/dev/null)"
    if echo "$envblock" | grep -qi 'DYLD_'; then
      alert "launchd item injects DYLD_* into its target (library hijack): $(basename "$plist")"
      echo "$envblock" | grep -i 'DYLD_' | sed 's/^/        /' | tee -a "$REPORT"
      dyld_hit=1
    fi
  done
done
[ $dyld_hit -eq 0 ] && ok "No launchd items inject DYLD_* variables"

# =====================================================================
section "23. TRUSTED ROOT CERTIFICATES (TLS interception / MITM)"
# A root CA added to your keychain lets whoever holds its key silently
# decrypt your HTTPS traffic. A managed Mac may have one legitimately; on a
# personal machine, an unexpected user/admin-trusted root is a serious signal.
trust="$(security dump-trust-settings 2>/dev/null; [ $IS_ROOT -eq 1 ] && security dump-trust-settings -d 2>/dev/null)"
tcount="$(echo "$trust" | grep -icE 'Cert [0-9]+:')"
if [ "${tcount:-0}" -gt 0 ] 2>/dev/null; then
  alert "$tcount user/admin-added certificate trust setting(s) — confirm every one is expected:"
  echo "$trust" | grep -iE 'Cert [0-9]+:|SecTrustSettingsResult|Number of' | sed 's/^/    /' | tee -a "$REPORT"
else
  ok "No user/admin-added certificate trust settings (only Apple's default roots)"
fi

# =====================================================================
if [ "$WANT_DEEP" -eq 1 ]; then
  section "24. UNIFIED-LOG TRIAGE — suspicious spawns, last 12h (--deep)"
  # The unified log records process launches. We pull the last 12h and look
  # for the hallmarks of a live infection: things run from /tmp, osascript
  # driving a shell, or pipe-to-shell downloads. Time-capped so it can't hang.
  info "Scanning the unified log (bounded to ~30s)..."
  logtmp="$(mktemp "${TMPDIR:-/tmp}/machunt_log.XXXXXX")"
  run_capped 30 "$logtmp" log show --style syslog --last 12h \
    --predicate 'process == "osascript" OR eventMessage CONTAINS "/tmp/" OR eventMessage CONTAINS "curl " OR eventMessage CONTAINS "base64 -d"'
  susp="$(grep -iE '/tmp/|/var/tmp/|/Users/Shared/|osascript.*(do shell|curl|http)|curl.*\|[[:space:]]*(sh|bash)|base64[[:space:]].*-d' "$logtmp" 2>/dev/null \
          | grep -vE 'com\.apple|/System/|machunt|--predicate|--style syslog|eventMessage CONTAINS|log show' | head -40)"
  if [ -n "$susp" ]; then
    warn "Log lines worth a look (heuristic — may include benign developer activity):"
    echo "$susp" | sed 's/^/    /' | tee -a "$REPORT"
  else
    ok "No obviously-suspicious spawn patterns in the last 12h"
  fi
  rm -f "$logtmp"
fi

# =====================================================================
section "SUMMARY"

# ----- Tally findings by severity (from the single findings file) --------
CRIT_N="$(awk -F'\t' '$1=="crit"{n++} END{print n+0}' "$FIND_FILE")"
HIGH_N="$(awk -F'\t' '$1=="high"{n++} END{print n+0}' "$FIND_FILE")"
MED_N="$(awk  -F'\t' '$1=="med"{n++}  END{print n+0}' "$FIND_FILE")"
LOW_N="$(awk  -F'\t' '$1=="low"{n++}  END{print n+0}' "$FIND_FILE")"
FLAGS=$(( CRIT_N + HIGH_N ))          # "flagged for review" = critical + high

# ----- Security-posture score: 100 = nothing found, deduct per finding ---
DEDUCT=$(( CRIT_N*30 + HIGH_N*12 + MED_N*4 + LOW_N*1 ))
SCORE=$(( 100 - DEDUCT )); [ "$SCORE" -lt 0 ] && SCORE=0
if   [ "$SCORE" -ge 90 ]; then GRADE="A"; GCOL="$G"
elif [ "$SCORE" -ge 80 ]; then GRADE="B"; GCOL="$G"
elif [ "$SCORE" -ge 70 ]; then GRADE="C"; GCOL="$Y"
elif [ "$SCORE" -ge 60 ]; then GRADE="D"; GCOL="$Y"
else                           GRADE="F"; GCOL="$R"
fi

log ""
log "  ${BOLD}Security-posture score: ${GCOL}${SCORE}/100${N}${BOLD}  (grade ${GRADE})${N}"
log "  ${R}${CRIT_N} critical${N}   ${R}${HIGH_N} high${N}   ${Y}${MED_N} notes${N}   ${C}${LOW_N} low${N}"
log ""
if [ "$FLAGS" -eq 0 ]; then
  log "  ${G}${BOLD}No critical or high-severity findings in this pass.${N}"
  log "  Reassuring, but not a clean bill of health — review sections 2, 7, 8 and 9"
  log "  by hand, and re-run with sudo for full coverage."
else
  log "  A finding means 'look at this', NOT 'definitely malware'. Many are benign"
  log "  (legit Developer-ID apps, your own SSH, a VPN). Work through each one:"
  log "    • Unknown LaunchAgent/Daemon  → look up the label & program path"
  log "    • Unsigned running process     → identify the app; quit & quarantine if unknown"
  log "    • Unexpected outbound conn.    → map the remote IP/host to an app you trust"
  log ""
  log "  ${BOLD}Items flagged for review (critical first):${N}"
  awk -F'\t' '$1=="crit"' "$FIND_FILE" | while IFS="$(printf '\t')" read -r sev mod msg; do
    log "    ${R}${BOLD}⛔ [$mod]${N} $msg"
  done
  awk -F'\t' '$1=="high"' "$FIND_FILE" | while IFS="$(printf '\t')" read -r sev mod msg; do
    log "    ${R}🚩 [$mod]${N} $msg"
  done
fi
log ""
log "  Full report saved to: ${BOLD}$REPORT${N}"

# copy_to_desktop <file> <label> — mirror an artifact to the Desktop (unless --no-desktop)
copy_to_desktop() {
  [ "$NO_DESKTOP" -eq 0 ] || return 0
  local dst="$HOME/Desktop/$(basename "$1")"
  cp "$1" "$dst" 2>/dev/null && log "  ${G}$2 copied to your Desktop:${N} $dst"
}
copy_to_desktop "$REPORT" "Report"

# ----- HTML report generator (--html) -----------------------------------
htmlesc() { printf '%s' "$*" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
write_html() {
  local html="$1" gc host date_h priv
  case "$GRADE" in A|B) gc="#22c55e";; C|D) gc="#eab308";; *) gc="#ef4444";; esac
  host="$(scutil --get ComputerName 2>/dev/null || hostname)"
  date_h="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  priv="$( [ $IS_ROOT -eq 1 ] && echo 'root (deep scan)' || echo 'user' )"
  {
    cat <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>machunt report</title>
<style>
  :root{--bg:#0b0f17;--panel:#131a26;--panel2:#0f1521;--line:#1f2937;--txt:#e5e7eb;--mut:#94a3b8;
        --crit:#ef4444;--high:#f97316;--med:#eab308;--low:#38bdf8;--ok:#22c55e;--accent:#8b5cf6;}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       background:radial-gradient(1200px 600px at 20% -10%,#16223a 0,var(--bg) 55%) fixed;color:var(--txt)}
  .wrap{max-width:960px;margin:0 auto;padding:32px 20px 64px}
  header{display:flex;flex-wrap:wrap;gap:24px;align-items:center;justify-content:space-between;
         border:1px solid var(--line);background:linear-gradient(180deg,var(--panel),var(--panel2));
         border-radius:18px;padding:26px 28px;margin-bottom:24px}
  .brand{font-weight:800;letter-spacing:.14em;font-size:12px;color:var(--accent)}
  h1{margin:.25em 0 .15em;font-size:25px}
  .meta{color:var(--mut);font-size:13px}
  .gauge{width:132px;height:132px;border-radius:50%;flex:0 0 auto;display:grid;place-items:center;
         background:conic-gradient(var(--gc) calc(var(--v)*1%),#1e293b 0)}
  .gauge .inner{width:104px;height:104px;border-radius:50%;background:var(--panel2);display:grid;place-items:center;text-align:center}
  .gauge .score{font-size:30px;font-weight:800;line-height:1}
  .gauge .grade{font-size:11px;color:var(--mut);letter-spacing:.14em;margin-top:4px}
  .chips{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 24px}
  .chip{border:1px solid var(--line);border-radius:999px;padding:7px 14px;font-size:13px;font-weight:600;
        background:var(--panel);display:flex;gap:8px;align-items:center}
  .dot{width:9px;height:9px;border-radius:50%}
  .card{border:1px solid var(--line);background:var(--panel);border-radius:14px;margin:0 0 16px;overflow:hidden}
  .card h2{margin:0;font-size:14px;padding:13px 18px;background:var(--panel2);border-bottom:1px solid var(--line)}
  .card ul{list-style:none;margin:0;padding:4px 0}
  .card li{padding:9px 18px 9px 42px;position:relative;border-bottom:1px solid rgba(255,255,255,.03);font-size:14px}
  .card li:last-child{border-bottom:0}
  .card li::before{content:"";position:absolute;left:20px;top:14px;width:9px;height:9px;border-radius:50%}
  li.crit::before{background:var(--crit)} li.high::before{background:var(--high)}
  li.med::before{background:var(--med)}  li.low::before{background:var(--low)}
  .tag{font-size:10px;font-weight:800;letter-spacing:.05em;padding:2px 7px;border-radius:6px;color:#0b0f17;margin-right:6px}
  .tag.crit{background:var(--crit)} .tag.high{background:var(--high)}
  .tag.med{background:var(--med)}  .tag.low{background:var(--low)}
  .clean{border:1px dashed var(--line);border-radius:14px;padding:34px;text-align:center;color:var(--ok);font-weight:700}
  code{background:#0b1220;padding:1px 6px;border-radius:5px;color:#cbd5e1}
  footer{color:var(--mut);font-size:12px;margin-top:28px;text-align:center;line-height:1.8}
  a{color:var(--accent)}
</style></head><body><div class="wrap">
HTMLHEAD
    printf '<header><div><div class="brand">MACHUNT · macOS THREAT HUNT</div>'
    printf '<h1>Compromise assessment</h1>'
    printf '<div class="meta">Host <b>%s</b> &middot; %s &middot; privilege: %s &middot; read-only</div></div>' \
      "$(htmlesc "$host")" "$(htmlesc "$date_h")" "$priv"
    printf '<div class="gauge" style="--gc:%s;--v:%s"><div class="inner"><div class="score" style="color:%s">%s</div><div class="grade">GRADE %s</div></div></div>' \
      "$gc" "$SCORE" "$gc" "$SCORE" "$GRADE"
    printf '</header>\n'
    printf '<div class="chips">'
    printf '<div class="chip"><span class="dot" style="background:var(--crit)"></span>%s critical</div>' "$CRIT_N"
    printf '<div class="chip"><span class="dot" style="background:var(--high)"></span>%s high</div>' "$HIGH_N"
    printf '<div class="chip"><span class="dot" style="background:var(--med)"></span>%s medium</div>' "$MED_N"
    printf '<div class="chip"><span class="dot" style="background:var(--low)"></span>%s low</div></div>\n' "$LOW_N"
    if [ ! -s "$FIND_FILE" ]; then
      printf '<div class="clean">&#10003; No findings recorded in this pass. Re-run with <code>sudo</code> for full coverage.</div>\n'
    else
      awk -F'\t' '{print $2}' "$FIND_FILE" | awk '!seen[$0]++' | while IFS= read -r mod; do
        printf '<div class="card"><h2>%s</h2><ul>' "$(htmlesc "$mod")"
        for s in crit high med low; do
          awk -F'\t' -v m="$mod" -v sv="$s" '$1==sv && $2==m{print $3}' "$FIND_FILE" | while IFS= read -r msg; do
            [ -n "$msg" ] || continue
            printf '<li class="%s"><span class="tag %s">%s</span>%s</li>' \
              "$s" "$s" "$(printf '%s' "$s" | tr 'a-z' 'A-Z')" "$(htmlesc "$msg")"
          done
        done
        printf '</ul></div>\n'
      done
    fi
    printf '<footer>Generated by <b>machunt</b> &middot; read-only macOS threat hunting.<br>'
    printf 'A finding means &ldquo;look at this&rdquo;, not &ldquo;this is malware&rdquo;. '
    printf 'Second opinions: KnockKnock / LuLu / BlockBlock (<a href="https://objective-see.org">objective-see.org</a>).<br>'
    printf 'Score = 100 &minus; (crit&times;30 + high&times;12 + med&times;4 + low&times;1), floored at 0.</footer>'
    printf '</div></body></html>\n'
  } > "$html"
}
if [ "$WANT_HTML" -eq 1 ]; then
  HTML="${RUN_DIR}/machunt_report_${TS}.html"
  write_html "$HTML"
  log "  ${G}HTML report written to:${N} $HTML"
  copy_to_desktop "$HTML" "HTML report"
fi

# Optional machine-readable JSON summary (--json)
if [ "$WANT_JSON" -eq 1 ]; then
  JSON="${RUN_DIR}/machunt_summary_${TS}.json"
  {
    printf '{\n'
    printf '  "tool": "machunt",\n'
    printf '  "host": "%s",\n' "$(scutil --get ComputerName 2>/dev/null || hostname)"
    printf '  "scanned_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "privileged": %s,\n' "$( [ $IS_ROOT -eq 1 ] && echo true || echo false )"
    printf '  "report_file": "%s",\n' "$REPORT"
    printf '  "score": %s,\n' "$SCORE"
    printf '  "grade": "%s",\n' "$GRADE"
    printf '  "counts": { "critical": %s, "high": %s, "medium": %s, "low": %s },\n' "$CRIT_N" "$HIGH_N" "$MED_N" "$LOW_N"
    printf '  "findings": [\n'
    awk -F'\t' '
      function esc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); return s }
      NF>=3 { if (n++) printf ",\n";
              printf "    {\"severity\":\"%s\",\"module\":\"%s\",\"message\":\"%s\"}", esc($1), esc($2), esc($3) }
      END   { if (n) printf "\n" }
    ' "$FIND_FILE"
    printf '  ]\n'
    printf '}\n'
  } > "$JSON"
  log "  ${G}JSON summary written to:${N} $JSON"
  copy_to_desktop "$JSON" "JSON summary"
fi
log ""
log "  ${C}Next-step recommendations:${N}"
log "    1. Re-run with: ${BOLD}sudo ./machunt.sh${N}  (covers system daemons, TCC, all ports)"
log "    2. Cross-check any flagged binary on VirusTotal (hash it: shasum -a 256 <file>)"
log "    3. For a second opinion, run the open-source tools below."
log ""
log "  ${C}Recommended companion tools (free, reputable):${N}"
log "    • KnockKnock / BlockBlock / LuLu  — Objective-See (objective-see.org)"
log "        KnockKnock enumerates persistence; LuLu is an outbound firewall;"
log "        BlockBlock alerts in real time when something installs persistence."
log "    • Malwarebytes for Mac            — good at known adware/PUP removal."
log ""

exit 0
