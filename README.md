<div align="center">

```
███╗   ███╗ █████╗  ██████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
████╗ ████║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
██╔████╔██║███████║██║     ███████║██║   ██║██╔██╗ ██║   ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██║██║   ██║██║╚██╗██║   ██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║╚██████╔╝██║ ╚████║   ██║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
```

### 🛡️ macOS Threat Hunting &amp; Compromise Assessment

**A read-only scanner that hunts where macOS malware actually hides — and never touches a thing.**

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/macOS-12%E2%80%9315-000000.svg?style=flat-square&logo=apple)](#)
[![Shell](https://img.shields.io/badge/Pure_Bash-no_dependencies-4EAA25.svg?style=flat-square&logo=gnubash&logoColor=white)](#)
[![Read Only](https://img.shields.io/badge/Mode-100%25_read--only-0ea5e9.svg?style=flat-square)](#-safety-first)
[![Maintainer](https://img.shields.io/badge/by-Mobin_Erteghaie-8b5cf6.svg?style=flat-square)](https://github.com/mobinert)

</div>

---

## ⚡ Quick start

```bash
git clone https://github.com/mobinert/machunt.git
cd machunt
chmod +x machunt.sh

./machunt.sh          # user-level scan
sudo ./machunt.sh     # full scan — system daemons, all ports, TCC
./machunt.sh --html   # also emit a designed HTML report (open in any browser)
./machunt.sh --json   # also emit a machine-readable summary
./machunt.sh --deep   # add slower checks (unified-log triage of the last 12h)
```

The timestamped report is saved **in the directory you run the tool from**, and a copy is placed on your **Desktop** (disable with `--no-desktop`). Add `--html` for a self-contained visual report, or `--json` for a `machunt_summary_*.json`, alongside it. Every run also prints a **0–100 security-posture score** with a letter grade.

---

## 🎯 Why machunt?

Antivirus looks for *known* files. **machunt looks for the techniques** — the launch agents, signature anomalies, rogue DNS, and privacy grants that real macOS implants rely on. It assumes nothing, verifies the code signature of every persistence target, and tells you **exactly what to look at** without ever deleting, quarantining, or "fixing" anything behind your back.

> **A `[FLAG]` means *"look at this"*, not *"this is malware."*** You stay in control of every decision.

---

## 🔍 What it scans

| # | Module | What it catches |
|---|--------|-----------------|
| 1 | **Security posture** | SIP, FileVault, Firewall, Gatekeeper, Remote Login, Screen Sharing |
| 2 | **LaunchAgents / Daemons** | Every persistence plist — with **code-signature verification** of its target |
| 3 | **Login items &amp; background tasks** | `sfltool` background items, login-item helpers |
| 4 | **Cron · periodic · at · hooks · emond** | Classic & legacy scheduled-execution backdoors |
| 5 | **Configuration profiles** | MDM / stalkerware forced proxies, certs, locked settings |
| 6 | **Kernel &amp; system extensions** | Non-Apple kexts and active system extensions |
| 7 | **Running processes** | Live binaries that are unsigned or run from temp/shared dirs |
| 8 | **Network** | Listening ports + established outbound — *who is your Mac talking to?* |
| 9 | **DNS · hosts · proxy** | Traffic-hijacking redirects and silent interception |
| 10 | **Browser extensions** | Safari + Chromium adware / hijackers |
| 11 | **SUID / SGID binaries** | Privilege-escalation backdoors in writable paths |
| 12 | **Recently modified files** | Changes in persistence/config dirs (last 7 days) |
| 13 | **Shell &amp; environment** | Download-and-execute / reverse-shell lines in `*.rc` files |
| 14 | **Known-malware IOCs** | Documented bad paths + "masquerades-as-Apple" heuristic |
| 15 | **Privacy permissions (TCC)** 🆕 | Which apps hold **camera / mic / screen / full-disk** — the top spyware tell |
| 16 | **Quarantine / downloads** 🆕 | Recently downloaded executables and *where they came from* |
| 17 | **Baseline diff** | Fingerprints persistence and **alerts on anything new** between runs |
| 18 | **Local accounts &amp; sudo** 🆕 | Admin/hidden users + passwordless-sudo (`/etc/sudoers.d`) backdoors |
| 19 | **SSH trust** 🆕 | Planted keys in `authorized_keys` = silent persistent remote access |
| 20 | **Network neighborhood** | Default gateway, ARP table &amp; duplicate-MAC **MITM / ARP-spoof** check |
| 21 | **XProtect &amp; update freshness** 🆕 | XProtect / Remediator versions + whether **auto security-data updates** were silently disabled |
| 22 | **DYLD injection &amp; env persistence** 🆕 | `DYLD_INSERT_LIBRARIES` in launchd items + the legacy `~/.MacOSX/environment.plist` |
| 23 | **Trusted root certificates** 🆕 | User/admin-added root CAs — the classic **HTTPS interception** backdoor |
| 24 | **Unified-log triage** 🆕 `--deep` | Last-12h process spawns from temp dirs, `osascript`→shell, pipe-to-shell downloads |

Run `./machunt.sh --help` for all options.

---

## 🧪 The signature model (the core idea)

For every auto-run binary, machunt classifies the code signature:

| Verdict | Meaning |
|---------|---------|
| 🟢 `Apple-signed` | Shipped by Apple — expected |
| 🔵 `Developer ID` | A real vendor — *confirm it's one you installed* |
| 🟡 `Developer ID, NOT notarized` | Signed, but Apple never malware-scanned it — extra scrutiny |
| 🔴 `ad-hoc` / `unsigned` / `invalid` | **Common in malware — investigate** |

Persistence targets signed with a Developer ID are additionally checked for **notarization** (`spctl`) — Apple's malware scan. A real vendor's tool is almost always notarized; an un-notarized one is worth a second look.

---

## 📊 Security-posture score

Every run ends with a **0–100 score** and a letter grade, so you can track a machine over time at a glance. It starts at 100 and deducts per finding by severity:

```
score = 100 − (critical×30 + high×12 + medium×4 + low×1)      # floored at 0
```

| Severity | Examples |
|----------|----------|
| ⛔ **Critical** | SIP or Gatekeeper disabled, a hidden admin user, passwordless-sudo drop-in, a LoginHook, a known-bad IOC path |
| 🚩 **High** | Unsigned/ad-hoc auto-run binary, a DYLD-injecting launch item, an unexpected trusted root CA |
| ❓ **Medium** | Firewall off, an un-notarized Developer-ID persistence target, SSH enabled |

The same breakdown is written to the `--html` and `--json` outputs. **A high score is reassuring, not a clean bill of health** — always skim the flagged items yourself.

## 🛟 Safety first

- **Read-only by design.** No `rm`, no `kill`, no quarantine, no config changes — ever.
- **No dependencies.** Pure `bash` + tools already on macOS. Nothing is installed.
- **Nothing leaves your Mac.** No network calls, no telemetry. The report is yours alone.
- `.gitignore` keeps your own scan reports and baseline **out of git** by default.

---

## 📋 Reading the results

After a scan, work through the flags top-to-bottom. Most flags on a healthy Mac are benign (your VPN, a Developer-ID utility, your own SSH). For anything unfamiliar:

```bash
shasum -a 256 /path/to/suspicious/binary    # then look the hash up on VirusTotal
```

### Recommended companions
- **[Objective-See](https://objective-see.org)** — KnockKnock (persistence), **LuLu** (outbound firewall), BlockBlock (live alerts). The gold standard, free.
- **Malwarebytes for Mac** — quick known-adware cleanup.

---

## 🗺️ Roadmap

- [x] `--json` machine-readable output
- [x] Wi-Fi / ARP anomaly check
- [x] HTML report with severity grouping (`--html`)
- [x] Security-posture score + letter grade
- [x] Unified-log triage for suspicious spawns (`--deep`)
- [x] Notarization (`spctl`) check per persistence binary
- [x] XProtect / update-freshness, DYLD-injection &amp; trusted-cert checks
- [ ] `--baseline-accept` flag to update the baseline in one step
- [ ] Optional signed JSON export for fleet/SIEM ingestion

---

## 📄 License

[MIT](LICENSE) © 2026 **Mobin Erteghaie**

<div align="center">
<sub>Built for defenders. Use only on systems you own or are authorized to assess.</sub>
</div>
