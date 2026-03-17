# NoEsc Paper Revisions Tracker

This document tracks implementation details that deviate from the original thesis proposal (`paper/CMSC190_KJVBorja_SP1.pdf`). Use this as a reference when revising the paper for the final manuscript.

## 1. Stateless Heuristic: SUID/SGID Abuse Detection

**Original Proposal (Section G):**
> "The executable’s path (exe) is located in a non-standard or world-writable directory, such as: `/tmp`, `/var/tmp`, `/home`." (Blacklist Approach)

**Implemented Logic:**
> "The executable’s path (exe) is **NOT** located in a standard system binary directory: `/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`." (Strict Whitelist Approach)

**Reason for Change:**
The original blacklist approach is brittle. An attacker could bypass detection by placing the malicious SUID binary in other writable directories like `/dev/shm`, `/opt`, or `/usr/local/games`. The strict whitelist ensures that ANY privileged execution from a non-standard location is flagged, significantly reducing False Negatives with minimal impact on False Positives in a standard environment.

## 2. Sandbox Exception for Academic Use

**Original Proposal:**
> Did not specify a safe location for user-created SUID binaries.

**Implemented Logic:**
> Added `/opt/student_sandbox/` to the SUID whitelist.

**Reason for Change:**
In a university laboratory setting (e.g., Operating Systems classes), students may be required to develop and execute their own SUID programs. Blocking all non-system SUID binaries would disrupt coursework. By designating a specific sandbox directory, we balance security (blocking `/home` and `/tmp`) with academic utility.

## 3. Package Management Compatibility (Known Limitation)

**Issue:**
Package managers like `apt` or `dpkg` may execute temporary configuration scripts (e.g., `.postinst` scripts) from `/tmp` or `/var/lib/dpkg/tmp` during package installation or upgrades.

**Impact:**
These scripts run as root (`euid=0`) but are technically initiated by the user (`auid=1000` via `sudo`). Since they reside in `/tmp` (which is not in our Strict Whitelist), the detector will flag them as malicious SUID abuse. This creates False Positives during system maintenance.

**Future Mitigation:**
The system should implement **Parent Process Tracking**. Before alerting, the engine should check if the parent process (`ppid`) is a known package manager (e.g., `dpkg`, `apt`, `snapd`) and whitelist the child process execution.

## 4. Sensitive File Tampering Logic Correction

**Original Proposal (Section I):**
> "Alert will be generated if... the action initiated by the process has an `auid` of 0 (root)."

**Implemented Logic:**
> Alert if the process has an `euid` **NOT EQUAL** to 0 (Non-Root).

**Reason for Change:**
The original text likely contained a typo. Alerting on Root modifications would flag legitimate administrative actions (e.g., `useradd`, `passwd`). The goal is to detect *unauthorized* tampering, which occurs when a non-root process attempts to write to these files (indicating a permission bypass or misconfiguration).

## 5. Stateless Engine Data Extraction Limitation (Methodology Note)

**Original Assumption:**
The paper implies the heuristic engine can easily read the plain-text target filename (e.g., `/etc/passwd`) directly from a single event to determine what was touched.

**Implemented Reality:**
The Linux `auditd` framework splits complex events across multiple log lines. The `SYSCALL` record contains the User IDs and Process execution data, but the plain-text filename is often placed in a separate `PATH` record. Because our daemon parses logs statelessly (line-by-line for high performance), it cannot natively link the `PATH` string back to the `SYSCALL` alert without complex memory aggregation.

**Mitigation Implemented:**
Instead of building a heavy, stateful log aggregator, the engine extracts the raw system call arguments (`a0`, `a1`), the Process ID (`pid`), and the Parent Process ID (`ppid`). The engine alerts the admin using the `key` field to identify the targeted file category (e.g., `identitychange`), and provides the `pid` so the admin can use `ausearch -p <pid> -i` to instantly retrieve the full, human-readable context from the raw kernel logs.

## 6. Dedicated Alert Logging (Architecture Design)

**Original Proposal:**
Did not specify the exact alerting output mechanism of the user-space daemon.

**Implemented Logic:**
The daemon now appends all alerts to a dedicated, restricted file: `/var/log/noesc_alerts.log` (Permissions: 600). This prevents alerts from being buried in standard system logs (`syslog` or `journalctl`), providing the administrator with a clean, centralized security dashboard.

## 7. Stateful Sudo Misuse Tuning (Operational Heuristic)

**Original Proposal (Section H):**
> "On a successful sudo execution of a high-risk command: Increment the user's score by +10." (With a threshold of 20).

**Implemented Logic:**
> High-risk command execution score increment lowered from +10 to +5.

**Reason for Change:**
The original +10 scoring meant that running just two legitimate administrative commands (e.g., `sudo cp` followed by `sudo systemctl restart`) within a 60-second window would immediately trigger a False Positive alert. In an academic/laboratory environment where students frequently debug server configurations, this strict threshold causes severe Alert Fatigue. Lowering the increment to +5 requires four rapid-fire `sudo` commands to trigger the threshold, effectively distinguishing between a human debugging a system and an automated exploitation script.
