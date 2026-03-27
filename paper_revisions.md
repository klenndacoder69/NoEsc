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

## 8. Multi-Tier Alert Architecture (Operational Enhancement)

**Original Proposal:**
Alert output mechanism not specified beyond basic detection.

**Implemented Architecture:**
NoEsc now employs a **4-tier alert delivery system** to ensure comprehensive coverage for different operational scenarios:

1. **STDERR (Console)**: Real-time alert display for manual testing and debugging
2. **Dedicated Log File** (`/var/log/noesc_alerts.log` or `./noesc_alerts.log`): Persistent forensic record with fallback for non-root testing
3. **Syslog Integration** (`openlog()` / `syslog()`): System-wide logging for enterprise monitoring (journald/rsyslog compatible)
4. **Desktop Notifications** (`notify-send` via D-Bus): Visual alerts for development and testing environments

**Rationale:**
- **Channel 1+2**: Ensures alerts are never lost (console + persistent file)
- **Channel 3**: Industry-standard integration with SIEM systems, log aggregators (Splunk, ELK), and centralized monitoring
- **Channel 4**: Immediate visual feedback during development, testing, and demonstrations (thesis defense)

**Technical Implementation:**
- Syslog facility: `LOG_AUTH` (authentication/security subsystem)
- Desktop notifications: Auto-detects logged-in graphical user, sends via their D-Bus session (works when daemon runs as root)
- Cross-platform compatibility: `syslog()` API works with both traditional rsyslog and modern journald

## 9. Context-Aware Alert Severity (Path-Based Risk Assessment)

**Original Proposal:**
All SUID abuse detections treated with uniform severity.

**Implemented Logic:**
NoEsc implements **path-based severity classification** to reduce false positive alert fatigue in academic environments:

**High-Risk Paths (CRITICAL Severity):**
- `/tmp/` - World-writable temporary directory (common attack vector)
- `/dev/shm/` - Shared memory filesystem (often used for in-memory exploits)
- `/var/tmp/` - Persistent temporary storage
- Unknown paths - Default to critical (fail-safe)

**Medium-Risk Paths (WARNING Severity):**
- `/home/` - User home directories (may contain student coursework)
- `/opt/` - Optional software installations (may contain legitimate custom applications)

**Impact on Alerting:**
- CRITICAL alerts → Trigger all 4 alert channels (including desktop notification)
- WARNING alerts → Logged to file and syslog, but **suppress desktop notification**
- All alerts remain in forensic logs for post-incident analysis

**Rationale:**
Students compiling and testing SUID programs for Operating Systems coursework (e.g., in `/home/student/cs415/`) should not generate disruptive desktop notifications that cause alert fatigue. However, the behavior is still logged (WARNING severity) for administrator review. Genuine attacks from `/tmp/` remain immediately visible (CRITICAL).

**Research Contribution:**
This context-aware approach addresses the challenge of deploying HIDS in academic environments where "anomalous" behavior may be legitimate coursework. The path-based heuristic provides a balance between security and usability.

## 10. Progressive Alerting for Stateful Sudo Misuse

**Original Proposal (Section H):**
Single threshold alert when score reaches 20 points.

**Implemented Logic:**
**Two-tier progressive alerting system:**
- **WARNING threshold** (15/20 points): Early warning alert
  - Logged to file and syslog
  - Desktop notification suppressed
  - Message: "Sudo Score Alert! User approaching threshold (Score: 15/20)"
  
- **CRITICAL threshold** (20/20 points): Threat confirmed
  - Logged to all channels
  - Desktop notification triggered
  - Score reset to 0 to prevent alert flooding
  - Message: "Stateful Sudo Misuse Detected! Suspicion Score reached 20/20"

**Rationale:**
Progressive alerting provides **defense-in-depth** with early warning capabilities:
1. Admins receive advance notice at 15 points (3 dangerous commands)
2. Can observe user behavior before full alert triggers
3. Reduces "surprise" CRITICAL alerts when legitimate admin work crosses threshold
4. Maintains full forensic trail (both WARNING and CRITICAL logged)

**Example Scenario:**
- Legitimate sysadmin: `chmod` → `chown` → `chmod` (15 pts, WARNING only)
- Attacker script: adds 4th command → CRITICAL alert with desktop notification
- Distinction: Human work pattern vs. automated exploitation

## 11. Alert Severity Labeling in Logs

**Original Proposal:**
Log format not explicitly specified.

**Implemented Log Format:**
```
[timestamp] SEVERITY ALERT [Vector]: Message | Context | Investigation
```

**Example:**
```
[3000000001.001] CRITICAL ALERT [PrivilegeEscalation]: SUID Abuse Detected! 
  User 1000 escalated to ROOT via /tmp/evil | Rule_Key=benign_priv | 
  User=1000 (euid=0) | Process=/tmp/evil (pid=5001) | 
  INVESTIGATE: ausearch -a 1 -i (exact event)
```

**Severity Levels:**
- `CRITICAL`: Immediate threat requiring investigation
- `WARNING`: Suspicious behavior requiring monitoring
- `INFO`: Informational events (future use)

**Rationale:**
Explicit severity labels enable:
- Log filtering (`grep CRITICAL noesc_alerts.log`)
- SIEM rule configuration (e.g., "trigger incident on CRITICAL")
- Compliance reporting (PCI-DSS requires severity classification)
- Machine learning feature extraction (severity as categorical variable)

## 12. Desktop Notification Stacking Prevention

**Implementation Detail:**
Desktop notifications sent with 150ms inter-notification delay (`usleep(150000)`).

**Problem Addressed:**
When multiple attack vectors trigger simultaneously (e.g., SUID abuse + file tampering + sudo misuse), sending all desktop notifications at once (0ms delay) can cause notification daemon to replace/overlay notifications, showing only the last alert.

**Solution:**
Sequential notification dispatch with 150ms spacing ensures each alert is registered by the notification daemon (dunst, notify-osd, etc.) and displayed in a stacked/queued manner.

**Performance Impact:**
Worst case: 3 simultaneous alerts = 450ms total delay. This is imperceptible for security alerting and ensures all critical threats are visible.

## 13. Event ID-Based Investigation Commands

**Original Proposal:**
Alerts provided PID for forensic lookup.

**Implemented Enhancement:**
Alerts now prioritize **Event Serial Number** over PID for investigation commands:

```
INVESTIGATE: ausearch -a <event_id> -i (exact event)
```

**Fallback:** If serial number unavailable, provide PID:
```
INVESTIGATE: ausearch -p <pid> -i
```

**Reason for Change:**
**PIDs are reused by the Linux kernel**. After a process exits, the PID becomes available for new processes. Using `ausearch -p <PID>` can return unrelated historical events with the same PID, confusing forensic analysis.

**Event Serial Numbers are unique and monotonically increasing** - they permanently identify a specific audit event and are never reused.

**Impact:**
More reliable forensic investigation, especially in long-running systems where PID wraparound occurs.

## 14. Alert Cooldown Mechanism

**Implementation Detail:**
Per-user, per-vector cooldown period: 10 seconds.

**Purpose:**
Prevent alert flooding when the same attack vector triggers repeatedly (e.g., attacker script retrying SUID binary in a loop).

**Behavior:**
- First detection: Alert generated immediately
- Subsequent detections (same user, same vector, within 10 seconds): Suppressed
- After 10 seconds: Next alert allowed

**Rationale:**
Balance between **responsiveness** (immediate first alert) and **log hygiene** (prevent thousands of duplicate alerts from automated attacks). All events remain in auditd logs; only NoEsc alerts are rate-limited.

**Configuration:**
Adjustable via `ALERT_COOLDOWN_SECS` constant in `rules_engine.h`.

## 15. Syslog vs Auditd Architectural Clarification

**Clarification for Paper:**
The system uses **two different logging mechanisms** for distinct purposes:

**Auditd (INPUT Source):**
- Kernel-level security auditing framework
- Records all system calls, file access, process execution
- NoEsc daemon reads from auditd via audispd plugin (STDIN)
- Provides comprehensive, tamper-proof event stream
- Required for compliance (PCI-DSS, HIPAA)

**Syslog (OUTPUT Destination):**
- Application-level centralized logging service
- NoEsc daemon writes alerts to syslog via `syslog()` API
- Enables integration with SIEM systems, log aggregators
- Standard practice for all Linux security daemons
- Compatible with both traditional rsyslog and modern journald

**Data Flow:**
```
System Activity → Auditd (kernel) → Audispd → NoEsc (detection) → Syslog (alerting)
```

**Paper Section Recommendation:**
Include architectural diagram in "System Design" section showing this dual-logging approach. Emphasize that auditd provides **forensic-quality input** while syslog provides **operational alerting output**.

## Summary of Revisions Impact

### Methodology Enhancements:
- Path-based severity (Revision 9)
- Progressive alerting (Revision 10)
- Alert cooldown (Revision 14)

### Operational Features:
- Multi-tier alerting (Revision 8)
- Desktop notifications (Revision 8)
- Severity labeling (Revision 11)
- Event ID forensics (Revision 13)

### Academic Environment Adaptations:
- Reduced false positives for student coursework (Revision 9)
- Alert fatigue mitigation (Revisions 9, 10, 12)
- Configurable notification filtering (Revision 8)

### Thesis Contributions:
These enhancements address **real-world deployment challenges** in academic HIDS:
1. Alert fatigue in educational environments
2. Balance between security and usability
3. Context-aware threat classification
4. Integration with existing enterprise monitoring infrastructure

**Recommendation:** Add a subsection titled "Alert Fatigue Mitigation Strategies" in the paper discussing how context-aware severity and progressive alerting reduce false positive impact while maintaining detection coverage.
