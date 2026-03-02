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
