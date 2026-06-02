# NoEsc: Linux Privilege Escalation Detector

**NoEsc** is a real-time privilege escalation detection tool for Linux systems. It uses a **Hybrid Detection Engine** that combines a deterministic C++ rule engine with a Python-based machine learning model (TF-IDF + SVM) to catch both known exploits and zero-day behavioral anomalies — piped directly from the Linux `auditd` subsystem.

> This project serves as an Undergraduate Special Problem (Thesis) for the BS Computer Science program at the **University of the Philippines Los Baños (UPLB)**, Institute of Computer Science.
>
> **Authors:** Klenn Jakek V. Borja and Joseph Anthony C. Hermocilla
> **Contact:** [kvborja@up.edu.ph](mailto:kvborja@up.edu.ph)

---

## Table of Contents

1. [Key Features](#key-features)
2. [Downloads & Resources](#downloads--resources)
3. [How It Works](#how-it-works)
4. [Quick Start (Automated Install)](#quick-start-automated-install)
5. [Manual Build Instructions](#manual-build-instructions)
6. [Configuration](#configuration)
7. [Engine Runtime Modes](#engine-runtime-modes)
8. [Live Mode Switching](#live-mode-switching)
9. [ML Listener Service](#ml-listener-service-systemd)
10. [Short-Window Companion Model](#short-window-companion-model)
11. [Maintenance Mode](#maintenance-mode-sudomisuse-notifications)
12. [Repository Structure](#repository-structure)
13. [ML Models & Results](#ml-models--results)
14. [Legal Disclaimer](#legal-disclaimer)
15. [License](#license)

---

## Key Features

- **Hybrid Engine**: C++ rule engine for instant deterministic alerts + Python ML bridge for behavioral anomaly detection, running in parallel.
- **Dual-Model ML Routing**: A primary long-window model (`v4_min3`) and a dedicated short-window companion model (`short_v1`) handle sequences of all lengths.
- **Process-Aware Whitelisting**: Configurable whitelist (`config/ml_process_whitelist.conf`) that skips known-benign system daemons to drastically reduce false positives.
- **Desktop Notifications**: Real-time `libnotify` popups when escalation or suspicious sequences are detected.
- **Live Mode Switching**: Hot-swap between `hybrid`, `ml-only`, and `rules-only` without restarting the daemon.
- **Maintenance Mode**: Suppresses `SudoMisuse` alerts during planned operator maintenance windows.

---

## Downloads & Resources

All large binary assets are hosted in the **[GitHub Releases](../../releases/latest)** page. Download and extract them before running the tool:

| Asset | Description | Where to extract |
|---|---|---|
| `NoEsc_Trained_Models.zip` | Pre-trained SVM + TF-IDF model artifacts for all model versions | Extract into `models/` in the project root |
| `NoEsc_Sample_Dataset.zip` | Raw `audit.log` dataset used for training and evaluation | Extract into `sample_set/` in the project root |
| `CMSC190_KJVBorja_SP.pdf` | Official research paper (UPLB SP manuscript) | — |

```bash
# After downloading from the Releases page:
unzip NoEsc_Trained_Models.zip -d models/
unzip NoEsc_Sample_Dataset.zip -d sample_set/
```

---

## How It Works

```
auditd  ──►  noesc_daemon (C++)
                │
                ├──► Rule Engine  ──► CRITICAL/WARNING alerts (instant)
                │
                └──► UDS Bridge  ──► ML Listener (Python)
                                          │
                                          ├──► v4_min3 model  (seq_len ≥ 3)
                                          └──► short_v1 model (seq_len 1–2)
                                                    │
                                                    └──► ML-DETECT alert + desktop notification
```

1. `auditd` feeds raw audit events into `noesc_daemon` via the audisp plugin interface.
2. The C++ **Rule Engine** evaluates each event immediately against deterministic heuristics (SUID abuse, sudo misuse, capability escalation, etc.).
3. The **UDS Bridge** simultaneously forwards event data over a Unix Domain Socket to the Python **ML Listener**.
4. The ML Listener groups events into per-PID sliding windows and routes them to the appropriate model based on sequence length.
5. Alerts from both engines trigger desktop notifications via `libnotify`.

---

## Quick Start (Automated Install)

The fastest way to get NoEsc running. Supports **Debian/Ubuntu-based** distributions:

```bash
git clone https://github.com/klenndacoder69/NoEsc.git
cd NoEsc
sudo ./scripts/install_daemon.sh
```

This script automatically:
- Installs system dependencies (`g++`, `auditd`, `libnotify`, etc.)
- Creates a Python virtual environment and installs ML requirements
- Compiles the C++ daemon
- Configures `systemd` and `auditd` to run NoEsc in the background

To fully remove a NoEsc deployment and restore `auditd`/`systemd` state:

```bash
sudo ./scripts/uninstall_daemon.sh
```

> **Note:** After installing, download `NoEsc_Trained_Models.zip` from the [Releases page](../../releases/latest) and extract it into the `models/` directory. The daemon will not start the ML bridge without model artifacts.

---

## Manual Build Instructions

For non-Ubuntu/Debian environments or manual control:

### 1. System Prerequisites

**Arch Linux:**
```bash
sudo pacman -S gcc make audit python python-pip libnotify
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc-c++ make audit python3 python3-pip libnotify dbus-x11
```

### 2. Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Compile the C++ Daemon

```bash
make clean
make
```

This uses the provided [Makefile](Makefile) to compile the C++ source and outputs the `noesc_daemon` executable in the project root.

---

## Configuration

All configuration files live in the [`config/`](config/) directory.

| File | Purpose |
|---|---|
| `config/noesc.conf` | auditd plugin configuration — points auditd at the daemon executable |
| `config/noesc.rules` | auditd rules — defines which syscalls and events to capture |
| `config/ml_process_whitelist.conf` | Process names that the ML bridge skips to avoid false positives |
| `config/suid_whitelist.conf` | SUID binaries that the rule engine ignores (known safe) |
| `config/noesc-ml-listener.service` | systemd unit file for the ML listener service |
| `config/ml_listener.env.example` | Example environment variable file for the ML listener |

**Basic setup:**

```bash
# 1. Install the auditd plugin config
sudo cp config/noesc.conf /etc/audit/plugins.d/

# 2. Install the auditd capture rules
sudo cp config/noesc.rules /etc/audit/rules.d/

# 3. Reload auditd
sudo service auditd reload
```

---

## Engine Runtime Modes

The daemon supports three detection paths, selectable at runtime:

| Mode | Behavior |
|---|---|
| `hybrid` *(default)* | Rule Engine + ML Bridge running in parallel |
| `ml-only` | ML Bridge only — no rule engine evaluation |
| `rules-only` | Rule Engine only — no ML bridge |

**CLI flags:**
```bash
./noesc_daemon --ml-only
./noesc_daemon --rules-only
./noesc_daemon --dump-json
```

**Environment variable override:**
```bash
NOESC_ENGINE_MODE=ml-only ./noesc_daemon
```

---

## Live Mode Switching

After running `install_daemon.sh`, NoEsc installs a live mode-switch helper:

```bash
sudo noesc-engine status
sudo noesc-engine hybrid
sudo noesc-engine ml-only
sudo noesc-engine rules-only
```

Each command rewrites `/etc/noesc/engine_mode` and reloads `auditd` so the plugin respawns with the new engine path — no manual restart needed.

---

## ML Listener Service (systemd)

`install_daemon.sh` installs a dedicated systemd service for the Python ML listener:

```bash
# Enable and start
sudo systemctl enable --now noesc-ml-listener

# Check health / live logs
sudo systemctl status noesc-ml-listener
sudo journalctl -u noesc-ml-listener -n 80 --no-pager

# Stop and disable
sudo systemctl disable --now noesc-ml-listener
```

**Running manually (without systemd):**
```bash
source .venv/bin/activate
python src/ml_engine/model_interface.py
```

**With short-sequence inference and dual-model routing:**
```bash
python src/ml_engine/model_interface.py \
   --short-seq-policy infer \
   --emit-benign \
   --emit-auth-only \
   --short-model-enabled \
   --short-model-max-seq-len 2 \
   --short-malicious-score-threshold 0.5
```

---

## Short-Window Companion Model

The short-window model (`short_v1`) handles PID windows with only 1–2 events, which the primary model (`v4_min3`) skips. To retrain it from scratch:

```bash
# Build short-window dataset and train
chmod +x scripts/ml/train_short_window_model.sh
./scripts/ml/train_short_window_model.sh
```

Outputs:
- Dataset: `sample_set/short_windows/`
- Model artifacts: `models/short_v1/`

---

## Maintenance Mode (SudoMisuse Notifications)

Suppresses `SudoMisuse` desktop alerts during planned maintenance windows:

```bash
sudo noesc-maint status
sudo noesc-maint on 30m
sudo noesc-maint on 1h30m
sudo noesc-maint until "2026-03-30 23:30:00"
sudo noesc-maint off
```

The helper writes a TTL file to `/etc/noesc/sudo_maintenance_mode.until`. The daemon reads this on each event and suppresses popups while the window is active.

---

## Repository Structure

All scripts must be invoked from the **project root directory** unless otherwise noted. Running scripts from inside their subdirectory will cause relative paths (e.g. `sample_set/`, `.venv/`, `models/`) to resolve incorrectly.

```
NoEsc/
├── src/
│   ├── daemon/             # C++ daemon source (main.cpp, parser, rule engine, UDS bridge)
│   └── ml_engine/          # Python ML source (model_interface.py, train_model.py, feature_contract.py)
│
├── scripts/
│   ├── install_daemon.sh   # Automated install (Debian/Ubuntu)
│   ├── uninstall_daemon.sh # Full removal and cleanup
│   ├── noesc-engine.sh     # Live mode-switch helper
│   ├── noesc-health.sh     # Service health check
│   ├── noesc-maint.sh      # Maintenance mode helper
│   ├── noesc-daemon-wrapper.sh         # auditd wrapper for the daemon
│   ├── noesc-ml-listener-launcher.sh   # systemd launcher for the ML listener
│   ├── export_logs.sh      # Export audit logs for analysis
│   ├── harvest_logs.sh     # Harvest audit logs from a running system
│   ├── rename_models.sh    # Utility to rename model artifact files
│   ├── lab/                # Research & dataset harvesting scripts (run from project root)
│   │   ├── execute_lab_breakout.sh     # Simulates malicious audit event sequences
│   │   ├── harvest_benign_data.sh      # Collects benign system activity data
│   │   ├── harvest_malicious_data.sh   # Collects malicious activity data
│   │   ├── setup_lab_vulns.sh          # Plants SUID backdoors for lab testing
│   │   ├── quick_test.sh               # Quick smoke test for the daemon
│   │   ├── test_daemon_safe.sh         # Safe daemon invocation test
│   │   └── collect_breakout_debug_logs.sh  # Diagnostics for lab breakout failures
│   ├── ml/                 # ML pipeline scripts
│   │   ├── train_short_window_model.sh # Trains the short-window companion model
│   │   ├── build_short_window_dataset.py
│   │   ├── replay_sample_set_to_ml_socket.py
│   │   ├── summarize_ml_listener_log.py
│   │   ├── pre_harvest_smoke_train.sh
│   │   └── verify_feature_contract.py
│   ├── eval/               # Evaluation and benchmarking scripts
│   │   ├── run_fairness_comparison.py
│   │   ├── build_fairness_input.sh
│   │   ├── ml_throughput.py
│   │   └── performance_benchmarks.sh
│   └── notification/       # Notification system test scripts
│
├── config/                 # All configuration files (auditd, systemd, whitelists)
│
├── models/
│   ├── v4_min3/            # Primary production model (TF-IDF + SVM, min 3 events/window)
│   └── short_v1/           # Short-window companion model (handles seq_len 1–2)
│   └── ...                 # Other model versions (artifacts in GitHub Release)
│
├── model_results/
│   └── training_reports.md # Consolidated training metrics for all model versions
│
├── out/
│   └── fairness_reports.md # Consolidated fairness comparison summaries
│
├── sample_set/             # Audit log dataset (download from GitHub Releases)
├── Makefile                # C++ daemon build system
├── requirements.txt        # Python dependencies
└── .gitignore
```

---

## ML Models & Results

The active production models used by the live engine are:

| Model | Path | Purpose | Training Samples | F1-Score |
|---|---|---|---|---|
| `v4_min3` | `models/v4_min3/` | Primary detection (seq_len ≥ 3) | 123,082 | 0.9983 |
| `short_v1` | `models/short_v1/` | Short-window detection (seq_len 1–2) | 29,433 | — |

Full training metrics and confusion matrices for all model versions: [`model_results/training_reports.md`](model_results/training_reports.md)

Fairness evaluation summaries (ML-only vs Rules-only across multiple dataset configurations): [`out/fairness_reports.md`](out/fairness_reports.md)

---

## Legal Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. You may only use NoEsc on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal and unethical. The authors assume no liability for misuse, damage, or legal consequences resulting from the unauthorized use of this tool.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
