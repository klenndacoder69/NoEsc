# Linux Privilege Escalation Detector

## Project Overview

**NoEsc** is a specialized security tool designed to detect and identify privilege escalation attempts and vulnerabilities in Linux systems. This project serves as an Undergraduate Thesis for the Computer Science program at the University of the Philippines Los Baños (UPLB), Institute of Computer Science.

## Author

**Klenn Jakek V. Borja and Joseph Anthony C. Hermocilla**  
University of the Philippines Los Baños (UPLB)  
Institute of Computer Science  
Email: [kvborja@up.edu.ph](mailto:kvborja@up.edu.ph)

## Legal Disclaimer

This tool is provided for **educational and authorized security testing purposes only** as part of an undergraduate thesis at UPLB. 

**Important:** You may only use NoEsc on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal and unethical. The authors assume no liability for misuse, damage, or legal consequences resulting from the unauthorized use of this tool.

## Build Instructions

### Prerequisites
- `auditd` and `audispd-plugins`
- C++17 compliant compiler (g++ or clang)
- CMake (optional)

### Compiling the Daemon

**Option 1: Using CMake**
```bash
mkdir build && cd build
cmake ..
make
```

**Option 2: Using G++ Directly**
```bash
g++ -std=c++17 src/daemon/main.cpp src/daemon/parser.cpp src/daemon/rules_engine.cpp src/daemon/uds_bridge.cpp -o noesc_daemon -I src/daemon
```

## Configuration

1. Copy the plugin configuration:
   ```bash
   sudo cp config/noesc.conf /etc/audit/plugins.d/
   ```
2. Ensure the daemon executable is in the path specified in `noesc.conf` (default: `/usr/local/bin/noesc_daemon`).
3. Reload auditd:
   ```bash
   sudo service auditd reload
   ```

## Engine Runtime Modes

NoEsc daemon now supports selecting detection paths at runtime:

- Hybrid (default): Rule engine + ML bridge
- ML-only: ML bridge only (no rule-engine evaluation)
- Rules-only: Rule engine only (no ML bridge)

### CLI flags

```bash
./noesc_daemon --ml-only
./noesc_daemon --rules-only
./noesc_daemon --dump-json
```

### Environment override

Set `NOESC_ENGINE_MODE` to one of:

- `hybrid`
- `ml-only`
- `rules-only`

Example:

```bash
NOESC_ENGINE_MODE=ml-only ./noesc_daemon
```

## ML-only Deployment (No Rule Engine)

Use this flow to evaluate ML behavior in isolation:

1. Start ML listener:

```bash
source .venv/bin/activate
python src/ml_engine/model_interface.py
```

To reduce `skipped=min_events_gate` lines without retraining, run:

```bash
python src/ml_engine/model_interface.py --short-seq-policy infer --emit-benign
```

This keeps the configured minimum-events threshold for reporting, but still scores
short sequences (`seq_len < min_events_per_sequence`) and marks them with
`short_seq=inferred` in `ML-DETECT` output.

To surface USER_AUTH-only PID windows (no syscall sequence) in logs, add:

```bash
python src/ml_engine/model_interface.py --short-seq-policy infer --emit-benign --emit-auth-only
```

This emits `ML-AUTH-ONLY` lines with `auth_total`, `auth_failed`, and
`auth_fail_rate` when a PID window has authentication events but no syscall tokens.

2. Run daemon in ML-only mode:

```bash
./noesc_daemon --ml-only
```

If running through auditd plugin path, point plugin `path` to a wrapper that
executes daemon with `--ml-only`, or set `NOESC_ENGINE_MODE=ml-only` in the
auditd service environment.

## Short-Window Companion Model Workflow

Use this when most live windows are `seq_len` 1-2 and you want a dedicated
short-window ML companion model.

1. Build short-window dataset and train short model:

```bash
chmod +x scripts/ml/train_short_window_model.sh
./scripts/ml/train_short_window_model.sh
```

2. Outputs:

- Dataset: `sample_set/short_windows/`
- Stats: `sample_set/short_windows/short_window_dataset_stats.json`
- Model artifacts: `models/short_v1/`

3. Run listener with dual-model routing (long model for full sequences,
short model for seq_len 1-2):

```bash
python src/ml_engine/model_interface.py \
   --short-seq-policy infer \
   --emit-benign \
   --emit-auth-only \
   --short-model-enabled \
   --short-model-max-seq-len 2 \
   --short-malicious-score-threshold 0.5
```

Use `--short-malicious-score-threshold` to calibrate short-window alerts. Short-model
predictions with `pred=1` but `score<threshold` are demoted to benign at runtime.
This keeps long-window behavior unchanged while reducing noisy short-window alerts.

4. Summarize listener fairness/coverage after replay:

```bash
python scripts/ml/summarize_ml_listener_log.py --log final_ml_listener.log
```

## Maintenance Mode (SudoMisuse Notifications)

NoEsc supports an operator maintenance window for SudoMisuse desktop notifications.

After installation, use:

```bash
sudo noesc-maint status
sudo noesc-maint on 30m
sudo noesc-maint on 1h30m
sudo noesc-maint until "2026-03-30 23:30:00"
sudo noesc-maint off
```

Notes:
- The helper writes the TTL file used by the daemon: `/etc/noesc/sudo_maintenance_mode.until`.
- The daemon checks this state periodically and suppresses SudoMisuse desktop popups while active.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
