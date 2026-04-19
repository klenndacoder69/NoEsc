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

2. Run daemon in ML-only mode:

```bash
./noesc_daemon --ml-only
```

If running through auditd plugin path, point plugin `path` to a wrapper that
executes daemon with `--ml-only`, or set `NOESC_ENGINE_MODE=ml-only` in the
auditd service environment.

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
