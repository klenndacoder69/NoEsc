# NoEsc Lab Setup Runbook (Start to Finish)

This is the single canonical command file for deploying and operating NoEsc in a computer laboratory.

## 0) Scope

This runbook covers:
- Fresh machine setup (Ubuntu 24.04.3 LTS)
- Build + deploy NoEsc daemon and ML listener
- Environment file model (`/etc/noesc/ml_listener.env` and project `.env`)
- Verification of successful deployment
- Daily execution commands
- Replay/test commands for both rules and ML paths
- Common troubleshooting commands

## 1) Machine Prerequisites (Run Once Per Lab PC)

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  g++ \
  make \
  cmake \
  auditd \
  audispd-plugins \
  python3 \
  python3-venv \
  python3-pip \
  libglib2.0-bin \
  ripgrep
```

Confirm baseline tools:

```bash
g++ --version
python3 --version
sudo systemctl status auditd --no-pager
```

## 2) Get Project on the Machine

If cloning fresh:

```bash
cd /home/$USER
git clone <YOUR_REPO_URL> NoEsc
cd /home/$USER/NoEsc
```

If already present, update it:

```bash
cd /home/$USER/NoEsc
git pull
```

## 3) Python Environment and ML Dependencies

```bash
cd /home/$USER/NoEsc
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Sanity check:

```bash
python -c "import joblib, numpy, pandas, scipy, sklearn; print('python-ml-deps-ok')"
```

## 4) Build and Deploy NoEsc (audisp plugin + systemd service)

```bash
cd /home/$USER/NoEsc
make clean
make
sudo ./scripts/install_daemon.sh
```

What this installs:
- `/usr/local/bin/noesc_daemon`
- `/usr/local/bin/noesc-daemon-wrapper`
- `/usr/local/bin/noesc-engine`
- `/usr/local/bin/noesc-ml-listener-launcher`
- `/etc/audit/plugins.d/noesc.conf`
- `/etc/systemd/system/noesc-ml-listener.service`
- `/etc/noesc/engine_mode`
- `/etc/noesc/ml_listener.env`
- Project `.env` (seeded once)

## 5) Environment Model (Important)

`noesc-ml-listener-launcher` loads env files in this order:
1. `/etc/noesc/ml_listener.env`
2. `<project-root>/.env`
3. `<project-root>/.env.local`
4. `<project-root>/config/ml_listener.env`

Practical recommendation for lab use:
- Keep lab defaults in project `.env`
- Use `/etc/noesc/ml_listener.env` only when you want machine-specific overrides

Create project `.env` from current deployed env if missing:

```bash
cd /home/$USER/NoEsc
[ -f .env ] || cp /etc/noesc/ml_listener.env .env
```

Set ML notification controls in project `.env`:

```bash
cd /home/$USER/NoEsc

grep -q '^NOESC_ML_NOTIFY_MALICIOUS=' .env \
  && sed -i 's/^NOESC_ML_NOTIFY_MALICIOUS=.*/NOESC_ML_NOTIFY_MALICIOUS=1/' .env \
  || echo 'NOESC_ML_NOTIFY_MALICIOUS=1' >> .env

grep -q '^NOESC_ML_NOTIFY_COOLDOWN_SECONDS=' .env \
  && sed -i 's/^NOESC_ML_NOTIFY_COOLDOWN_SECONDS=.*/NOESC_ML_NOTIFY_COOLDOWN_SECONDS=2.0/' .env \
  || echo 'NOESC_ML_NOTIFY_COOLDOWN_SECONDS=2.0' >> .env

grep -q '^NOESC_ML_NOTIFY_CLOSE_SECONDS=' .env \
  && sed -i 's/^NOESC_ML_NOTIFY_CLOSE_SECONDS=.*/NOESC_ML_NOTIFY_CLOSE_SECONDS=5.0/' .env \
  || echo 'NOESC_ML_NOTIFY_CLOSE_SECONDS=5.0' >> .env
```

Review effective key values:

```bash
cd /home/$USER/NoEsc
rg -n '^NOESC_PROJECT_ROOT|^NOESC_PYTHON_BIN|^NOESC_ML_NOTIFY_MALICIOUS|^NOESC_ML_NOTIFY_COOLDOWN_SECONDS|^NOESC_ML_NOTIFY_CLOSE_SECONDS' /etc/noesc/ml_listener.env .env
```

## 6) Start Services and Set Engine Mode

```bash
cd /home/$USER/NoEsc
sudo systemctl daemon-reload
sudo systemctl enable --now noesc-ml-listener
sudo noesc-engine ml-only
sudo noesc-engine status
```

If you want hybrid mode for normal operation:

```bash
sudo noesc-engine hybrid
sudo noesc-engine status
```

## 7) Verification Checklist (Must Pass)

Service health:

```bash
sudo systemctl status noesc-ml-listener --no-pager
```

Audit plugin config:

```bash
sudo grep -n '^path' /etc/audit/plugins.d/noesc.conf
```

Socket availability:

```bash
sudo ss -xl | rg /tmp/noesc_ml.sock
ls -l /tmp/noesc_ml.sock
```

Startup logs:

```bash
sudo journalctl -u noesc-ml-listener -o cat -n 120 --no-pager | rg -n 'NoEsc ML listener bound|Listener min-events-per-sequence|ML malicious desktop notification enabled'
```

## 8) Daily Operations (Execution Commands)

Engine mode switching:

```bash
sudo noesc-engine rules-only
sudo noesc-engine ml-only
sudo noesc-engine hybrid
sudo noesc-engine status
```

Live ML stream (Terminal 1):

```bash
sudo journalctl -u noesc-ml-listener -f -o cat --no-pager | rg --line-buffered -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]'
```

Replay audit log through daemon ML path (Terminal 2):

```bash
cd /home/$USER/NoEsc
sudo bash -c '
head -n 5000 sample_set/audit.log.1 | while IFS= read -r line; do
  printf "%s\n" "$line"
  sleep 0.002
done | ./noesc_daemon --ml-only > /var/tmp/noesc_ml_replay.out 2>&1
'
```

Verify replay results (Terminal 3):

```bash
cd /home/$USER/NoEsc
sudo journalctl -u noesc-ml-listener -o cat --since "2 min ago" --no-pager | rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]' | head -n 40
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" /var/tmp/noesc_ml_replay.out
```

## 9) High-Confidence ML Replay Test (Direct Socket)

This bypasses audit plugin pacing and directly validates listener inference + notifications.

```bash
cd /home/$USER/NoEsc
cat sample_set/audit.log.1 | ./noesc_daemon --dump-json >/tmp/noesc_dump.ndjson 2>/tmp/noesc_dump.err
head -n 400 /tmp/noesc_dump.ndjson > /tmp/noesc_small.ndjson

sudo /home/$USER/NoEsc/.venv/bin/python scripts/ml/replay_sample_set_to_ml_socket.py \
  --input /tmp/noesc_small.ndjson \
  --socket-path /tmp/noesc_ml.sock \
  --delay-ms 5 \
  --cycles 1

sudo journalctl -u noesc-ml-listener -o cat -n 200 --no-pager | rg -n 'ML-DETECT.*label=MALICIOUS|ML notification dispatch failed|ML notification: could not resolve active graphical user session'
```

## 10) Rules Path Tests

Quick rule detection test:

```bash
cd /home/$USER/NoEsc
./quick_test.sh
```

Safe rule test:

```bash
cd /home/$USER/NoEsc
./test_daemon_safe.sh
```

Rules notification smoke test:

```bash
cd /home/$USER/NoEsc
./scripts/notification/test_notification.sh
```

## 11) ML Notification-Specific Tests

Direct desktop bus probe (should return `(uint32 N,)` and show popup):

```bash
gdbus call --session \
  --dest org.freedesktop.Notifications \
  --object-path /org/freedesktop/Notifications \
  --method org.freedesktop.Notifications.Notify \
  'NoEsc' 0 'dialog-error' 'NoEsc gdbus probe' 'Typed timeout + urgency hints' "[]" "{'urgency': <byte 2>}" "int32 5000"
```

Close-notification probe example (replace `N`):

```bash
gdbus call --session \
  --dest org.freedesktop.Notifications \
  --object-path /org/freedesktop/Notifications \
  --method org.freedesktop.Notifications.CloseNotification "uint32 N"
```

## 12) Troubleshooting Commands

No popup, but MALICIOUS exists in logs:

```bash
sudo journalctl -u noesc-ml-listener -o cat -n 200 --no-pager | rg -n 'ML-DETECT.*label=MALICIOUS|ML malicious desktop notification enabled|ML notification dispatch failed|ML notification: could not resolve active graphical user session'
```

Force restart after env/code changes:

```bash
sudo systemctl restart noesc-ml-listener
sudo systemctl status noesc-ml-listener --no-pager
```

If socket replay shows permission denied, use sudo for replay script:

```bash
sudo /home/$USER/NoEsc/.venv/bin/python /home/$USER/NoEsc/scripts/ml/replay_sample_set_to_ml_socket.py --input /tmp/noesc_small.ndjson --socket-path /tmp/noesc_ml.sock --delay-ms 5 --cycles 1
```

Check installed launcher version if behavior is stale:

```bash
cd /home/$USER/NoEsc
sudo install -m 755 scripts/noesc-ml-listener-launcher.sh /usr/local/bin/noesc-ml-listener-launcher
sudo systemctl restart noesc-ml-listener
```

## 13) Lab Rollout Pattern (Many Machines)

Repeat on each PC:
1. Section 1
2. Section 2
3. Section 3
4. Section 4
5. Section 5
6. Section 6
7. Section 7

For demo day on each PC:
1. Terminal 1: run live stream command (Section 8)
2. Terminal 2: run replay command (Section 8)
3. Terminal 3: run verification command (Section 8)

## 14) Final Sanity Snapshot (One Command Block)

```bash
cd /home/$USER/NoEsc

sudo noesc-engine status
sudo systemctl status noesc-ml-listener --no-pager | head -n 30
sudo ss -xl | rg /tmp/noesc_ml.sock

rg -n '^NOESC_ML_NOTIFY_MALICIOUS|^NOESC_ML_NOTIFY_COOLDOWN_SECONDS|^NOESC_ML_NOTIFY_CLOSE_SECONDS' .env /etc/noesc/ml_listener.env

sudo journalctl -u noesc-ml-listener -o cat -n 80 --no-pager | rg -n 'NoEsc ML listener bound|ML malicious desktop notification enabled|^\[ML-DETECT\]'
```
