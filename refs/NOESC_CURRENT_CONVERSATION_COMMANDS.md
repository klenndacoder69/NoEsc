# NoEsc Current Conversation Commands

Use this file as the canonical command source for this conversation.

## 1) Deploy and Service Bring-Up

```bash
cd /home/swuffles/Documents/NoEsc
sudo ./scripts/install_daemon.sh
sudo noesc-engine ml-only
sudo systemctl enable --now noesc-ml-listener
sudo noesc-engine status
sudo systemctl status noesc-ml-listener --no-pager
```

## 2) Validate ML Listener Health

```bash
cd /home/swuffles/Documents/NoEsc
sudo ss -xl | rg /tmp/noesc_ml.sock
sudo journalctl -u noesc-ml-listener -o cat -n 80 --no-pager
sudo journalctl -u noesc-ml-listener -o cat --since "10 min ago" --no-pager | rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]' | head -n 30
```

## 3) Live Stream ML Decisions (Terminal 1)

```bash
sudo journalctl -u noesc-ml-listener -f -o cat --no-pager | rg --line-buffered -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]'
```

## 4) Pacing Replay Through Daemon ML-Only (Terminal 2)

```bash
cd /home/swuffles/Documents/NoEsc
sudo bash -c '
head -n 5000 sample_set/audit.log.1 | while IFS= read -r line; do
  printf "%s\n" "$line"
  sleep 0.002
done | ./noesc_daemon --ml-only > /var/tmp/noesc_ml_replay.out 2>&1
'
```

## 5) Post-Replay Verification (Terminal 3)

```bash
cd /home/swuffles/Documents/NoEsc
sudo journalctl -u noesc-ml-listener -o cat --since "2 min ago" --no-pager | rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]' | head -n 30
sudo journalctl -u noesc-ml-listener -o cat --since "10 min ago" --no-pager | grep -c '^\[ML-DETECT\]'
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" /var/tmp/noesc_ml_replay.out
```

## 6) ML-DETECT Delta Counter

```bash
cd /home/swuffles/Documents/NoEsc
before=$(sudo journalctl -u noesc-ml-listener -o cat --since "10 min ago" --no-pager | grep -c '^\[ML-DETECT\]')

sudo bash -c '
head -n 5000 sample_set/audit.log.1 | while IFS= read -r line; do
  printf "%s\n" "$line"
  sleep 0.002
done | ./noesc_daemon --ml-only > /var/tmp/noesc_ml_replay.out 2>&1
'

sleep 3
after=$(sudo journalctl -u noesc-ml-listener -o cat --since "10 min ago" --no-pager | grep -c '^\[ML-DETECT\]')
echo "ml_detect_before=$before ml_detect_after=$after delta=$((after-before))"
```

## 7) Direct Socket Replay Proof (High Confidence)

```bash
cd /home/swuffles/Documents/NoEsc
cat sample_set/audit.log.1 | ./noesc_daemon --dump-json >/tmp/noesc_dump.ndjson 2>/tmp/noesc_dump.err
head -n 300 /tmp/noesc_dump.ndjson > /tmp/noesc_small.ndjson

sudo /home/swuffles/Documents/NoEsc/.venv/bin/python scripts/ml/replay_sample_set_to_ml_socket.py \
  --input /tmp/noesc_small.ndjson \
  --socket-path /tmp/noesc_ml.sock \
  --delay-ms 5 \
  --cycles 1

sudo journalctl -u noesc-ml-listener -o cat --since "2 min ago" --no-pager | rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]' | head -n 40
```

## 8) Rules-Only / Hybrid Live Switching

```bash
sudo noesc-engine rules-only
sudo noesc-engine ml-only
sudo noesc-engine hybrid
sudo noesc-engine status
```

## 9) Rules Notification Smoke Test

```bash
cd /home/swuffles/Documents/NoEsc
./scripts/notification/test_notification.sh
```

## 10) Troubleshooting

Regex parse error with square brackets:

```bash
rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]'
```

Bridge drop count:

```bash
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" /var/tmp/noesc_ml_replay.out
```

If drop count is high, slow pacing or reduce sample size:

```bash
head -n 2000 sample_set/audit.log.1 | while IFS= read -r line; do printf "%s\n" "$line"; sleep 0.003; done | ./noesc_daemon --ml-only > /var/tmp/noesc_ml_replay.out 2>&1
```

Restart listener service:

```bash
sudo systemctl restart noesc-ml-listener
sudo systemctl status noesc-ml-listener --no-pager
```

## 11) Quick Recovery From Current State

Terminal 1 (fixed regex, live ML stream):

```bash
sudo journalctl -u noesc-ml-listener -f -o cat --no-pager | rg --line-buffered -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]'
```

Terminal 2 (silent replay, this command intentionally prints no output):

```bash
cd /home/swuffles/Documents/NoEsc
sudo bash -c '
head -n 5000 sample_set/audit.log.1 | while IFS= read -r line; do
  printf "%s\n" "$line"
  sleep 0.002
done | ./noesc_daemon --ml-only > /var/tmp/noesc_ml_replay.out 2>&1
'
```

Terminal 3 (confirm ML actually processed events):

```bash
cd /home/swuffles/Documents/NoEsc
sudo journalctl -u noesc-ml-listener -o cat --since "2 min ago" --no-pager | rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]' | head -n 30
sudo journalctl -u noesc-ml-listener -o cat --since "10 min ago" --no-pager | grep -c '^\[ML-DETECT\]'
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" /var/tmp/noesc_ml_replay.out
```

Important note:

```bash
# ML listener output is in journal logs.
# Desktop notifications are currently rules-engine behavior by default.
```

Optional ML popup watcher (presentation only):

```bash
sudo journalctl -u noesc-ml-listener -f -o cat --no-pager | awk '/^\[ML-DETECT\].*label=MALICIOUS/ { system("notify-send --app-name=NoEsc --urgency=critical \"NoEsc ML Alert\" \"ML marked MALICIOUS\" >/dev/null 2>&1"); print }'
```

## 12) NoEsc Command Glossary (What Each One Is)

Operator-facing commands:

1. noesc_daemon
Role: Core detector process that consumes audit lines and executes rule path, ML bridge path, or both.
Supported flags:
- --ml-only
- --rules-only
- --dump-json
- -h
- --help
Also supports env override:
- NOESC_ENGINE_MODE=hybrid|ml-only|rules-only

2. noesc-maint
Role: Maintenance-mode control for SudoMisuse desktop notification suppression window.
Supported commands:
- status
- off
- on <duration>
- until <epoch-or-date>
- help, -h, --help

3. noesc-engine
Role: Deployed-mode switcher for auditd plugin execution mode.
Supported commands:
- status
- set <hybrid|ml-only|rules-only>
- hybrid
- ml-only
- rules-only
- reload
- help, -h, --help

Internal plumbing commands (normally not used directly by admins):

4. noesc-daemon-wrapper
Role: Wrapper used by audit plugin path. Reads mode from /etc/noesc/engine_mode (or NOESC_ENGINE_MODE), then execs noesc_daemon with correct mode flag.
When you use noesc-engine, this wrapper is what makes switching work without editing plugin config every time.

5. noesc-ml-listener-launcher
Role: Systemd launcher for ML listener service. Reads /etc/noesc/ml_listener.env and starts model_interface.py with the configured args.
This keeps systemd unit clean and environment-driven.

Practical minimum set for administrators:

Most admins only need:
- noesc-engine
- noesc-maint
- systemctl (noesc-ml-listener)

They usually do not need to call:
- noesc-daemon-wrapper
- noesc-ml-listener-launcher

