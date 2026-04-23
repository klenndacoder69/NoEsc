# NoEsc Live Presentation Commands

This is a single copy-paste command runbook for live demos of:

- rules engine only
- ML engine only
- hybrid mode
- ML listener health and replay validation

Run all commands from project root unless noted otherwise.

## 0) One-Time Deploy/Update

```bash
cd /home/swuffles/Documents/NoEsc
sudo ./scripts/install_daemon.sh
```

## 1) Start ML Listener Service

```bash
cd /home/swuffles/Documents/NoEsc
sudo systemctl enable --now noesc-ml-listener
sudo systemctl status noesc-ml-listener --no-pager
sudo journalctl -u noesc-ml-listener -n 80 --no-pager
```

## 2) Check Engine Mode + Switch Modes Live

```bash
sudo noesc-engine status
sudo noesc-engine rules-only
sudo noesc-engine ml-only
sudo noesc-engine hybrid
```

## 3) Validate ML Listener Is Truly Running

```bash
sudo ss -xl | rg /tmp/noesc_ml.sock
sudo journalctl -u noesc-ml-listener -o cat -n 60 --no-pager
sudo journalctl -u noesc-ml-listener -o cat --since "10 min ago" --no-pager | rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]' | head -n 30
```

## 4) Live Stream ML Decisions (Terminal 1)

```bash
sudo journalctl -u noesc-ml-listener -f -o cat --no-pager | rg --line-buffered -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]'
```

## 5) Replay for ML-Only Demo With Pacing (Terminal 2)

```bash
cd /home/swuffles/Documents/NoEsc
sudo bash -c '
head -n 5000 sample_set/audit.log.1 | while IFS= read -r line; do
  printf "%s\n" "$line"
  sleep 0.002
done | ./noesc_daemon --ml-only > /var/tmp/noesc_ml_replay.out 2>&1
'
```

## 6) Replay Result Checks (Terminal 3)

```bash
cd /home/swuffles/Documents/NoEsc
sudo journalctl -u noesc-ml-listener -o cat --since "2 min ago" --no-pager | rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]' | head -n 30
sudo journalctl -u noesc-ml-listener -o cat --since "10 min ago" --no-pager | grep -c '^\[ML-DETECT\]'
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" /var/tmp/noesc_ml_replay.out
```

## 7) Before/After Delta Counter (ML-DETECT)

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

## 8) Direct Socket Replay (Strong ML Proof Path)

Use this when you want guaranteed listener-side proof independent of daemon stdout behavior.

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

## 9) Rules-Only Demo Commands

```bash
cd /home/swuffles/Documents/NoEsc
sudo noesc-engine rules-only
./scripts/notification/test_notification.sh
```

Known-trigger rule sanity:

```bash
cd /home/swuffles/Documents/NoEsc
rm -f noesc_alerts.log /tmp/rules_trigger.out
cat sample_set/yay_kernel_install_like.log | ./noesc_daemon --rules-only >/tmp/rules_trigger.out 2>&1
rg --count --include-zero "\[!\] NoEsc ALERT" /tmp/rules_trigger.out
if [[ -f noesc_alerts.log ]]; then rg --count --include-zero "WARNING ALERT \[SudoMisuse\]" noesc_alerts.log; else echo "0"; fi
if [[ -f noesc_alerts.log ]]; then rg --count --include-zero "CRITICAL ALERT \[SudoMisuse\]" noesc_alerts.log; else echo "0"; fi
```

## 10) Hybrid Demo Command

```bash
sudo noesc-engine hybrid
```

## 11) Full Presentation Flow (Minimal)

```bash
cd /home/swuffles/Documents/NoEsc

# Ensure services are up
sudo systemctl enable --now noesc-ml-listener
sudo noesc-engine status

# Rules-only segment
sudo noesc-engine rules-only
./scripts/notification/test_notification.sh

# ML-only segment
sudo noesc-engine ml-only
sudo journalctl -u noesc-ml-listener -f -o cat --no-pager | rg --line-buffered -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]'
```

In another terminal during ML-only segment:

```bash
cd /home/swuffles/Documents/NoEsc
sudo bash -c '
head -n 5000 sample_set/audit.log.1 | while IFS= read -r line; do
  printf "%s\n" "$line"
  sleep 0.002
done | ./noesc_daemon --ml-only > /var/tmp/noesc_ml_replay.out 2>&1
'
```

## 12) Troubleshooting

Regex fix for brackets:

```bash
rg -e '^\[ML-DETECT\]' -e '^\[ML-AUTH-ONLY\]'
```

Check bridge drops:

```bash
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" /var/tmp/noesc_ml_replay.out
```

If drops are high, use smaller input or slower pacing:

```bash
head -n 2000 sample_set/audit.log.1 | while IFS= read -r line; do printf "%s\n" "$line"; sleep 0.003; done | ./noesc_daemon --ml-only > /var/tmp/noesc_ml_replay.out 2>&1
```

Check ML listener service logs quickly:

```bash
sudo journalctl -u noesc-ml-listener -n 120 --no-pager
```

Restart ML listener service:

```bash
sudo systemctl restart noesc-ml-listener
sudo systemctl status noesc-ml-listener --no-pager
```

Check deployed mode wiring:

```bash
sudo noesc-engine status
cat /etc/noesc/engine_mode
grep -E '^path\s*=' /etc/audit/plugins.d/noesc.conf
```
