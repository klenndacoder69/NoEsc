# NoEsc Complete Command Reference

This is the complete essential command list for building, training, running, and validating the NoEsc pipeline.

All commands assume you are in the project root:

```bash
cd /home/swuffles/Documents/NoEsc
```

## 1) Build Commands

Build with Makefile:

```bash
make clean
make
```

Build with CMake:

```bash
mkdir -p build
cd build
cmake ..
make
```

Direct compile (manual fallback):

```bash
g++ -std=c++17 src/daemon/main.cpp src/daemon/parser.cpp src/daemon/rules_engine.cpp src/daemon/uds_bridge.cpp -o noesc_daemon -I src/daemon
```

## 2) Python Environment Commands

Activate existing venv:

```bash
source .venv/bin/activate
```

Optional first-time setup (if venv does not exist yet):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3) Install and Auditd Integration Commands

Install daemon/plugin/helper in one step:

```bash
sudo ./scripts/install_daemon.sh
```

Manual plugin config + reload:

```bash
sudo cp config/noesc.conf /etc/audit/plugins.d/
sudo service auditd reload
```

## 4) Daemon Runtime Mode Commands

Hybrid mode (default):

```bash
./noesc_daemon
```

ML-only mode:

```bash
./noesc_daemon --ml-only
```

Rules-only mode:

```bash
./noesc_daemon --rules-only
```

Parser dump JSON mode:

```bash
./noesc_daemon --dump-json
```

Environment override mode:

```bash
NOESC_ENGINE_MODE=ml-only ./noesc_daemon
NOESC_ENGINE_MODE=rules-only ./noesc_daemon
NOESC_ENGINE_MODE=hybrid ./noesc_daemon
```

## 5) ML Listener Commands

Baseline listener:

```bash
source .venv/bin/activate
python src/ml_engine/model_interface.py
```

Infer short sequences + emit benign:

```bash
python src/ml_engine/model_interface.py --short-seq-policy infer --emit-benign
```

Infer short sequences + emit auth-only windows:

```bash
python src/ml_engine/model_interface.py --short-seq-policy infer --emit-benign --emit-auth-only
```

Dual-model listener (long + short), explicit artifacts, threshold gate:

```bash
python src/ml_engine/model_interface.py \
  --short-seq-policy infer \
  --emit-benign \
  --emit-auth-only \
  --short-model-enabled \
  --short-model-path models/short_v1/svm_model.pkl \
  --short-vectorizer-path models/short_v1/tfidf_vectorizer.pkl \
  --short-metadata-path models/short_v1/training_metadata.json \
  --short-model-max-seq-len 2 \
  --short-malicious-score-threshold 0.5
```

## 6) Core Training Commands

Train general model directly:

```bash
source .venv/bin/activate
python src/ml_engine/train_model.py \
  --malicious-dir sample_set/training_data/malicious \
  --benign-dir sample_set/training_data/benign \
  --model-out models/v4/svm_model.pkl \
  --vectorizer-out models/v4/tfidf_vectorizer.pkl \
  --metadata-out models/v4/training_metadata.json \
  --train-ratio 0.7 \
  --min-events-per-sequence 2
```

Pre-harvest smoke training wrapper:

```bash
./scripts/ml/pre_harvest_smoke_train.sh
```

Build short-window dataset directly:

```bash
source .venv/bin/activate
python scripts/ml/build_short_window_dataset.py \
  --benign-input sample_set/training_data/benign/benign_parsed.json \
  --malicious-input sample_set/training_data/malicious/malicious_parsed.json \
  --out-dir sample_set/short_windows \
  --min-syscalls 1 \
  --max-syscalls 2 \
  --max-pids-per-class 50000
```

Train short companion model wrapper:

```bash
chmod +x scripts/ml/train_short_window_model.sh
./scripts/ml/train_short_window_model.sh
```

Train short companion model with explicit PID cap:

```bash
NOESC_SHORT_MAX_PIDS_PER_CLASS=50000 ./scripts/ml/train_short_window_model.sh
```

Verify feature contract and metadata compatibility:

```bash
source .venv/bin/activate
python scripts/ml/verify_feature_contract.py
python scripts/ml/verify_feature_contract.py --metadata models/v4/training_metadata.json
python scripts/ml/verify_feature_contract.py --metadata models/short_v1/training_metadata.json
```

## 7) Data Harvest and Lab Generation Commands

Install harvest audit rules and auditd setup:

```bash
sudo ./scripts/harvest_logs.sh
```

Export host audit logs archive:

```bash
sudo ./scripts/export_logs.sh pc1
```

Parse benign collections into training NDJSON:

```bash
./harvest_benign_data.sh
```

Benign parse in append mode:

```bash
NOESC_APPEND_OUTPUT=1 ./harvest_benign_data.sh
```

Generate malicious dataset by lab breakout runs:

```bash
./harvest_malicious_data.sh
```

Malicious harvest with explicit controls:

```bash
NOESC_BREAKOUT_RUNS=5 \
NOESC_FAILED_SUDO_MIN=1 \
NOESC_FAILED_SUDO_MAX=2 \
NOESC_TARGET_LINES=0 \
NOESC_APPEND_OUTPUT=0 \
./harvest_malicious_data.sh
```

Prepare randomized SUID lab payload:

```bash
sudo ./setup_lab_vulns.sh
```

Execute one randomized breakout run:

```bash
./execute_lab_breakout.sh
```

Collect breakout debug diagnostics bundle:

```bash
./collect_breakout_debug_logs.sh
```

## 8) Replay and Evaluation Commands

Replay audit log into daemon in ML-only mode (paced):

```bash
while IFS= read -r line; do
  printf '%s\n' "$line"
  sleep 0.002
done < sample_set/audit.log.1 | ./noesc_daemon --ml-only
```

Replay NDJSON directly to ML socket:

```bash
source .venv/bin/activate
python scripts/ml/replay_sample_set_to_ml_socket.py \
  --input sample_set/training_data/benign/benign_parsed.json \
  --socket-path /tmp/noesc_ml.sock \
  --delay-ms 15 \
  --cycles 1
```

Summarize ML listener log:

```bash
source .venv/bin/activate
python scripts/ml/summarize_ml_listener_log.py --log final_ml_listener.log
```

Fairness comparison smoke run (1 repeat):

```bash
source .venv/bin/activate
python scripts/eval/run_fairness_comparison.py \
  --input-log sample_set/audit.log.1 \
  --repeats 1 \
  --ml-replay-delay-ms 0.0 \
  --rules-replay-delay-ms 0.0 \
  --short-malicious-score-threshold 0.5 \
  --out-dir out/fairness_comparison_smoke
```

Fairness comparison full run (3 repeats):

```bash
source .venv/bin/activate
python scripts/eval/run_fairness_comparison.py \
  --input-log sample_set/audit.log.1 \
  --repeats 3 \
  --ml-replay-delay-ms 2.0 \
  --rules-replay-delay-ms 0.0 \
  --short-malicious-score-threshold 0.5 \
  --out-dir out/fairness_comparison
```

Print fairness outputs:

```bash
cat out/fairness_comparison/summary.txt
cat out/fairness_comparison/per_run_metrics.csv
```

## 9) Rules-Only Validation Commands

Rules-only sanity test on audit.log.1:

```bash
source .venv/bin/activate
rm -f noesc_alerts.log /tmp/rules_audit1.out
cat sample_set/audit.log.1 | ./noesc_daemon --rules-only >/tmp/rules_audit1.out 2>&1
rg --count --include-zero "\\[!\\] NoEsc ALERT" /tmp/rules_audit1.out
if [[ -f noesc_alerts.log ]]; then rg --count --include-zero "ALERT \\[" noesc_alerts.log; else echo "0"; fi
```

Rules-only known-trigger dataset sanity test:

```bash
source .venv/bin/activate
rm -f noesc_alerts.log /tmp/rules_trigger.out
cat sample_set/yay_kernel_install_like.log | ./noesc_daemon --rules-only >/tmp/rules_trigger.out 2>&1
rg --count --include-zero "\\[!\\] NoEsc ALERT" /tmp/rules_trigger.out
if [[ -f noesc_alerts.log ]]; then rg --count --include-zero "WARNING ALERT \\[SudoMisuse\\]" noesc_alerts.log; else echo "0"; fi
if [[ -f noesc_alerts.log ]]; then rg --count --include-zero "CRITICAL ALERT \\[SudoMisuse\\]" noesc_alerts.log; else echo "0"; fi
```

## 10) Listener Diagnostics Commands

Bridge offline/drop count:

```bash
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" final_ml_listener.log
```

Short-model malicious score diagnostics:

```bash
awk '
/^\[ML-DETECT\]/ {
  label=""; src=""; score=0;
  for(i=1;i<=NF;i++){
    if($i~/^label=/){split($i,a,"="); label=a[2]}
    if($i~/^model_source=/){split($i,a,"="); src=a[2]}
    if($i~/^score=/){split($i,a,"="); score=a[2]+0}
  }
  if(label=="MALICIOUS" && src=="short"){n++; s+=score; if(score>=0.9) h90++; if(score<0.1) l10++}
}
END{
  printf("short_malicious_count=%d avg_score=%.6f ge_0.9=%d lt_0.1=%d\n", n, (n?s/n:0), h90, l10)
}' final_ml_listener.log
```

Threshold simulation and calibrated rate estimate:

```bash
awk '
/^\[ML-DETECT\]/ {
  label=""; src=""; score=0;
  for(i=1;i<=NF;i++){
    if($i~/^label=/){split($i,a,"="); label=a[2]}
    if($i~/^model_source=/){split($i,a,"="); src=a[2]}
    if($i~/^score=/){split($i,a,"="); score=a[2]+0}
  }
  total++;
  if(label=="MALICIOUS") raw++;
  if(label=="MALICIOUS" && !(src=="short" && score<0.5)) t05++;
}
END{
  printf("raw_mal=%d raw_rate=%.2f%%\n", raw, 100*raw/total);
  printf("short_score>=0.5 mal=%d rate=%.2f%%\n", t05, 100*t05/total);
}' final_ml_listener.log
```

Length bucket breakdown (len1, len2, len3plus):

```bash
awk '
/^\[ML-DETECT\]/ {
  label=""; src=""; score=0; seq=0;
  for(i=1;i<=NF;i++){
    if($i~/^label=/){split($i,a,"="); label=a[2]}
    if($i~/^model_source=/){split($i,a,"="); src=a[2]}
    if($i~/^score=/){split($i,a,"="); score=a[2]+0}
    if($i~/^seq_len=/){split($i,a,"="); seq=a[2]+0}
  }

  bucket = (seq<=1 ? "len1" : (seq==2 ? "len2" : "len3plus"));
  total[bucket]++;

  if(label=="MALICIOUS") raw_mal[bucket]++;

  cal_mal = (label=="MALICIOUS" && !(src=="short" && score<0.5));
  if(cal_mal) cal_mal_count[bucket]++;
}
END {
  printf("bucket,total,raw_mal,raw_rate_pct,cal_mal,cal_rate_pct\n");
  for (b in total) {
    raw_rate = (total[b] ? 100.0*raw_mal[b]/total[b] : 0);
    cal_rate = (total[b] ? 100.0*cal_mal_count[b]/total[b] : 0);
    printf("%s,%d,%d,%.2f,%d,%.2f\n", b, total[b], raw_mal[b], raw_rate, cal_mal_count[b], cal_rate);
  }
}' final_ml_listener.log | sort
```

## 11) Maintenance and Notification Commands

Maintenance mode helper:

```bash
sudo noesc-maint status
sudo noesc-maint on 30m
sudo noesc-maint on 1h30m
sudo noesc-maint until 1767225600
sudo noesc-maint until "2026-03-30 23:30:00"
sudo noesc-maint off
```

Notification stress and behavior tests:

```bash
./scripts/notification/test_notification.sh
./scripts/notification/test_notification_cooldown.sh
./scripts/notification/test_notification_multi_vector.sh
./scripts/notification/test_notification_spam.sh
./scripts/notification/test_notification_stacking.sh
./scripts/notification/test_debug_notify.sh
./scripts/notification/test_smart_severity.sh
./scripts/notification/test_yay_kernel_install_burst.sh
./scripts/notification/test_yay_kernel_install_extreme.sh
./scripts/notification/test_yay_kernel_install_mixed.sh
./scripts/notification/replay_extreme_10s_realtime.sh
```

## 12) Quick Local Detection Test Commands

Quick test:

```bash
./quick_test.sh
```

Safe test (no rule changes):

```bash
./test_daemon_safe.sh
```

## 13) Utility and Model File Management Commands

Rename/move loose model artifacts interactively:

```bash
./scripts/rename_models.sh
```

## 14) Complete Executable Script Inventory

List all executable shell entrypoints in this repository:

```bash
rg --files -g '*.sh' | sort
```

Current script inventory:

```bash
./collect_breakout_debug_logs.sh
./execute_lab_breakout.sh
./harvest_benign_data.sh
./harvest_malicious_data.sh
./quick_test.sh
./scripts/export_logs.sh
./scripts/harvest_logs.sh
./scripts/install_daemon.sh
./scripts/ml/pre_harvest_smoke_train.sh
./scripts/ml/train_short_window_model.sh
./scripts/noesc-maint.sh
./scripts/notification/replay_extreme_10s_realtime.sh
./scripts/notification/test_debug_notify.sh
./scripts/notification/test_notification.sh
./scripts/notification/test_notification_cooldown.sh
./scripts/notification/test_notification_multi_vector.sh
./scripts/notification/test_notification_spam.sh
./scripts/notification/test_notification_stacking.sh
./scripts/notification/test_smart_severity.sh
./scripts/notification/test_yay_kernel_install_burst.sh
./scripts/notification/test_yay_kernel_install_extreme.sh
./scripts/notification/test_yay_kernel_install_mixed.sh
./scripts/rename_models.sh
./setup_lab_vulns.sh
./test_daemon_safe.sh
```

## 15) Python Entrypoint Inventory

List Python entrypoints used for training, listener runtime, and evaluation:

```bash
rg --files -g '*.py' src/ml_engine scripts | sort
```

Current Python entrypoint inventory:

```bash
src/ml_engine/feature_contract.py
src/ml_engine/model_interface.py
src/ml_engine/train_model.py
scripts/eval/run_fairness_comparison.py
scripts/ml/build_short_window_dataset.py
scripts/ml/replay_sample_set_to_ml_socket.py
scripts/ml/summarize_ml_listener_log.py
scripts/ml/verify_feature_contract.py
```

## 16) Differentiated Strict-Order Blocks (Complete Setup to Full Run)

Use these blocks when you want the exact sequence to make everything work end-to-end.

### Block A: First-Time Complete Setup (machine/bootstrap)

```bash
cd /home/swuffles/Documents/NoEsc

# 1) Python env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2) Build daemon
make clean
make

# 3) Install daemon + plugin + maintenance helper
sudo ./scripts/install_daemon.sh

# 4) Optional: install/refresh audit harvest rules for dataset collection hosts
sudo ./scripts/harvest_logs.sh
```

### Block B: Build Training Data and Train Models (full pipeline)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate

# 1) Build benign parsed dataset from collected logs
./harvest_benign_data.sh

# 2) Build malicious parsed dataset from lab breakout runs
NOESC_BREAKOUT_RUNS=5 \
NOESC_FAILED_SUDO_MIN=1 \
NOESC_FAILED_SUDO_MAX=2 \
NOESC_TARGET_LINES=0 \
NOESC_APPEND_OUTPUT=0 \
./harvest_malicious_data.sh

# 3) Train main long-window model
python src/ml_engine/train_model.py \
  --malicious-dir sample_set/training_data/malicious \
  --benign-dir sample_set/training_data/benign \
  --model-out models/v4/svm_model.pkl \
  --vectorizer-out models/v4/tfidf_vectorizer.pkl \
  --metadata-out models/v4/training_metadata.json \
  --train-ratio 0.7 \
  --min-events-per-sequence 2

# 4) Build short-window dataset (seq_len 1-2)
python scripts/ml/build_short_window_dataset.py \
  --benign-input sample_set/training_data/benign/benign_parsed.json \
  --malicious-input sample_set/training_data/malicious/malicious_parsed.json \
  --out-dir sample_set/short_windows \
  --min-syscalls 1 \
  --max-syscalls 2 \
  --max-pids-per-class 50000

# 5) Train short companion model
NOESC_SHORT_MAX_PIDS_PER_CLASS=50000 ./scripts/ml/train_short_window_model.sh

# 6) Verify contracts and metadata
python scripts/ml/verify_feature_contract.py --metadata models/v4/training_metadata.json
python scripts/ml/verify_feature_contract.py --metadata models/short_v1/training_metadata.json
```

### Block C: Run Dual-Model Listener + Replay + Summarize (core runtime validation)

Terminal 1 (listener):

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
rm -f final_ml_listener.log /tmp/noesc_ml.sock
python src/ml_engine/model_interface.py \
  --short-seq-policy infer \
  --emit-benign \
  --emit-auth-only \
  --short-model-enabled \
  --short-model-path models/short_v1/svm_model.pkl \
  --short-vectorizer-path models/short_v1/tfidf_vectorizer.pkl \
  --short-metadata-path models/short_v1/training_metadata.json \
  --short-model-max-seq-len 2 \
  --short-malicious-score-threshold 0.5 | tee final_ml_listener.log
```

Terminal 2 (replay into daemon ML-only):

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
while IFS= read -r line; do
  printf '%s\n' "$line"
  sleep 0.002
done < sample_set/audit.log.1 | ./noesc_daemon --ml-only
```

Terminal 3 (summary + bridge check):

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
python scripts/ml/summarize_ml_listener_log.py --log final_ml_listener.log
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" final_ml_listener.log
```

### Block D: Full Fairness Benchmark (ML vs Rules, repeated)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
python scripts/eval/run_fairness_comparison.py \
  --input-log sample_set/audit.log.1 \
  --repeats 3 \
  --ml-replay-delay-ms 2.0 \
  --rules-replay-delay-ms 0.0 \
  --short-malicious-score-threshold 0.5 \
  --out-dir out/fairness_comparison

cat out/fairness_comparison/summary.txt
cat out/fairness_comparison/per_run_metrics.csv
```

### Block E: Rules-Only Known-Trigger Sanity (engine health check)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
rm -f noesc_alerts.log /tmp/rules_trigger.out
cat sample_set/yay_kernel_install_like.log | ./noesc_daemon --rules-only >/tmp/rules_trigger.out 2>&1
rg --count --include-zero "\\[!\\] NoEsc ALERT" /tmp/rules_trigger.out
if [[ -f noesc_alerts.log ]]; then rg --count --include-zero "WARNING ALERT \\[SudoMisuse\\]" noesc_alerts.log; else echo "0"; fi
if [[ -f noesc_alerts.log ]]; then rg --count --include-zero "CRITICAL ALERT \\[SudoMisuse\\]" noesc_alerts.log; else echo "0"; fi
```

### Block F: Minimal Daily Workflow (when models already exist)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate

# Terminal 1
rm -f final_ml_listener.log /tmp/noesc_ml.sock
python src/ml_engine/model_interface.py \
  --short-seq-policy infer \
  --emit-benign \
  --emit-auth-only \
  --short-model-enabled \
  --short-model-max-seq-len 2 \
  --short-malicious-score-threshold 0.5 | tee final_ml_listener.log

# Terminal 2
while IFS= read -r line; do
  printf '%s\n' "$line"
  sleep 0.002
done < sample_set/audit.log.1 | ./noesc_daemon --ml-only

# Terminal 3
python scripts/ml/summarize_ml_listener_log.py --log final_ml_listener.log
```
