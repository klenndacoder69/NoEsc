# NoEsc ML Model Issue Resolution Summary (Start to Current State)

## 1) Why this document exists

This document is a full postmortem and implementation summary of the machine-learning detection issue we investigated in NoEsc, from initial symptoms to the current calibrated solution.

It is written to answer the core questions:

- What was broken at the start?
- Was the initial problem related to short/lower-length sequences not being detected?
- What did we change in code and workflow?
- What did the results look like before and after?
- What is the technically correct conclusion now for ML vs rules fairness?

Short answer: yes, the main starting issue was that many short syscall windows were not being scored (or were effectively under-covered), and this caused severe abstention and confusing behavior.

---

## 2) Initial symptom profile

At the beginning of this effort, live listener behavior showed very high skip/abstention due to minimum-events gating.

Observed pattern:

- Many windows had `seq_len=1` or `seq_len=2`.
- Model metadata/contract required a larger minimum sequence length for standard inference.
- Result: substantial `skipped=min_events_gate` behavior.

Early listener distribution (representative run from the investigation phase):

- `total_detect = 833`
- `malicious = 4`
- `benign = 30`
- `skipped = 799`
- Skip composition was dominated by short windows (`seq_len=1` mostly, then `seq_len=2`).

Interpretation:

- The model was not necessarily "bad" in all contexts.
- The runtime path had a coverage gap: it was seeing lots of short windows but not evaluating most of them.
- That gap made fairness comparisons against rules difficult because ML was abstaining heavily.

---

## 3) Root cause (confirmed)

### 3.1 Operational root cause

The listener enforced minimum-event constraints in a way that caused many short windows to be skipped in practical replay/live conditions.

### 3.2 Data-shape root cause

Real event streams naturally produce many short PID windows, especially in noisy or bursty conditions. A long-window-oriented model contract alone was insufficient.

### 3.3 Visibility root cause

Windows containing only `USER_AUTH` context (without syscall tokens) were under-visible in ML output, which hid potentially meaningful auth-only behavior during analysis.

---

## 4) What we implemented (chronological)

## Phase A: coverage and observability fixes

### A1) Added short-sequence policy control in listener

File changed:

- `src/ml_engine/model_interface.py`

Feature:

- `--short-seq-policy {skip,infer}`

Effect:

- `skip`: preserve old behavior.
- `infer`: score short windows anyway, while preserving metadata reference in output.

Output annotation improvements:

- Added `short_seq=inferred|no`
- Added `required=<min_events>`

### A2) Added USER_AUTH-only emission

File changed:

- `src/ml_engine/model_interface.py`

Feature:

- `--emit-auth-only`

Effect:

- Emits `ML-AUTH-ONLY` lines for PID windows that have auth events but no syscall sequence.
- Adds `auth_total`, `auth_failed`, and `auth_fail_rate` visibility.

### A3) Added summarization tooling

File added:

- `scripts/ml/summarize_ml_listener_log.py`

Effect:

- Standardized post-run metrics:
  - coverage/skip rates
  - malicious/benign counts
  - short/full distribution
  - auth-only counters
  - later, model-source split

---

## Phase B: short-window specialization

### B1) Built dedicated short-window dataset tooling

File added:

- `scripts/ml/build_short_window_dataset.py`

Capabilities:

- Extracts short syscall windows (`1..2` by default).
- Includes optional auth-only windows.
- Supports per-class PID caps for tractable training.

### B2) Automated short-window model training flow

File added:

- `scripts/ml/train_short_window_model.sh`

Practical adjustment:

- Introduced/used class caps (for example `NOESC_SHORT_MAX_PIDS_PER_CLASS=15000`) so training completed in realistic time.

Artifacts produced:

- `models/short_v1/svm_model.pkl`
- `models/short_v1/tfidf_vectorizer.pkl`
- `models/short_v1/training_metadata.json`

### B3) Dual-model routing in listener

File changed:

- `src/ml_engine/model_interface.py`

Features:

- `--short-model-enabled`
- `--short-model-path`
- `--short-vectorizer-path`
- `--short-metadata-path`
- `--short-model-max-seq-len`

Effect:

- `seq_len <= threshold` routed to short model.
- Longer windows routed to long model.
- Output now includes `model_source=short|long`.

---

## Phase C: calibration of short-model alert inflation

After dual-model routing, coverage became excellent but short-window alert volume became too high.

Representative uncalibrated dual-model run:

- `total_ml_detect_lines: 7103`
- `coverage: 100%`
- `malicious_predictions: 1625` (~22.88%)
- `model_source_short: 6788`
- `model_source_long: 315`

Diagnostics showed most short malicious outputs were low-score and noisy.

### C1) Added runtime threshold gate for short-model malicious outputs

File changed:

- `src/ml_engine/model_interface.py`

Feature added:

- `--short-malicious-score-threshold <float>`

Behavior:

- Applies only on short-routed predictions.
- If short model says malicious but score is below threshold, prediction is demoted to benign.
- Long model behavior remains unchanged.

Additional output fields:

- `short_gate=demoted|none`
- `short_mal_threshold=<value|off>`

This change solved alert inflation while preserving full coverage.

---

## 5) Documentation and workflow improvements

Updated files:

- `README.md`
- `bash.md`

Key workflow additions:

- calibrated listener invocation
- log summarization commands
- length-bucket evaluation commands
- repeatable fairness automation command set

Automation file added:

- `scripts/eval/run_fairness_comparison.py`

Purpose:

- repeat ML-only and rules-only replay runs on the same input
- collect per-run CSV
- produce summary text with mean metrics

---

## 6) Final measured outcomes

## 6.1 Calibrated ML-only run behavior

Representative calibrated run (after threshold gate):

- `total_ml_detect_lines: 7104`
- `coverage: 100.00%`
- `skip_rate: 0.00%`
- `malicious_predictions: 149` (~2.10%)
- `benign_predictions: 6955`
- `model_source_short: 6788`
- `model_source_long: 316`
- `auth_only_windows: 10`
- `auth_only_with_failures: 1`

Bridge health:

- `ML Bridge Offline` drop count: `0`

Short malicious score quality after calibration:

- `short_malicious_count=131`
- `avg_score=0.999865`
- `ge_0.9=131`
- `lt_0.1=0`

Length-bucket profile from calibrated output:

- `len1: 131 / 6027 = 2.17%`
- `len2: 0 / 761 = 0.00%`
- `len3plus: 18 / 316 = 5.70%`

## 6.2 Fairness automation summary on `audit.log.1`

From `out/fairness_comparison/summary.txt` (3 repeats):

ML-only (calibrated dual-model):

- mean alerts total: `92.00`
- mean alert rate / input events: `0.1014%`
- mean len1 malicious rate: `2.1512%`
- mean len2 malicious rate: `0.3190%`
- mean len3+ malicious rate: `4.1999%`
- mean bridge drop count: `0.00`

Rules-only:

- mean alerts total: `0.00`
- mean alert rate / input events: `0.0000%`

Important interpretation:

- This does **not** automatically prove ML is more "correct" globally.
- It proves that for this input file and this ruleset, ML emitted low-rate alerts while rules emitted none.

## 6.3 Rules sanity check on known trigger dataset

On `sample_set/yay_kernel_install_like.log` with rules-only:

- stderr alert lines: `20`
- warning SudoMisuse: `10`
- critical SudoMisuse: `10`

This confirms the rules engine is operational and capable of alerting when signatures/conditions are met.

---

## 7) Credibility and correctness conclusion

Question: which is more credible/correct, rules or ML?

Technically correct answer from current evidence:

1. Rules engine is more credible for deterministic, explainable signature detection.
2. Calibrated ML is more credible for broader coverage when behavior falls outside current rule signatures.
3. Without independent ground-truth labels for each event window, absolute correctness ranking cannot be claimed from alert counts alone.

Operationally best result now:

- Hybrid credibility: rules as high-confidence anchors, ML as calibrated coverage extension.

---

## 8) What exactly was solved

The original issue (short/lower-length sequence under-detection/under-scoring) was solved in three layers:

1. Coverage layer:
- `--short-seq-policy infer` removed short-window abstention.

2. Specialization layer:
- added dedicated short-window companion model and routing.

3. Calibration layer:
- `--short-malicious-score-threshold` removed short-window alert inflation and restored practical precision behavior.

Result:

- No longer skipping the majority of short windows.
- No longer flooding malicious alerts from weak short-window scores.
- Stable replay pipeline with reproducible fairness comparisons.

---

## 9) Remaining recommended next steps

1. Ground-truth labeling pass:
- label sampled alerts/non-alerts from both engines for precision/recall estimates.

2. Hard-negative mining for short model:
- prioritize benign admin lookalikes during short-window retraining.

3. Dual-dataset fairness reporting:
- include one dataset where rules are silent (`audit.log.1`) and one where rules are active (`yay_kernel_install_like.log`).

4. Keep long model unchanged unless new evidence indicates long-window regression.

---

## 10) File change inventory from this effort

Core runtime/model files:

- `src/ml_engine/model_interface.py`
- `scripts/ml/summarize_ml_listener_log.py`
- `scripts/ml/build_short_window_dataset.py`
- `scripts/ml/train_short_window_model.sh`
- `scripts/eval/run_fairness_comparison.py`

Docs/runbooks:

- `README.md`
- `bash.md`
- `refs/ML_MODEL_ISSUE_RESOLUTION_SUMMARY.md` (this document)

Artifacts/models:

- `models/short_v1/svm_model.pkl`
- `models/short_v1/tfidf_vectorizer.pkl`
- `models/short_v1/training_metadata.json`

---

## 11) Final one-paragraph executive summary

The ML issue started as a practical coverage failure: most real PID windows were short (`seq_len=1/2`) and were being skipped or poorly represented, making fairness comparisons unreliable. We fixed this by enabling short-window inference, adding auth-only visibility, building and routing to a dedicated short-window model, then calibrating short-window malicious outputs with a runtime threshold gate. This transformed behavior from high abstention and noisy short alerts into stable full coverage (0% skip, 0 bridge drops) with controlled alert rates. Comparative testing showed that on `audit.log.1`, calibrated ML emits low-rate alerts while rules emit none; on a known trigger dataset, rules fire as expected. The most credible operational conclusion is hybrid: rules for deterministic signatures, calibrated ML for complementary anomaly coverage.
