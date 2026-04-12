# NoEsc Pre-Harvest Runbook

This runbook freezes all pre-harvest decisions and validation steps before long benign/malicious data collection.

## 1. Why this exists

The fairness risk is not only model quality, but evidence mismatch:
- Rule engine consumes SYSCALL and USER_AUTH signals.
- ML must consume equivalent evidence under a stable, reproducible contract.

## 2. Locked decisions

1. Evidence contract: SYSCALL + USER_AUTH.
2. USER_AUTH encoding: context features only (no token interleaving into syscall text).
3. Window behavior: USER_AUTH does not reset sequence windows.
4. Event scope: include all USER_AUTH events.
5. Acceptance gate: keep new contract if MCC improves or does not drop by more than 0.01.
6. Final experiments use fresh harvest after pre-harvest validation is complete.

## 3. Train-serve feature parity contract

Canonical source of truth:
- src/ml_engine/feature_contract.py

Contract fields:
- payload_fields: type, syscall, res, auid, euid, exe, pid, timestamp
- event_types_included: SYSCALL, USER_AUTH
- context_feature_columns:
  - ctx_euid_is_root
  - ctx_auid_non_zero
  - ctx_auid_euid_mismatch
  - ctx_exe_in_tmp
  - ctx_exe_in_usr_bin
  - ctx_auth_total_count
  - ctx_auth_failed_count
  - ctx_auth_failure_rate

## 4. Pre-harvest checklist

1. Build daemon successfully.
2. Verify dump-json emits SYSCALL and USER_AUTH.
3. Verify train-serve contract consistency.
4. Run smoke training on ml_smoke data.
5. Verify metadata compatibility with contract script.
6. Freeze code commit hash for harvest runs.

## 5. Commands

### 5.1 Contract verification

```bash
./.venv/bin/python scripts/ml/verify_feature_contract.py
```

### 5.2 Smoke training (fast)

```bash
bash scripts/ml/pre_harvest_smoke_train.sh
```

### 5.3 Metadata compatibility check (after smoke train)

```bash
./.venv/bin/python scripts/ml/verify_feature_contract.py \
  --metadata models/smoke_user_auth/training_metadata.json
```

## 6. Harvest deferred plan

Long harvest is intentionally deferred until all checklist items pass.

When ready, run final harvest and retraining once, with frozen code and documented env variables.

## 7. Experiment manifest template

Record this per final run:
- timestamp_utc:
- git_commit:
- branch:
- daemon_binary_hash:
- trainer_contract_version:
- malicious_env:
- benign_source:
- malicious_line_count:
- benign_line_count:
- sequence_samples_total:
- train_samples:
- test_samples:
- metrics:
  - accuracy:
  - precision:
  - recall:
  - f1:
  - fpr:
  - mcc:
- acceptance_gate_result:

## 8. Notes on live ML decisioning

Live decisioning can stay deferred. Recommended before final rollout:
- run listener in shadow mode first
- compare offline and shadow predictions on the same replay logs
- only then enable live alerting behavior
