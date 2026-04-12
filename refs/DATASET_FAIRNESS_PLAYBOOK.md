# NoEsc Dataset Fairness Playbook

This file summarizes the agreed process for building training data fairly for the thesis comparison.

See also: `refs/PRE_HARVEST_RUNBOOK.md` for the frozen pre-harvest protocol,
train-serve parity contract checks, and smoke-training commands.

## 1) Fairness Goal

Use the same export pipeline and field contract for both classes:

- C++ daemon is the single source of truth.
- Both benign and malicious must be generated through `./noesc_daemon --dump-json`.
- JSON schema used by ML: `type`, `timestamp`, `syscall`, `res`, `auid`, `euid`, `exe`, `pid`.

This preserves feature parity between the Rules Engine and the ML engine.

## 2) Data Construction Rules

### Required

- Regenerate both benign and malicious data with the current daemon binary.
- Use identical dump-json filtering behavior for both classes.
- Keep labeling by directory only:
  - benign directory -> label 0
  - malicious directory -> label 1

### Dump-json contamination filter (already implemented)

In dump-json mode, these executables are excluded from export:

- `/usr/bin/notify-send`
- `/usr/bin/xargs`
- `/usr/bin/gdbus`
- `/usr/bin/plasmashell`
- `/usr/bin/git`
- `/usr/bin/mktemp`
- `/usr/bin/seq`
- any path containing `noesc_daemon`

Also excluded:

- events outside `SYSCALL` and `USER_AUTH`
- events with invalid `pid`, `auid`, or `euid` (`< 0`)
- `SYSCALL` events with missing syscall (`syscall` empty and `syscall_id < 0`)

## 3) Malicious Log Generation

Use the root-level scripts:

- `setup_lab_vulns.sh`
- `execute_lab_breakout.sh`
- `harvest_malicious_data.sh`

Recommended environment setup for larger collection:

```bash
export NOESC_TARGET_LINES=250000
export NOESC_BREAKOUT_RUNS=20
export NOESC_MAX_BATCHES=1000
export NOESC_APPEND_OUTPUT=1
./harvest_malicious_data.sh
```

## 4) Benign Log Generation

Regenerate benign JSON using the same dump-json export path and same daemon binary.

Example pattern:

```bash
cat /var/log/audit/audit.log | ./noesc_daemon --dump-json > sample_set/training_data/benign/benign_parsed.json 2>/dev/null
```

If collecting from multiple benign captures, append into one benign file or keep multiple files in the benign directory.

## 5) Size Target for Fair Training

Do not rely only on raw line count. The trainer groups by `(source_file, pid)` and uses sequence samples.

Practical target:

- Malicious: about 200k to 300k exported JSON lines
- Benign used for training: similar order of magnitude (or match sequence-sample counts)

Reason:

- Current historical benign is much larger than malicious and can dominate class distribution if used as-is.

## 6) Quick Sanity Checks

After regeneration, run these checks on both classes.

### Should be near zero

```bash
grep -c '"syscall":""' sample_set/training_data/benign/benign_parsed.json
grep -c '"pid":"-1"' sample_set/training_data/benign/benign_parsed.json
grep -c '"syscall":""' sample_set/training_data/malicious/malicious_parsed.json
grep -c '"pid":"-1"' sample_set/training_data/malicious/malicious_parsed.json
```

### USER_AUTH coverage sanity checks

```bash
grep -c '"type":"USER_AUTH"' sample_set/training_data/benign/benign_parsed.json
grep -c '"type":"USER_AUTH"' sample_set/training_data/malicious/malicious_parsed.json
grep -c '"type":"USER_AUTH".*"res":"failed"' sample_set/training_data/benign/benign_parsed.json
grep -c '"type":"USER_AUTH".*"res":"failed"' sample_set/training_data/malicious/malicious_parsed.json
```

### Should be zero due to contaminant filter

```bash
grep -c '"exe":"/usr/bin/notify-send"' sample_set/training_data/malicious/malicious_parsed.json
grep -c '"exe":"/usr/bin/xargs"' sample_set/training_data/malicious/malicious_parsed.json
grep -c '"exe":"/usr/bin/gdbus"' sample_set/training_data/malicious/malicious_parsed.json
grep -c '"exe":"/usr/bin/plasmashell"' sample_set/training_data/malicious/malicious_parsed.json
grep -c '"exe":"/usr/bin/seq"' sample_set/training_data/malicious/malicious_parsed.json
```

## 7) Experiment Reproducibility Notes

For thesis write-up, record:

- date/time of each export run
- commit hash of daemon/trainer code
- malicious script configuration (`NOESC_*` env values)
- final benign and malicious line counts
- final sequence-sample counts reported by trainer

This makes your Rules vs ML comparison reproducible and defensible.
