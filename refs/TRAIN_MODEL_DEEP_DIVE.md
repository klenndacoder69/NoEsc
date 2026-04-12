# NoEsc train_model.py Deep Dive

This guide explains everything inside `src/ml_engine/train_model.py` from first principles.

Audience:
- You can already program.
- You are new to Machine Learning theory and workflow.

Goal:
- After reading this file end to end, you should be able to explain exactly what NoEsc training does, why it does it, and how to interpret the output report.

---

## 1. What Problem This Script Solves

`train_model.py` trains a binary classifier that predicts whether process behavior is:
- `0` = benign
- `1` = malicious

Important design decision:
- Labels are assigned by directory, not by rule engine output.
- Files in `--benign-dir` get label `0`.
- Files in `--malicious-dir` get label `1`.

This means the script is an offline supervised learning pipeline with weak labels from data source location.

---

## 2. High-Level Pipeline (Start to Finish)

The script does this sequence:

1. Parse command-line arguments.
2. Read JSON/NDJSON events from benign and malicious directories.
3. Normalize and validate each event.
4. Group events into process-local sequences by `(source_file, pid, label)`.
5. Build text documents from syscall sequences.
6. Add contextual numeric features.
7. Split data into train/test chronologically (per class).
8. Convert documents to TF-IDF vectors (2-gram and 3-gram).
9. Train a linear SVM classifier.
10. Predict on test set and compute metrics.
11. Save model, vectorizer, and metadata artifacts.

---

## 3. Required Inputs and Dependencies

### 3.1 Input event schema

Each event is expected to contain at least:
- `syscall`
- `auid`
- `euid`
- `exe`
- `pid`
- `timestamp`

Events missing syscall or pid are skipped.

### 3.2 Input file formats accepted

Each file can be:
- a single JSON object
- a JSON array
- an object containing top-level `events` array
- NDJSON (one JSON object per line)

If a non-empty line is not valid JSON, training fails with a `ValueError`.

### 3.3 Python packages used

- `numpy`
- `pandas`
- `scipy`
- `scikit-learn`
- `joblib`

---

## 4. Core ML Concepts (Quick but Complete)

### 4.1 Sample

A "sample" in this script is NOT one log line.

A sample is one process-local sequence (one `(source_file, pid, label)` group) with:
- a syscall sequence document (text)
- contextual numeric features
- one label (0 or 1)

### 4.2 Feature

A "feature" is a numeric value fed into the model.

This script uses two feature blocks:
- TF-IDF text features from syscall n-grams
- hand-crafted context features (`ctx_*` columns)

These are concatenated into one sparse feature vector per sample.

### 4.3 TF-IDF

TF-IDF converts text to numbers.

Here, text is the syscall sequence, for example:
- Document: `59 105 59 92 106`

With `ngram_range=(2,3)`, model uses patterns like:
- 2-gram: `59 105`, `105 59`, `59 92`, ...
- 3-gram: `59 105 59`, `105 59 92`, ...

Intuition:
- Frequent pattern in one sample but not everywhere gets higher importance.
- Very common patterns across all samples get lower weight.

### 4.4 Linear SVM

SVM learns a decision boundary (hyperplane) that separates benign vs malicious in feature space.

Linear SVM prediction is essentially sign of:

`w . x + b`

where:
- `x` is your sample feature vector
- `w` are learned weights
- `b` is bias

If score is above boundary, class tends to malicious; otherwise benign.

`class_weight="balanced"` helps when classes are imbalanced.

---

## 5. Function-by-Function Walkthrough

This section maps exactly to the source flow.

### 5.1 `parse_args()`

Defines CLI contract:
- `--malicious-dir` (required)
- `--benign-dir` (required)
- output artifact paths
- `--train-ratio` (default `0.70`)
- `--min-events-per-sequence` (default `2`)

### 5.2 `parse_int()` and `parse_timestamp()`

Defensive parsers for noisy input:
- Convert values safely.
- Handle missing values and weird strings.
- Timestamp fallback supports numeric text and audit style timestamp strings.

### 5.3 `discover_files(directory)`

Recursively finds regular files in deterministic order:
- sorted directories
- sorted filenames

This improves reproducibility.

### 5.4 `load_json_records(file_path)`

Loads one file, trying:
1. whole-file JSON parse
2. line-by-line NDJSON fallback

Strictness:
- Invalid non-empty JSON line raises error.

### 5.5 `normalize_event(...)`

Converts raw dict into `ParsedEvent` dataclass.

Rejects event if:
- missing syscall
- missing pid

Timestamp fallback:
- if missing/unparseable, uses ingest order to keep deterministic chronology.

### 5.6 `ingest_directory(...)`

For each file in directory:
- load records
- normalize each record
- append valid events

Tracks running ingest order.

### 5.7 `build_sequence_samples(...)`

Core transformation from events to ML samples.

Steps:
1. Build DataFrame of events.
2. Sort by `source_file, pid, timestamp, ingest_order`.
3. Group by `(source_file, pid, label)`.
4. Skip groups shorter than `min-events-per-sequence`.
5. Build syscall document string (`" ".join(syscalls)`).
6. Compute context features:
   - `ctx_euid_is_root`
   - `ctx_auid_non_zero`
   - `ctx_auid_euid_mismatch`
   - `ctx_exe_in_tmp`
   - `ctx_exe_in_usr_bin`
7. Produce one `SequenceSample` per group.

Result: `samples_df` sorted by global chronology fields.

### 5.8 `chronological_split(...)`

Given a DataFrame, split into earlier train and later test by ratio.

### 5.9 `chronological_split_per_class(...)`

This is the important fix for valid evaluation:
- Split label `0` chronologically.
- Split label `1` chronologically.
- Concatenate class-wise train parts and class-wise test parts.

Why needed:
- A single global chronological split can produce a test set with one class only.
- Per-class chronological split keeps time logic while preserving both classes in both splits.

### 5.10 `build_feature_matrices(...)`

Creates vectorizer:
- analyzer word
- ngrams 2 and 3
- `token_pattern=r"(?u)\b[^\s]+\b"`

Then:
1. `fit_transform` train documents
2. `transform` test documents
3. Build sparse context matrices
4. `hstack` text + context

### 5.11 `compute_metrics(...)`

Computes:
- Accuracy
- Precision
- Recall
- F1
- False Positive Rate
- Matthews Correlation Coefficient
- confusion matrix components: TN, FP, FN, TP

### 5.12 `main()`

Orchestrates full training:
- ingest malicious and benign
- build sequence samples
- split train/test
- train SVM
- evaluate
- print report
- save artifacts

---

## 6. Why Each Design Choice Exists

### 6.1 Sequence-level (pid-based) modeling

Why:
- Security behavior is temporal and contextual.
- Single syscall line is often ambiguous.

Effect:
- Better captures behavioral pattern than line-level classifier.

### 6.2 N-gram syscall text features

Why:
- You want transition patterns, not only individual syscall IDs.

Effect:
- Captures local ordering behavior.

### 6.3 Added context features

Why:
- Pure syscall n-grams lose execution context.

Effect:
- Root/non-root and path location cues improve separability.

### 6.4 Chronological split (per class)

Why:
- Better approximates deployment where future behavior is tested after past training.
- Prevents random leakage across time.

### 6.5 Balanced class weighting in SVM

Why:
- Real datasets often imbalanced.

Effect:
- Penalizes mistakes on minority class more fairly.

---

## 7. Artifact Files: What They Mean

### 7.1 SVM model (`*.pkl`)

Contains trained classifier parameters (decision boundary).

### 7.2 TF-IDF vectorizer (`*.pkl`)

Contains learned vocabulary and IDF weights.

Critical rule:
- Inference must use the SAME vectorizer artifact from training.

### 7.3 Training metadata (`*.json`)

Stores:
- parameters used
- class labels
- number of samples
- vocabulary size
- artifact paths

This is vital for reproducibility.

---

## 8. How to Explain Your Example Output Line by Line

Command run:

```
python3 src/ml_engine/train_model.py \
  --malicious-dir sample_set/ml_smoke/malicious \
  --benign-dir sample_set/ml_smoke/benign \
  --model-out models/smoke_svm_model.pkl \
  --vectorizer-out models/smoke_tfidf_vectorizer.pkl \
  --metadata-out models/smoke_training_metadata.json \
  --train-ratio 0.70 \
  --min-events-per-sequence 2
```

Output interpretation:

### `Total sequence samples : 28193`

After grouping by `(source_file, pid, label)` and filtering short groups, you got 28,193 samples.

### `Train samples (70%) : 19734`
### `Test samples (30%) : 8459`

Using train ratio 0.70, each class was split chronologically then merged.

### `Train class counts : {0: np.int64(12098), 1: np.int64(7636)}`
### `Test class counts : {0: np.int64(5186), 1: np.int64(3273)}`

Both classes appear in both splits. This is valid evaluation.

`np.int64(...)` just means NumPy integer type used in pandas counts. It is normal.

### Confusion matrix

`TN=5184 FP=2 FN=0 TP=3273`

Meaning:
- `TN`: benign predicted benign (correct)
- `FP`: benign predicted malicious (false alarm)
- `FN`: malicious predicted benign (missed attack)
- `TP`: malicious predicted malicious (correct)

### Metric explanations using your numbers

Let:
- TN = 5184
- FP = 2
- FN = 0
- TP = 3273

1. Accuracy
- `(TP + TN) / (TP + TN + FP + FN)`
- `(3273 + 5184) / 8459 = 8457 / 8459 = 0.999764`

2. Precision
- `TP / (TP + FP)`
- `3273 / 3275 = 0.999389`

3. Recall
- `TP / (TP + FN)`
- `3273 / 3273 = 1.000000`

4. F1
- harmonic mean of precision and recall
- `2PR/(P+R) = 0.999695`

5. False Positive Rate
- `FP / (FP + TN)`
- `2 / 5186 = 0.000386`

6. MCC
- Correlation-style metric in `[-1, 1]`
- near `1` means very strong classification quality.

### Saved artifacts

- `models/smoke_svm_model.pkl` trained classifier
- `models/smoke_tfidf_vectorizer.pkl` text feature mapping
- `models/smoke_training_metadata.json` run metadata

---

## 9. Common Failure Modes and What They Mean

### 9.1 `No module named joblib`

Cause:
- missing dependencies

Fix:
- install packages from `requirements.txt` in virtual environment

### 9.2 `empty vocabulary`

Cause (previous bug):
- incorrect regex token pattern escaping

Fix:
- use `token_pattern=r"(?u)\b[^\s]+\b"`

### 9.3 Single-label warning in confusion matrix

Cause:
- one-class test split due global chronology

Fix:
- class-wise chronological split (`chronological_split_per_class`)

### 9.4 Non-JSON input file error

Cause:
- directory contains debug text files / logs not in JSON format

Fix:
- keep training directories JSON-only

---

## 10. Practical Run Checklist (Production-Style)

1. Confirm dependency install works.
2. Confirm input directories contain only JSON/NDJSON training files.
3. Run smoke training.
4. Verify both classes exist in train and test.
5. Verify no warnings about single label.
6. Run full training.
7. Save metrics and artifacts for thesis report.

---

## 11. What You Can Now Confidently Explain

After this guide, you should be able to explain:

- Why labels are directory-based and what weak-label implications are.
- Why the sample unit is sequence-level, not event-level.
- What TF-IDF and syscall n-grams represent.
- What linear SVM learns and how decision happens conceptually.
- Why chronological split is used and why per-class split was needed.
- What each metric in the report means and how to compute it.
- What each artifact file stores and why it matters for reproducibility.

If you can explain all above in your own words, you fully understand `train_model.py` at implementation + theory level.
