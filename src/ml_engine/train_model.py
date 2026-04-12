#!/usr/bin/env python3
"""NoEsc offline ML trainer.

This script is intentionally isolated from the rule engine decision outputs.
Labels are assigned ONLY by input directory source:
- malicious directory -> label 1
- benign directory -> label 0

Pipeline summary:
1. Ingest JSON-formatted audit events from two directories.
2. Group events by (source_file, pid) to preserve process-local syscall order.
3. Build syscall "documents" and contextual features, including USER_AUTH statistics.
4. Sort samples chronologically and split 70/30 (train/test) without shuffling.
5. Train SVM (sklearn.svm.SVC) using TF-IDF 2-gram and 3-gram syscall features
   + appended contextual features.
6. Evaluate and print metrics.
7. Save model artifacts with joblib.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
)
from sklearn.svm import SVC

RANDOM_STATE = 42
MALICIOUS_LABEL = 1
BENIGN_LABEL = 0

# Context feature names are kept explicit so they can be reused in inference.
CONTEXT_FEATURE_COLUMNS = [
    "ctx_euid_is_root",
    "ctx_auid_non_zero",
    "ctx_auid_euid_mismatch",
    "ctx_exe_in_tmp",
    "ctx_exe_in_usr_bin",
    "ctx_auth_total_count",
    "ctx_auth_failed_count",
    "ctx_auth_failure_rate",
]


@dataclass
class ParsedEvent:
    """Normalized event representation used by the trainer."""

    source_file: str
    ingest_order: int
    timestamp: float
    pid: str
    event_type: str
    syscall: str
    res: str
    auid: int
    euid: int
    exe: str
    label: int


@dataclass
class SequenceSample:
    """One training sample built from a process-local syscall sequence."""

    source_file: str
    pid: str
    label: int
    timestamp: float
    ingest_order: int
    document: str
    ctx_euid_is_root: int
    ctx_auid_non_zero: int
    ctx_auid_euid_mismatch: int
    ctx_exe_in_tmp: int
    ctx_exe_in_usr_bin: int
    ctx_auth_total_count: int
    ctx_auth_failed_count: int
    ctx_auth_failure_rate: float
    num_events: int


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Train NoEsc SVM model from malicious and benign JSON audit logs."
    )
    parser.add_argument(
        "--malicious-dir",
        required=True,
        help="Directory containing malicious JSON audit logs. All events here get label=1.",
    )
    parser.add_argument(
        "--benign-dir",
        required=True,
        help="Directory containing benign JSON audit logs. All events here get label=0.",
    )
    parser.add_argument(
        "--model-out",
        default="models/svm_model.pkl",
        help="Output path for serialized SVM model.",
    )
    parser.add_argument(
        "--vectorizer-out",
        default="models/tfidf_vectorizer.pkl",
        help="Output path for serialized TF-IDF vectorizer.",
    )
    parser.add_argument(
        "--metadata-out",
        default="models/training_metadata.json",
        help="Output path for training metadata JSON.",
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.70,
        help="Chronological train split ratio. Default: 0.70",
    )
    parser.add_argument(
        "--min-events-per-sequence",
        type=int,
        default=2,
        help="Minimum events required to keep a pid-sequence sample. Default: 2",
    )
    return parser.parse_args()


def parse_int(value: Any, default: int = -1) -> int:
    """Parse int values safely from JSON fields."""
    if value is None:
        return default

    text = str(value).strip().lower()
    if text in {"", "unset", "none", "null", "n/a", "na"}:
        return default

    try:
        return int(text)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return default


def parse_timestamp(value: Any) -> Optional[float]:
    """Parse event timestamp into epoch seconds.

    Supports:
    - numeric timestamps
    - strings like "1712345678.123"
    - strings like "1712345678.123:456" (audit serial suffix)
    - ISO datetime strings
    """
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    if not text:
        return None

    # Handle audit style "timestamp:serial" by keeping only timestamp prefix.
    if ":" in text:
        prefix = text.split(":", 1)[0].strip()
        try:
            return float(prefix)
        except ValueError:
            pass

    try:
        return float(text)
    except ValueError:
        pass

    dt = pd.to_datetime(text, utc=True, errors="coerce")
    if pd.isna(dt):
        return None
    return float(dt.timestamp())


def discover_files(directory: str) -> List[str]:
    """Recursively collect regular files in deterministic order."""
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"Directory does not exist: {directory}")

    discovered: List[str] = []
    for root, dirs, files in os.walk(directory):
        dirs.sort()
        files.sort()
        for name in files:
            if name.startswith("."):
                continue
            file_path = os.path.join(root, name)
            if os.path.isfile(file_path):
                discovered.append(file_path)
    return discovered


def normalize_top_level_json(obj: Any) -> List[Dict[str, Any]]:
    """Normalize top-level JSON object into a list of event dicts."""
    if isinstance(obj, dict):
        events = obj.get("events")
        if isinstance(events, list):
            return [item for item in events if isinstance(item, dict)]
        return [obj]

    if isinstance(obj, list):
        return [item for item in obj if isinstance(item, dict)]

    return []


def load_json_records(file_path: str) -> List[Dict[str, Any]]:
    """Load JSON events from a file.

    Accepted shapes:
    - JSON object (single event)
    - JSON array of objects
    - JSON object with top-level "events" array
    - NDJSON / JSON lines (one object per line)

    Strict contract:
    - This function accepts JSON/NDJSON only.
    - Any non-empty, non-comment line that is not valid JSON raises ValueError.
    """
    with open(file_path, "r", encoding="utf-8") as handle:
        raw_text = handle.read().strip()

    if not raw_text:
        return []

    # First attempt: whole-file JSON.
    try:
        loaded = json.loads(raw_text)
        return normalize_top_level_json(loaded)
    except json.JSONDecodeError:
        pass

    # Fallback: line-by-line NDJSON.
    records: List[Dict[str, Any]] = []
    with open(file_path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                loaded_line = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "Non-JSON content detected in JSON/NDJSON input file "
                    f"{file_path} at line {line_number}: {exc}"
                ) from exc
            records.extend(normalize_top_level_json(loaded_line))

    return records


def normalize_event(
    record: Dict[str, Any],
    source_file: str,
    label: int,
    ingest_order: int,
) -> Optional[ParsedEvent]:
    """Convert raw JSON event dict to ParsedEvent expected by training flow."""
    event_type = str(record.get("type", "")).strip()
    syscall = str(record.get("syscall", "")).strip()
    res = str(record.get("res", "")).strip().lower()
    pid_raw = record.get("pid")

    if not event_type:
        if syscall:
            event_type = "SYSCALL"
        elif res:
            event_type = "USER_AUTH"

    if event_type not in {"SYSCALL", "USER_AUTH"}:
        return None

    if pid_raw is None:
        return None

    if event_type == "SYSCALL" and not syscall:
        return None

    pid = str(pid_raw).strip()
    if not pid:
        return None

    timestamp = parse_timestamp(record.get("timestamp"))
    if timestamp is None:
        # Fallback to ingest order to preserve deterministic chronology.
        timestamp = float(ingest_order)

    return ParsedEvent(
        source_file=source_file,
        ingest_order=ingest_order,
        timestamp=timestamp,
        pid=pid,
        event_type=event_type,
        syscall=syscall,
        res=res,
        auid=parse_int(record.get("auid"), default=-1),
        euid=parse_int(record.get("euid"), default=-1),
        exe=str(record.get("exe", "")).strip(),
        label=label,
    )


def ingest_directory(
    directory: str,
    label: int,
    ingest_order_start: int,
) -> Tuple[List[ParsedEvent], int]:
    """Ingest and normalize all events from one labeled directory."""
    events: List[ParsedEvent] = []
    ingest_order = ingest_order_start

    for file_path in discover_files(directory):
        records = load_json_records(file_path)
        for record in records:
            normalized = normalize_event(record, file_path, label, ingest_order)
            ingest_order += 1
            if normalized is not None:
                events.append(normalized)

    return events, ingest_order


def build_sequence_samples(
    events: Iterable[ParsedEvent],
    min_events_per_sequence: int,
) -> pd.DataFrame:
    """Group events by (source_file, pid) and build sequence-level samples."""
    event_rows = [event.__dict__ for event in events]
    if not event_rows:
        raise ValueError("No valid events were ingested from the provided directories.")

    df = pd.DataFrame(event_rows)
    df = df.sort_values(
        by=["source_file", "pid", "timestamp", "ingest_order"],
        kind="mergesort",
    )

    samples: List[SequenceSample] = []
    grouped = df.groupby(["source_file", "pid", "label"], sort=False)

    for (source_file, pid, label), group in grouped:
        if len(group) < min_events_per_sequence:
            continue

        group = group.sort_values(by=["timestamp", "ingest_order"], kind="mergesort")
        syscall_tokens = group.loc[group["event_type"] == "SYSCALL", "syscall"].astype(str)
        syscalls = [token for token in syscall_tokens.tolist() if token]
        if len(syscalls) < min_events_per_sequence:
            continue

        auth_mask = group["event_type"] == "USER_AUTH"
        auth_total_count = int(auth_mask.sum())
        auth_failed_count = int((auth_mask & (group["res"] == "failed")).sum())
        auth_failure_rate = (
            float(auth_failed_count / auth_total_count)
            if auth_total_count > 0
            else 0.0
        )

        exe_series = group["exe"].astype(str)
        document = " ".join(syscalls)

        sample = SequenceSample(
            source_file=source_file,
            pid=str(pid),
            label=int(label),
            timestamp=float(group["timestamp"].iloc[0]),
            ingest_order=int(group["ingest_order"].iloc[0]),
            document=document,
            ctx_euid_is_root=int((group["euid"] == 0).any()),
            ctx_auid_non_zero=int(((group["auid"] != 0) & (group["auid"] != -1)).any()),
            ctx_auid_euid_mismatch=int(
                (
                    (group["auid"] != group["euid"])
                    & (group["auid"] != -1)
                    & (group["euid"] != -1)
                ).any()
            ),
            ctx_exe_in_tmp=int(
                exe_series.str.startswith("/tmp/").any()
                or exe_series.str.startswith("/dev/shm/").any()
            ),
            ctx_exe_in_usr_bin=int(exe_series.str.startswith("/usr/bin/").any()),
            ctx_auth_total_count=auth_total_count,
            ctx_auth_failed_count=auth_failed_count,
            ctx_auth_failure_rate=auth_failure_rate,
            num_events=int(len(group)),
        )
        samples.append(sample)
 
    if not samples:
        raise ValueError(
            "No sequence samples were produced. Try lowering --min-events-per-sequence."
        )

    samples_df = pd.DataFrame([sample.__dict__ for sample in samples])
    samples_df = samples_df.sort_values(
        by=["timestamp", "ingest_order"],
        kind="mergesort",
    ).reset_index(drop=True)

    return samples_df


def chronological_split(samples_df: pd.DataFrame, train_ratio: float) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Chronologically split samples into train/test without shuffling."""
    if not (0.0 < train_ratio < 1.0):
        raise ValueError("train_ratio must be between 0 and 1.")

    total = len(samples_df)
    if total < 2:
        raise ValueError("Need at least 2 sequence samples for train/test split.")

    split_idx = int(total * train_ratio)
    split_idx = max(1, min(split_idx, total - 1))

    train_df = samples_df.iloc[:split_idx].copy()
    test_df = samples_df.iloc[split_idx:].copy()

    return train_df, test_df

def chronological_split_per_class(
    samples_df: pd.DataFrame, train_ratio: float
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    train_parts: List[pd.DataFrame] = []
    test_parts: List[pd.DataFrame] = []

    for label in sorted(samples_df["label"].unique()):
        class_df = samples_df[samples_df["label"] == label].copy()
        class_train, class_test = chronological_split(class_df, train_ratio)
        train_parts.append(class_train)
        test_parts.append(class_test)

    train_df = pd.concat(train_parts, ignore_index=True).sort_values(
        by=["timestamp", "ingest_order"], kind="mergesort"
    ).reset_index(drop=True)

    test_df = pd.concat(test_parts, ignore_index=True).sort_values(
        by=["timestamp", "ingest_order"], kind="mergesort"
    ).reset_index(drop=True)

    if train_df["label"].nunique() < 2 or test_df["label"].nunique() < 2:
        raise ValueError(
            "Per-class chronological split still produced a single-class split."
        )

    return train_df, test_df

def build_feature_matrices(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> Tuple[TfidfVectorizer, csr_matrix, csr_matrix]:
    """Build TF-IDF + contextual sparse feature matrices."""

    # N-gram requirement: generate 2-grams and 3-grams of syscall sequences.
    vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(2, 3),
        lowercase=False,
        token_pattern=r"(?u)\b[^\s]+\b",
    )

    x_train_text = vectorizer.fit_transform(train_df["document"])
    x_test_text = vectorizer.transform(test_df["document"])

    x_train_ctx = csr_matrix(train_df[CONTEXT_FEATURE_COLUMNS].to_numpy(dtype=np.float32))
    x_test_ctx = csr_matrix(test_df[CONTEXT_FEATURE_COLUMNS].to_numpy(dtype=np.float32))

    x_train = hstack([x_train_text, x_train_ctx], format="csr")
    x_test = hstack([x_test_text, x_test_ctx], format="csr")

    return vectorizer, x_train, x_test


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    """Compute required evaluation metrics."""
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    conf = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = conf.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    try:
        mcc = matthews_corrcoef(y_true, y_pred)
    except ValueError:
        mcc = 0.0

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fpr),
        "mcc": float(mcc),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def ensure_parent_dir(path: str) -> None:
    """Create parent directory for an output file path if needed."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def main() -> None:
    """Run full training pipeline."""
    args = parse_args()

    np.random.seed(RANDOM_STATE)

    # Strict directory-based labels (pure ML contract).
    malicious_events, next_order = ingest_directory(
        directory=args.malicious_dir,
        label=MALICIOUS_LABEL,
        ingest_order_start=0,
    )
    benign_events, _ = ingest_directory(
        directory=args.benign_dir,
        label=BENIGN_LABEL,
        ingest_order_start=next_order,
    )

    all_events = malicious_events + benign_events
    if not all_events:
        raise ValueError(
            "No valid events loaded. Ensure input files are JSON/NDJSON with required fields: "
            "type, syscall (SYSCALL only), res (USER_AUTH optional), auid, euid, exe, pid, timestamp."
        )

    samples_df = build_sequence_samples(
        events=all_events,
        min_events_per_sequence=args.min_events_per_sequence,
    )

    train_df, test_df = chronological_split_per_class(samples_df, train_ratio=args.train_ratio)

    y_train = train_df["label"].to_numpy(dtype=np.int32)
    y_test = test_df["label"].to_numpy(dtype=np.int32)

    if np.unique(y_train).size < 2:
        raise ValueError(
            "Training split contains only one class. Provide more balanced chronological data "
            "or adjust the input logs."
        )

    vectorizer, x_train, x_test = build_feature_matrices(train_df, test_df)

    # SVM classifier as requested.
    svm = SVC(
        kernel="linear",
        class_weight="balanced",
        random_state=RANDOM_STATE,
    )
    svm.fit(x_train, y_train)

    y_pred = svm.predict(x_test)
    metrics = compute_metrics(y_test, y_pred)

    print("=" * 72)
    print("NoEsc Offline Training Report")
    print("=" * 72)
    print(f"Total sequence samples : {len(samples_df)}")
    print(f"Train samples (70%)    : {len(train_df)}")
    print(f"Test samples (30%)     : {len(test_df)}")
    print(f"Train class counts     : {dict(train_df['label'].value_counts().sort_index())}")
    print(f"Test class counts      : {dict(test_df['label'].value_counts().sort_index())}")
    print("-" * 72)
    print(f"Accuracy               : {metrics['accuracy']:.6f}")
    print(f"Precision              : {metrics['precision']:.6f}")
    print(f"Recall                 : {metrics['recall']:.6f}")
    print(f"F1-Score               : {metrics['f1']:.6f}")
    print(f"False Positive Rate    : {metrics['fpr']:.6f}")
    print(f"Matthews Corrcoef      : {metrics['mcc']:.6f}")
    print("-" * 72)
    print(
        "Confusion Matrix (labels: 0=benign, 1=malicious): "
        f"TN={metrics['tn']} FP={metrics['fp']} FN={metrics['fn']} TP={metrics['tp']}"
    )
    print("=" * 72)

    ensure_parent_dir(args.model_out)
    ensure_parent_dir(args.vectorizer_out)
    ensure_parent_dir(args.metadata_out)

    # Required artifacts.
    joblib.dump(svm, args.model_out)
    joblib.dump(vectorizer, args.vectorizer_out)

    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "random_state": RANDOM_STATE,
        "malicious_label": MALICIOUS_LABEL,
        "benign_label": BENIGN_LABEL,
        "train_ratio": args.train_ratio,
        "min_events_per_sequence": args.min_events_per_sequence,
        "context_feature_columns": CONTEXT_FEATURE_COLUMNS,
        "event_types_included": ["SYSCALL", "USER_AUTH"],
        "num_sequence_samples": int(len(samples_df)),
        "num_train_samples": int(len(train_df)),
        "num_test_samples": int(len(test_df)),
        "vocabulary_size": int(len(vectorizer.vocabulary_)),
        "inputs": {
            "malicious_dir": os.path.abspath(args.malicious_dir),
            "benign_dir": os.path.abspath(args.benign_dir),
        },
        "artifacts": {
            "svm_model": os.path.abspath(args.model_out),
            "tfidf_vectorizer": os.path.abspath(args.vectorizer_out),
        },
    }

    with open(args.metadata_out, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)

    print(f"Saved SVM model      : {args.model_out}")
    print(f"Saved TF-IDF vect.   : {args.vectorizer_out}")
    print(f"Saved training meta  : {args.metadata_out}")


if __name__ == "__main__":
    main()
