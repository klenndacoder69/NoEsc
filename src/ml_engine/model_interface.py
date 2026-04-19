"""NoEsc Machine Learning Engine Interface.

Receives parsed audit events over a Unix datagram socket, buffers per-process
windows, builds train-contract features, and performs live SVM inference.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack

from feature_contract import CONTEXT_FEATURE_COLUMNS, EVENT_TYPES_INCLUDED_SET, PAYLOAD_FIELDS

DEFAULT_SOCKET_PATH = "/tmp/noesc_ml.sock"
RECV_BUFFER_SIZE = 65535
DEFAULT_WINDOW_SECONDS = 2.0
DEFAULT_NGRAM_SIZE = 3
DEFAULT_POLL_SLEEP_SECONDS = 0.05
DEFAULT_SHORT_SEQ_POLICY = "skip"

DEFAULT_MODEL_CANDIDATES = (
    "models/v4_min3/svm_model.pkl",
    "models/v4/svm_model.pkl",
    "models/svm_model.pkl",
)
DEFAULT_VECTORIZER_CANDIDATES = (
    "models/v4_min3/tfidf_vectorizer.pkl",
    "models/v4/tfidf_vectorizer.pkl",
    "models/tfidf_vectorizer.pkl",
)
DEFAULT_METADATA_CANDIDATES = (
    "models/v4_min3/training_metadata.json",
    "models/v4/training_metadata.json",
    "models/training_metadata.json",
)

SUPPORTED_EVENT_TYPES = EVENT_TYPES_INCLUDED_SET
REQUIRED_FIELDS = PAYLOAD_FIELDS


def pick_first_existing(candidates: Tuple[str, ...]) -> str:
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


def parse_int(value: str, default: int = -1) -> int:
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NoEsc live ML listener and inference")
    parser.add_argument("--socket-path", default=DEFAULT_SOCKET_PATH)
    parser.add_argument("--window-seconds", type=float, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--ngram-size", type=int, default=DEFAULT_NGRAM_SIZE)
    parser.add_argument(
        "--model-path",
        default=os.environ.get("NOESC_MODEL_PATH", pick_first_existing(DEFAULT_MODEL_CANDIDATES)),
    )
    parser.add_argument(
        "--vectorizer-path",
        default=os.environ.get(
            "NOESC_VECTORIZER_PATH", pick_first_existing(DEFAULT_VECTORIZER_CANDIDATES)
        ),
    )
    parser.add_argument(
        "--metadata-path",
        default=os.environ.get(
            "NOESC_METADATA_PATH", pick_first_existing(DEFAULT_METADATA_CANDIDATES)
        ),
    )
    parser.add_argument(
        "--min-events-per-sequence",
        type=int,
        default=0,
        help="If 0, use metadata value when available. Otherwise use explicit value.",
    )
    parser.add_argument(
        "--emit-benign",
        action="store_true",
        help="Emit ML-DETECT lines for benign predictions too (default: malicious only).",
    )
    parser.add_argument(
        "--short-seq-policy",
        choices=("skip", "infer"),
        default=os.environ.get("NOESC_SHORT_SEQ_POLICY", DEFAULT_SHORT_SEQ_POLICY),
        help=(
            "Behavior when seq_len is below min-events-per-sequence: "
            "'skip' (default) or 'infer' (score anyway and annotate output)."
        ),
    )
    return parser.parse_args()


class NoEscModel:
    def __init__(
        self,
        model_path: str,
        vectorizer_path: str,
        metadata_path: str,
        min_events_per_sequence: int,
    ):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.metadata_path = metadata_path
        self.model: Any = None
        self.vectorizer: Any = None
        self.min_events_per_sequence = min_events_per_sequence

    def load_model(self) -> None:
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Missing model artifact: {self.model_path}")
        if not os.path.exists(self.vectorizer_path):
            raise FileNotFoundError(f"Missing vectorizer artifact: {self.vectorizer_path}")

        print(f"[*] Loading SVM model from {self.model_path}", flush=True)
        self.model = joblib.load(self.model_path)

        print(f"[*] Loading TF-IDF vectorizer from {self.vectorizer_path}", flush=True)
        self.vectorizer = joblib.load(self.vectorizer_path)

        if os.path.exists(self.metadata_path):
            print(f"[*] Loading metadata from {self.metadata_path}", flush=True)
            with open(self.metadata_path, "r", encoding="utf-8") as handle:
                metadata = json.load(handle)

            metadata_ctx = metadata.get("context_feature_columns")
            if metadata_ctx != list(CONTEXT_FEATURE_COLUMNS):
                print(
                    "[!] Warning: metadata context feature columns differ from runtime contract",
                    flush=True,
                )

            if self.min_events_per_sequence <= 0:
                metadata_min = int(metadata.get("min_events_per_sequence", 2))
                self.min_events_per_sequence = max(1, metadata_min)

        if self.min_events_per_sequence <= 0:
            self.min_events_per_sequence = 2

        print(
            f"[*] Listener min-events-per-sequence = {self.min_events_per_sequence}",
            flush=True,
        )

    def predict_sample(
        self,
        document: str,
        context_values: Dict[str, float],
    ) -> Tuple[int, Optional[float]]:
        if self.model is None or self.vectorizer is None:
            raise RuntimeError("Model and vectorizer must be loaded before inference")

        x_text = self.vectorizer.transform([document])
        ctx_row = np.asarray(
            [[context_values[name] for name in CONTEXT_FEATURE_COLUMNS]], dtype=np.float32
        )
        x_ctx = csr_matrix(ctx_row)
        x = hstack([x_text, x_ctx], format="csr")

        prediction = int(self.model.predict(x)[0])

        score: Optional[float] = None
        if hasattr(self.model, "decision_function"):
            raw = self.model.decision_function(x)
            score = float(raw[0])
        elif hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(x)
            score = float(proba[0][1])

        return prediction, score


class SequenceBuffer:
    def __init__(
        self,
        window_seconds: float,
        ngram_size: int,
        model: NoEscModel,
        emit_benign: bool,
        short_seq_policy: str,
    ):
        self.window_seconds = window_seconds
        self.ngram_size = ngram_size
        self.model = model
        self.emit_benign = emit_benign
        self.short_seq_policy = short_seq_policy
        self.by_pid: Dict[str, Dict[str, object]] = {}

    def add_event(self, event: Dict[str, str]) -> None:
        now = time.monotonic()
        pid = event["pid"]
        if not pid:
            return

        event_type = event.get("type", "")
        if event_type not in SUPPORTED_EVENT_TYPES:
            return

        if pid not in self.by_pid:
            self.by_pid[pid] = {
                "events": deque(),
                "last_update": now,
            }

        state = self.by_pid[pid]
        events = state.get("events")
        if not isinstance(events, deque):
            return

        events.append(
            {
                "ts": now,
                "type": event_type,
                "syscall": event.get("syscall", ""),
                "res": event.get("res", ""),
                "auid": parse_int(event.get("auid", ""), default=-1),
                "euid": parse_int(event.get("euid", ""), default=-1),
                "exe": event.get("exe", ""),
            }
        )

        state["last_update"] = now
        self._prune_old(events, now)

    def flush_expired(self, force: bool = False) -> None:
        now = time.monotonic()
        to_remove: List[str] = []

        for pid, state in self.by_pid.items():
            events = state.get("events")
            if not isinstance(events, deque):
                to_remove.append(pid)
                continue

            last_update = state.get("last_update", now)
            if not isinstance(last_update, float):
                last_update = now

            idle_seconds = now - last_update
            if force or idle_seconds >= self.window_seconds:
                self._emit_prediction(pid=pid, events=list(events))
                to_remove.append(pid)

        for pid in to_remove:
            self.by_pid.pop(pid, None)

    def _prune_old(self, events: Deque[Dict[str, object]], now: float) -> None:
        while events and isinstance(events[0].get("ts"), float):
            oldest_ts = float(events[0]["ts"])
            if (now - oldest_ts) <= self.window_seconds:
                break
            events.popleft()

    def _emit_prediction(self, pid: str, events: List[Dict[str, object]]) -> None:
        if not events:
            return

        syscall_seq = [
            str(event.get("syscall", ""))
            for event in events
            if event.get("type") == "SYSCALL" and str(event.get("syscall", ""))
        ]
        if not syscall_seq:
            return

        auids = [int(event.get("auid", -1)) for event in events]
        euids = [int(event.get("euid", -1)) for event in events]
        exes = [str(event.get("exe", "")) for event in events]

        auth_total_count = sum(1 for event in events if event.get("type") == "USER_AUTH")
        auth_failed_count = sum(
            1
            for event in events
            if event.get("type") == "USER_AUTH" and str(event.get("res", "")).lower() == "failed"
        )
        auth_failure_rate = (
            float(auth_failed_count / auth_total_count) if auth_total_count > 0 else 0.0
        )

        ctx_values: Dict[str, float] = {
            "ctx_euid_is_root": float(any(euid == 0 for euid in euids)),
            "ctx_auid_non_zero": float(
                any((auid != 0 and auid != -1) for auid in auids)
            ),
            "ctx_auid_euid_mismatch": float(
                any((auid != euid and auid != -1 and euid != -1) for auid, euid in zip(auids, euids))
            ),
            "ctx_exe_in_tmp": float(
                any(exe.startswith("/tmp/") or exe.startswith("/dev/shm/") for exe in exes)
            ),
            "ctx_exe_in_usr_bin": float(any(exe.startswith("/usr/bin/") for exe in exes)),
            "ctx_auth_total_count": float(auth_total_count),
            "ctx_auth_failed_count": float(auth_failed_count),
            "ctx_auth_failure_rate": float(auth_failure_rate),
        }

        latest_auid = str(next((auid for auid in reversed(auids) if auid != -1), ""))
        latest_euid = str(next((euid for euid in reversed(euids) if euid != -1), ""))
        latest_exe = next((exe for exe in reversed(exes) if exe), "")

        joined_seq = " ".join(syscall_seq)
        print(
            "[ML-SEQ] "
            f"pid={pid} auid={latest_auid} euid={latest_euid} exe={latest_exe} "
            f"auth_total={auth_total_count} auth_failed={auth_failed_count} "
            f"seq={joined_seq}",
            flush=True,
        )

        if len(syscall_seq) >= self.ngram_size:
            ngrams = [
                "|".join(syscall_seq[i : i + self.ngram_size])
                for i in range(len(syscall_seq) - self.ngram_size + 1)
            ]
            print(
                f"[ML-NGRAM] pid={pid} n={self.ngram_size} grams={ngrams}",
                flush=True,
            )

        is_short_seq = len(syscall_seq) < self.model.min_events_per_sequence
        if is_short_seq and self.short_seq_policy == "skip":
            print(
                "[ML-DETECT] "
                f"pid={pid} skipped=min_events_gate seq_len={len(syscall_seq)} "
                f"required={self.model.min_events_per_sequence}",
                flush=True,
            )
            return

        prediction, score = self.model.predict_sample(joined_seq, ctx_values)
        label = "MALICIOUS" if prediction == 1 else "BENIGN"

        if prediction == 0 and not self.emit_benign:
            return

        score_text = "n/a" if score is None else f"{score:.6f}"
        print(
            "[ML-DETECT] "
            f"pid={pid} pred={prediction} label={label} score={score_text} "
            f"seq_len={len(syscall_seq)} auth_total={auth_total_count} "
            f"auth_failed={auth_failed_count} auth_fail_rate={auth_failure_rate:.4f}"
            f" short_seq={'inferred' if is_short_seq else 'no'}"
            f" required={self.model.min_events_per_sequence}",
            flush=True,
        )


def normalize_event(payload: Dict[str, object]) -> Dict[str, str]:
    event = {field: str(payload.get(field, "")).strip() for field in REQUIRED_FIELDS}
    event["type"] = event["type"].upper()
    if not event["type"]:
        if event["syscall"]:
            event["type"] = "SYSCALL"
        elif event["res"]:
            event["type"] = "USER_AUTH"
    event["res"] = event["res"].lower()
    return event


def remove_stale_socket(socket_path: str) -> None:
    if os.path.exists(socket_path):
        os.unlink(socket_path)


def run_listener(
    socket_path: str,
    window_seconds: float,
    ngram_size: int,
    model: NoEscModel,
    emit_benign: bool,
    short_seq_policy: str,
) -> None:
    remove_stale_socket(socket_path)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(socket_path)
    sock.setblocking(False)

    print(f"[*] NoEsc ML listener bound at {socket_path}", flush=True)

    keep_running = {"value": True}

    def _stop_listener(_signum: int, _frame) -> None:
        keep_running["value"] = False

    signal.signal(signal.SIGINT, _stop_listener)
    signal.signal(signal.SIGTERM, _stop_listener)

    buffer = SequenceBuffer(
        window_seconds=window_seconds,
        ngram_size=ngram_size,
        model=model,
        emit_benign=emit_benign,
        short_seq_policy=short_seq_policy,
    )

    try:
        while keep_running["value"]:
            try:
                raw_data = sock.recv(RECV_BUFFER_SIZE)
            except BlockingIOError:
                buffer.flush_expired(force=False)
                time.sleep(DEFAULT_POLL_SLEEP_SECONDS)
                continue
            except InterruptedError:
                continue
            except OSError as exc:
                print(f"[!] ML listener socket error: {exc}", flush=True)
                break

            if not raw_data:
                continue

            try:
                payload = json.loads(raw_data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                print(f"[!] Dropping malformed ML payload: {exc}", flush=True)
                continue

            if not isinstance(payload, dict):
                print("[!] Dropping non-object ML payload", flush=True)
                continue

            event = normalize_event(payload)
            buffer.add_event(event)
            buffer.flush_expired(force=False)
    finally:
        buffer.flush_expired(force=True)
        sock.close()
        remove_stale_socket(socket_path)
        print("[*] NoEsc ML listener stopped", flush=True)


def main() -> None:
    args = parse_args()

    model = NoEscModel(
        model_path=args.model_path,
        vectorizer_path=args.vectorizer_path,
        metadata_path=args.metadata_path,
        min_events_per_sequence=args.min_events_per_sequence,
    )
    model.load_model()

    run_listener(
        socket_path=args.socket_path,
        window_seconds=args.window_seconds,
        ngram_size=args.ngram_size,
        model=model,
        emit_benign=args.emit_benign,
        short_seq_policy=args.short_seq_policy,
    )


if __name__ == "__main__":
    main()
