"""NoEsc Machine Learning Engine Interface.

Receives parsed audit events over a Unix datagram socket, buffers per-process
windows, builds train-contract features, and performs live SVM inference.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import signal
import socket
import subprocess
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
DEFAULT_SHORT_MODEL_MAX_SEQ_LEN = 2
DEFAULT_SHORT_MALICIOUS_SCORE_THRESHOLD: Optional[float] = None
DEFAULT_NOTIFY_MALICIOUS = False
DEFAULT_NOTIFY_COOLDOWN_SECONDS = 2.0
DEFAULT_NOTIFY_CLOSE_SECONDS = 5.0
DEFAULT_ML_PROCESS_WHITELIST_PATH = "/etc/noesc/ml_process_whitelist.conf"
DEFAULT_ML_PROCESS_WHITELIST_CANDIDATES = (
    "/etc/noesc/ml_process_whitelist.conf",
    "config/ml_process_whitelist.conf",
)

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
DEFAULT_SHORT_MODEL_CANDIDATES = (
    "models/short_v1/svm_model.pkl",
)
DEFAULT_SHORT_VECTORIZER_CANDIDATES = (
    "models/short_v1/tfidf_vectorizer.pkl",
)
DEFAULT_SHORT_METADATA_CANDIDATES = (
    "models/short_v1/training_metadata.json",
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


def parse_optional_float(value: Optional[str], default: Optional[float] = None) -> Optional[float]:
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"", "unset", "none", "null", "n/a", "na", "off", "disabled"}:
        return default
    try:
        return float(text)
    except ValueError:
        return default


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "n", "off", "disabled"}:
        return False
    return default


def parse_float(value: Optional[str], default: float) -> float:
    parsed = parse_optional_float(value, None)
    if parsed is None:
        return default
    return float(parsed)


def is_maintenance_mode_active() -> bool:
    """Check if the global NoEsc maintenance mode is active."""
    maint_file = "/etc/noesc/sudo_maintenance_mode.until"
    if not os.path.exists(maint_file):
        return False
    try:
        with open(maint_file, "r", encoding="utf-8") as f:
            line = f.readline().strip()
            if line.startswith("until_epoch="):
                until_epoch = float(line.split("=")[1])
                if time.time() < until_epoch:
                    return True
    except Exception:
        pass
    return False


def load_ml_process_whitelist(path: str) -> tuple[set[str], list[str]]:
    """Load the ML process whitelist from a config file.

    Returns (exact_matches, prefix_matches) where:
    - exact_matches: set of full paths to skip
    - prefix_matches: list of path prefixes to skip (entries ending with '/')
    """
    exact: set[str] = set()
    prefixes: list[str] = []

    if not os.path.exists(path):
        return exact, prefixes

    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if entry.endswith("/"):
                prefixes.append(entry)
            else:
                exact.add(entry)

    return exact, prefixes


def is_exe_whitelisted(exe: str, exact: set[str], prefixes: list[str]) -> bool:
    """Check if an executable path is in the ML process whitelist."""
    if not exe:
        return False
    if exe in exact:
        return True
    return any(exe.startswith(prefix) for prefix in prefixes)


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
        "--emit-auth-only",
        action="store_true",
        help=(
            "Emit ML-AUTH-ONLY lines for PID windows that contain USER_AUTH events "
            "but no SYSCALL sequence."
        ),
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
    parser.add_argument(
        "--short-model-enabled",
        action="store_true",
        help="Enable dedicated short-window model routing for seq_len <= --short-model-max-seq-len.",
    )
    parser.add_argument(
        "--short-model-path",
        default=os.environ.get(
            "NOESC_SHORT_MODEL_PATH", pick_first_existing(DEFAULT_SHORT_MODEL_CANDIDATES)
        ),
    )
    parser.add_argument(
        "--short-vectorizer-path",
        default=os.environ.get(
            "NOESC_SHORT_VECTORIZER_PATH",
            pick_first_existing(DEFAULT_SHORT_VECTORIZER_CANDIDATES),
        ),
    )
    parser.add_argument(
        "--short-metadata-path",
        default=os.environ.get(
            "NOESC_SHORT_METADATA_PATH", pick_first_existing(DEFAULT_SHORT_METADATA_CANDIDATES)
        ),
    )
    parser.add_argument(
        "--short-model-max-seq-len",
        type=int,
        default=int(
            os.environ.get("NOESC_SHORT_MODEL_MAX_SEQ_LEN", str(DEFAULT_SHORT_MODEL_MAX_SEQ_LEN))
        ),
        help="Maximum seq_len routed to short model when --short-model-enabled is set.",
    )
    parser.add_argument(
        "--short-malicious-score-threshold",
        type=float,
        default=parse_optional_float(
            os.environ.get("NOESC_SHORT_MALICIOUS_SCORE_THRESHOLD"),
            DEFAULT_SHORT_MALICIOUS_SCORE_THRESHOLD,
        ),
        help=(
            "Optional decision_function score threshold for short-model malicious outputs. "
            "When set, short-model predictions with pred=1 and score<threshold are demoted to benign."
        ),
    )
    parser.add_argument(
        "--notify-malicious",
        action="store_true",
        default=parse_bool(
            os.environ.get("NOESC_ML_NOTIFY_MALICIOUS"),
            DEFAULT_NOTIFY_MALICIOUS,
        ),
        help="Emit desktop notifications for ML malicious detections.",
    )
    parser.add_argument(
        "--notify-cooldown-seconds",
        type=float,
        default=parse_float(
            os.environ.get("NOESC_ML_NOTIFY_COOLDOWN_SECONDS"),
            DEFAULT_NOTIFY_COOLDOWN_SECONDS,
        ),
        help="Minimum interval between ML malicious desktop notifications.",
    )
    parser.add_argument(
        "--notify-close-seconds",
        type=float,
        default=parse_float(
            os.environ.get("NOESC_ML_NOTIFY_CLOSE_SECONDS"),
            DEFAULT_NOTIFY_CLOSE_SECONDS,
        ),
        help="Seconds before auto-closing ML desktop notifications via gdbus.",
    )
    parser.add_argument(
        "--process-whitelist-path",
        default=os.environ.get(
            "NOESC_ML_PROCESS_WHITELIST_PATH",
            pick_first_existing(DEFAULT_ML_PROCESS_WHITELIST_CANDIDATES),
        ),
        help="Path to ML process whitelist config file. Executables listed are skipped.",
    )
    return parser.parse_args()


class MlDesktopNotifier:
    def __init__(self, enabled: bool, cooldown_seconds: float, close_seconds: float):
        self.enabled = enabled
        self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        self.close_seconds = max(0.0, float(close_seconds))
        self.last_notify_ts = 0.0
        self.warned_no_target = False

    def notify_malicious(
        self,
        pid: str,
        auid: str,
        euid: str,
        exe: str,
        seq_len: int,
        score_text: str,
        model_source: str,
        auth_failed_count: int,
    ) -> None:
        if not self.enabled:
            return

        if is_maintenance_mode_active():
            return

        now = time.monotonic()
        if now - self.last_notify_ts < self.cooldown_seconds:
            return

        self.last_notify_ts = now

        exe_text = exe if exe else "unknown"
        auth_status = "failed" if auth_failed_count > 0 else "none"
        title = "[NoEsc] ML MALICIOUS"
        body = (
            f"pid={pid} exe={exe_text} auid={auid or 'unknown'} euid={euid or 'unknown'} "
            f"score={score_text} source={model_source} seq_len={seq_len} auth_failed={auth_status}"
        )

        if len(body) > 240:
            body = body[:237] + "..."

        self._dispatch_notify(title=title, body=body)

    def _dispatch_notify(self, title: str, body: str) -> None:
        try:
            run_as_user: Optional[str] = None
            env_pairs: List[str] = []

            if os.geteuid() == 0:
                target = self._resolve_graphical_user()
                if target is not None:
                    username, _uid, resolved_env = target
                    run_as_user = username
                    env_pairs = [f"{key}={value}" for key, value in resolved_env.items()]

                elif not self.warned_no_target:
                    print(
                        "[!] ML notification: could not resolve active graphical user session; "
                        "falling back to current service user",
                        flush=True,
                    )
                    self.warned_no_target = True

            notification_id = self._send_notification_via_gdbus(
                title=title,
                body=body,
                run_as_user=run_as_user,
                env_pairs=env_pairs,
            )
            if notification_id is not None and self.close_seconds > 0.0:
                self._schedule_notification_close(
                    notification_id=notification_id,
                    run_as_user=run_as_user,
                    env_pairs=env_pairs,
                )
        except Exception as exc:  # pragma: no cover
            print(f"[!] ML notification dispatch failed: {exc}", flush=True)

    def _build_gdbus_base(self) -> List[str]:
        return [
            "gdbus",
            "call",
            "--session",
            "--dest",
            "org.freedesktop.Notifications",
            "--object-path",
            "/org/freedesktop/Notifications",
        ]

    def _with_user_session_env(
        self,
        base_cmd: List[str],
        run_as_user: Optional[str],
        env_pairs: List[str],
    ) -> List[str]:
        if run_as_user is None:
            return base_cmd
        return ["runuser", "-u", run_as_user, "--", "env", *env_pairs, *base_cmd]

    def _send_notification_via_gdbus(
        self,
        title: str,
        body: str,
        run_as_user: Optional[str],
        env_pairs: List[str],
    ) -> Optional[int]:
        expire_timeout_ms = max(1000, int(self.close_seconds * 1000.0))
        cmd = self._build_gdbus_base() + [
            "--method",
            "org.freedesktop.Notifications.Notify",
            "NoEsc",
            "0",
            "dialog-error",
            title,
            body,
            "[]",
            "{'urgency': <byte 2>}",
            f"int32 {expire_timeout_ms}",
        ]
        wrapped_cmd = self._with_user_session_env(cmd, run_as_user, env_pairs)
        output = subprocess.check_output(
            wrapped_cmd,
            text=True,
            stderr=subprocess.DEVNULL,
        )

        match = re.search(r"uint32\s+(\d+)", output)
        if match is None:
            return None
        return int(match.group(1))

    def _schedule_notification_close(
        self,
        notification_id: int,
        run_as_user: Optional[str],
        env_pairs: List[str],
    ) -> None:
        delay = f"{self.close_seconds:.3f}"
        close_cmd = (
            f"sleep {delay} && "
            "gdbus call --session "
            "--dest org.freedesktop.Notifications "
            "--object-path /org/freedesktop/Notifications "
            "--method org.freedesktop.Notifications.CloseNotification "
            f"\"uint32 {notification_id}\""
        )

        if run_as_user is None:
            wrapped_cmd = ["sh", "-c", close_cmd]
        else:
            wrapped_cmd = [
                "runuser",
                "-u",
                run_as_user,
                "--",
                "env",
                *env_pairs,
                "sh",
                "-c",
                close_cmd,
            ]

        subprocess.Popen(
            wrapped_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _resolve_graphical_user(self) -> Optional[Tuple[str, int, Dict[str, str]]]:
        # Preferred path: query systemd-logind for the active local user session
        # (works for Wayland/X11 desktop sessions).
        try:
            sessions_output = subprocess.check_output(
                ["loginctl", "list-sessions", "--no-legend"],
                text=True,
                stderr=subprocess.DEVNULL,
            )

            for line in sessions_output.splitlines():
                parts = line.split()
                if not parts:
                    continue

                session_id = parts[0]
                session_props_raw = subprocess.check_output(
                    [
                        "loginctl",
                        "show-session",
                        session_id,
                        "-p",
                        "Name",
                        "-p",
                        "User",
                        "-p",
                        "Active",
                        "-p",
                        "Class",
                        "-p",
                        "Remote",
                        "-p",
                        "Display",
                        "-p",
                        "Leader",
                    ],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )

                session_props: Dict[str, str] = {}
                for row in session_props_raw.splitlines():
                    if "=" not in row:
                        continue
                    key, value = row.split("=", 1)
                    session_props[key] = value

                if session_props.get("Active") != "yes":
                    continue
                if session_props.get("Class") != "user":
                    continue
                if session_props.get("Remote") == "yes":
                    continue

                username = session_props.get("Name", "").strip()
                uid_text = session_props.get("User", "").strip()
                if not username or not uid_text:
                    continue

                uid = int(uid_text)
                if uid < 1000:
                    continue

                runtime_dir = f"/run/user/{uid}"
                user_bus_path = f"{runtime_dir}/bus"
                if not os.path.exists(user_bus_path):
                    continue

                resolved_env: Dict[str, str] = {
                    "DBUS_SESSION_BUS_ADDRESS": f"unix:path={user_bus_path}",
                    "XDG_RUNTIME_DIR": runtime_dir,
                }

                leader_pid = session_props.get("Leader", "").strip()
                if leader_pid.isdigit():
                    try:
                        with open(f"/proc/{leader_pid}/environ", "rb") as environ_file:
                            environ_raw = environ_file.read().decode("utf-8", errors="ignore")

                        for item in environ_raw.split("\x00"):
                            if "=" not in item:
                                continue
                            key, value = item.split("=", 1)
                            if key in {"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"} and value:
                                resolved_env[key] = value
                    except Exception:
                        pass

                display_value = session_props.get("Display", "").strip()
                if display_value and "DISPLAY" not in resolved_env:
                    resolved_env["DISPLAY"] = display_value

                return username, uid, resolved_env
        except Exception:
            pass

        # Fallback path for environments without loginctl or incomplete session data.
        try:
            who_output = subprocess.check_output(
                ["who"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in who_output.splitlines():
                parts = line.split()
                if not parts:
                    continue

                username = parts[0]
                if username == "root":
                    continue

                user_info = pwd.getpwnam(username)
                uid = int(user_info.pw_uid)
                if uid < 1000:
                    continue

                runtime_dir = f"/run/user/{uid}"
                user_bus_path = f"{runtime_dir}/bus"
                if not os.path.exists(user_bus_path):
                    continue

                resolved_env = {
                    "DBUS_SESSION_BUS_ADDRESS": f"unix:path={user_bus_path}",
                    "XDG_RUNTIME_DIR": runtime_dir,
                }

                return username, uid, resolved_env
        except Exception:
            return None

        return None


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
        short_model: Optional[NoEscModel],
        short_model_max_seq_len: int,
        emit_benign: bool,
        emit_auth_only: bool,
        short_seq_policy: str,
        short_malicious_score_threshold: Optional[float],
        notifier: MlDesktopNotifier,
        whitelist_exact: Optional[set] = None,
        whitelist_prefixes: Optional[list] = None,
    ):
        self.window_seconds = window_seconds
        self.ngram_size = ngram_size
        self.model = model
        self.short_model = short_model
        self.short_model_max_seq_len = max(1, short_model_max_seq_len)
        self.emit_benign = emit_benign
        self.emit_auth_only = emit_auth_only
        self.short_seq_policy = short_seq_policy
        self.short_malicious_score_threshold = short_malicious_score_threshold
        self.notifier = notifier
        self.whitelist_exact: set[str] = whitelist_exact or set()
        self.whitelist_prefixes: list[str] = whitelist_prefixes or []
        self.whitelist_skip_count = 0
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

        latest_auid = str(next((auid for auid in reversed(auids) if auid != -1), ""))
        latest_euid = str(next((euid for euid in reversed(euids) if euid != -1), ""))
        latest_exe = next((exe for exe in reversed(exes) if exe), "")

        # --- Process whitelist gate ---
        if is_exe_whitelisted(latest_exe, self.whitelist_exact, self.whitelist_prefixes):
            self.whitelist_skip_count += 1
            if self.whitelist_skip_count <= 5 or self.whitelist_skip_count % 100 == 0:
                print(
                    f"[ML-WHITELIST] pid={pid} exe={latest_exe} skipped "
                    f"(total_skipped={self.whitelist_skip_count})",
                    flush=True,
                )
            return

        syscall_seq = [
            str(event.get("syscall", ""))
            for event in events
            if event.get("type") == "SYSCALL" and str(event.get("syscall", ""))
        ]
        if not syscall_seq:
            if self.emit_auth_only and auth_total_count > 0:
                auth_status = "failed" if auth_failed_count > 0 else "success"
                print(
                    "[ML-AUTH-ONLY] "
                    f"pid={pid} auid={latest_auid} euid={latest_euid} exe={latest_exe} "
                    f"auth_total={auth_total_count} auth_failed={auth_failed_count} "
                    f"auth_fail_rate={auth_failure_rate:.4f} auth_status={auth_status}",
                    flush=True,
                )
            return

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

        selected_model = self.model
        model_source = "long"
        if self.short_model is not None and len(syscall_seq) <= self.short_model_max_seq_len:
            selected_model = self.short_model
            model_source = "short"

        prediction, score = selected_model.predict_sample(joined_seq, ctx_values)

        short_gate = "none"
        if (
            model_source == "short"
            and prediction == 1
            and self.short_malicious_score_threshold is not None
            and score is not None
            and score < self.short_malicious_score_threshold
        ):
            prediction = 0
            short_gate = "demoted"

        label = "MALICIOUS" if prediction == 1 else "BENIGN"

        if prediction == 0 and not self.emit_benign:
            return

        score_text = "n/a" if score is None else f"{score:.6f}"
        threshold_text = (
            "off"
            if self.short_malicious_score_threshold is None
            else f"{self.short_malicious_score_threshold:.6f}"
        )
        print(
            "[ML-DETECT] "
            f"pid={pid} pred={prediction} label={label} score={score_text} "
            f"seq_len={len(syscall_seq)} auth_total={auth_total_count} "
            f"auth_failed={auth_failed_count} auth_fail_rate={auth_failure_rate:.4f}"
            f" model_source={model_source}"
            f" short_gate={short_gate}"
            f" short_mal_threshold={threshold_text}"
            f" short_seq={'inferred' if is_short_seq else 'no'}"
            f" required={self.model.min_events_per_sequence}",
            flush=True,
        )

        if prediction == 1:
            self.notifier.notify_malicious(
                pid=pid,
                auid=latest_auid,
                euid=latest_euid,
                exe=latest_exe,
                seq_len=len(syscall_seq),
                score_text=score_text,
                model_source=model_source,
                auth_failed_count=auth_failed_count,
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
    short_model: Optional[NoEscModel],
    short_model_max_seq_len: int,
    emit_benign: bool,
    emit_auth_only: bool,
    short_seq_policy: str,
    short_malicious_score_threshold: Optional[float],
    notifier: MlDesktopNotifier,
    whitelist_exact: Optional[set] = None,
    whitelist_prefixes: Optional[list] = None,
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
        short_model=short_model,
        short_model_max_seq_len=short_model_max_seq_len,
        emit_benign=emit_benign,
        emit_auth_only=emit_auth_only,
        short_seq_policy=short_seq_policy,
        short_malicious_score_threshold=short_malicious_score_threshold,
        notifier=notifier,
        whitelist_exact=whitelist_exact,
        whitelist_prefixes=whitelist_prefixes,
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

    # Load ML process whitelist
    wl_exact, wl_prefixes = load_ml_process_whitelist(args.process_whitelist_path)
    wl_total = len(wl_exact) + len(wl_prefixes)
    if wl_total > 0:
        print(
            f"[*] ML process whitelist loaded: {len(wl_exact)} exact + "
            f"{len(wl_prefixes)} prefix entries from {args.process_whitelist_path}",
            flush=True,
        )
    else:
        print("[*] ML process whitelist: empty or not found", flush=True)

    model = NoEscModel(
        model_path=args.model_path,
        vectorizer_path=args.vectorizer_path,
        metadata_path=args.metadata_path,
        min_events_per_sequence=args.min_events_per_sequence,
    )
    model.load_model()

    short_model: Optional[NoEscModel] = None
    if args.short_model_enabled:
        short_model = NoEscModel(
            model_path=args.short_model_path,
            vectorizer_path=args.short_vectorizer_path,
            metadata_path=args.short_metadata_path,
            min_events_per_sequence=1,
        )
        short_model.load_model()
        print(
            f"[*] Short model routing enabled for seq_len <= {max(1, args.short_model_max_seq_len)}",
            flush=True,
        )

    if args.short_malicious_score_threshold is not None:
        print(
            "[*] Short model malicious score threshold enabled at "
            f"{args.short_malicious_score_threshold:.6f}",
            flush=True,
        )

    if args.notify_malicious:
        print(
            "[*] ML malicious desktop notification enabled "
            f"(cooldown={max(0.0, args.notify_cooldown_seconds):.2f}s "
            f"close={max(0.0, args.notify_close_seconds):.2f}s)",
            flush=True,
        )

    notifier = MlDesktopNotifier(
        enabled=args.notify_malicious,
        cooldown_seconds=max(0.0, args.notify_cooldown_seconds),
        close_seconds=max(0.0, args.notify_close_seconds),
    )

    run_listener(
        socket_path=args.socket_path,
        window_seconds=args.window_seconds,
        ngram_size=args.ngram_size,
        model=model,
        short_model=short_model,
        short_model_max_seq_len=max(1, args.short_model_max_seq_len),
        emit_benign=args.emit_benign,
        emit_auth_only=args.emit_auth_only,
        short_seq_policy=args.short_seq_policy,
        short_malicious_score_threshold=args.short_malicious_score_threshold,
        notifier=notifier,
        whitelist_exact=wl_exact,
        whitelist_prefixes=wl_prefixes,
    )


if __name__ == "__main__":
    main()
