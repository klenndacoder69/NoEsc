"""NoEsc Machine Learning Engine Interface.

Current stage: receive parsed audit events over a Unix datagram socket,
buffer per-process syscall windows, track USER_AUTH context counts,
and print pid-aware sequence n-grams.
"""

import json
import os
import signal
import socket
import time
from collections import deque
from typing import Deque, Dict, List, Tuple

from feature_contract import EVENT_TYPES_INCLUDED_SET, PAYLOAD_FIELDS

SOCKET_PATH = "/tmp/noesc_ml.sock"
RECV_BUFFER_SIZE = 65535
WINDOW_SECONDS = 2.0
NGRAM_SIZE = 3

SUPPORTED_EVENT_TYPES = EVENT_TYPES_INCLUDED_SET

REQUIRED_FIELDS = PAYLOAD_FIELDS


class NoEscModel:
    def __init__(self, model_path: str = "model.pkl"):
        self.model_path = model_path
        self.model = None

    def load_model(self) -> None:
        print(f"[*] Loading SVM model from {self.model_path}")
        # TODO: Implement joblib/pickle load.

    def predict(self, features: List[float]) -> int:
        """Return 0 (benign) or 1 (malicious)."""
        _ = features
        return 0


class SequenceBuffer:
    def __init__(self, window_seconds: float, ngram_size: int):
        self.window_seconds = window_seconds
        self.ngram_size = ngram_size
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
                "auid": event["auid"],
                "euid": event["euid"],
                "exe": event["exe"],
                "auth_total_count": 0,
                "auth_failed_count": 0,
                "last_update": now,
            }

        state = self.by_pid[pid]
        events = state["events"]
        if not isinstance(events, deque):
            return

        if event_type == "SYSCALL":
            syscall = event.get("syscall", "")
            if syscall:
                events.append((now, syscall))
        elif event_type == "USER_AUTH":
            state["auth_total_count"] = int(state.get("auth_total_count", 0)) + 1
            if event.get("res", "").lower() == "failed":
                state["auth_failed_count"] = int(state.get("auth_failed_count", 0)) + 1

        state["auid"] = event["auid"]
        state["euid"] = event["euid"]
        if event["exe"]:
            state["exe"] = event["exe"]
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

            if not events:
                idle_seconds = now - last_update
                if force or idle_seconds >= self.window_seconds:
                    to_remove.append(pid)
                continue

            idle_seconds = now - last_update
            if force or idle_seconds >= self.window_seconds:
                seq = [syscall for _, syscall in events]
                self._print_sequence(
                    pid=pid,
                    auid=str(state.get("auid", "")),
                    euid=str(state.get("euid", "")),
                    exe=str(state.get("exe", "")),
                    seq=seq,
                    auth_total_count=int(state.get("auth_total_count", 0)),
                    auth_failed_count=int(state.get("auth_failed_count", 0)),
                )
                to_remove.append(pid)

        for pid in to_remove:
            self.by_pid.pop(pid, None)

    def _prune_old(self, events: Deque[Tuple[float, str]], now: float) -> None:
        while events and (now - events[0][0]) > self.window_seconds:
            events.popleft()

    def _print_sequence(
        self,
        pid: str,
        auid: str,
        euid: str,
        exe: str,
        seq: List[str],
        auth_total_count: int,
        auth_failed_count: int,
    ) -> None:
        if not seq:
            return

        joined_seq = " ".join(seq)
        print(
            "[ML-SEQ] "
            f"pid={pid} auid={auid} euid={euid} exe={exe} "
            f"auth_total={auth_total_count} auth_failed={auth_failed_count} "
            f"seq={joined_seq}",
            flush=True,
        )

        if len(seq) >= self.ngram_size:
            ngrams = [
                "|".join(seq[i : i + self.ngram_size])
                for i in range(len(seq) - self.ngram_size + 1)
            ]
            print(
                f"[ML-NGRAM] pid={pid} n={self.ngram_size} grams={ngrams}",
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


def run_listener(socket_path: str = SOCKET_PATH) -> None:
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

    buffer = SequenceBuffer(window_seconds=WINDOW_SECONDS, ngram_size=NGRAM_SIZE)

    try:
        while keep_running["value"]:
            try:
                raw_data = sock.recv(RECV_BUFFER_SIZE)
            except BlockingIOError:
                buffer.flush_expired(force=False)
                time.sleep(0.05)
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


if __name__ == "__main__":
    run_listener()
