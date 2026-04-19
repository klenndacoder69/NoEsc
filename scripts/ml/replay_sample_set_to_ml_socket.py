#!/usr/bin/env python3
"""Replay NDJSON sample events into the NoEsc ML listener socket."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path
from typing import Dict, Iterable, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay sample events to NoEsc ML listener")
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Path to NDJSON file. Provide multiple times to replay multiple files in order.",
    )
    parser.add_argument(
        "--socket-path",
        default="/tmp/noesc_ml.sock",
        help="Unix datagram socket path used by model_interface.py",
    )
    parser.add_argument(
        "--delay-ms",
        type=float,
        default=15.0,
        help="Delay between events in milliseconds (default: 15).",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=1,
        help="Number of times to replay all inputs (default: 1).",
    )
    return parser.parse_args()


def iter_events(file_paths: Iterable[str]) -> Iterable[Dict[str, object]]:
    for path_text in file_paths:
        path = Path(path_text)
        if not path.exists():
            raise FileNotFoundError(f"Missing input file: {path}")
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON in {path}:{line_no}: {exc}") from exc
                if not isinstance(payload, dict):
                    raise ValueError(f"Expected JSON object in {path}:{line_no}")
                yield payload


def main() -> None:
    args = parse_args()

    if args.cycles < 1:
        raise ValueError("--cycles must be >= 1")

    delay_seconds = max(0.0, args.delay_ms / 1000.0)
    sent = 0

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        for _ in range(args.cycles):
            for payload in iter_events(args.input):
                raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                sock.sendto(raw, args.socket_path)
                sent += 1
                if delay_seconds > 0:
                    time.sleep(delay_seconds)
    finally:
        sock.close()

    print(f"[+] Replayed {sent} events to {args.socket_path}")


if __name__ == "__main__":
    main()
