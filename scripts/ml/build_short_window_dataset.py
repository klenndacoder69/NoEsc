#!/usr/bin/env python3
"""Build short-window training datasets from existing NoEsc NDJSON logs.

This script extracts pid windows focused on:
- short syscall sequences (configurable, default: 1..2 syscalls)
- auth-only windows (optional, default: enabled)

Outputs:
- sample_set/short_windows/benign/short_windows.json
- sample_set/short_windows/malicious/short_windows.json
- sample_set/short_windows/short_window_dataset_stats.json
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ParsedEvent:
    source_file: str
    ingest_order: int
    pid: str
    event_type: str
    syscall: str
    timestamp: float
    raw: Dict[str, Any]


def parse_int(value: Any, default: int = -1) -> int:
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


def parse_timestamp(value: Any, fallback: int) -> float:
    if value is None:
        return float(fallback)
    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    if not text:
        return float(fallback)

    if ":" in text:
        prefix = text.split(":", 1)[0].strip()
        try:
            return float(prefix)
        except ValueError:
            pass

    try:
        return float(text)
    except ValueError:
        return float(fallback)


def normalize_event_type(record: Dict[str, Any]) -> str:
    event_type = str(record.get("type", "")).strip().upper()
    syscall = str(record.get("syscall", "")).strip()
    res = str(record.get("res", "")).strip()

    if not event_type:
        if syscall:
            return "SYSCALL"
        if res:
            return "USER_AUTH"

    return event_type


def load_ndjson(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_no}: {exc}") from exc
            if not isinstance(payload, dict):
                continue
            records.append(payload)
    return records


def build_events(input_file: Path) -> List[ParsedEvent]:
    rows: List[ParsedEvent] = []
    records = load_ndjson(input_file)
    for idx, record in enumerate(records):
        pid = str(record.get("pid", "")).strip()
        if not pid:
            continue

        event_type = normalize_event_type(record)
        syscall = str(record.get("syscall", "")).strip()
        if event_type == "SYSCALL" and not syscall:
            continue
        if event_type not in {"SYSCALL", "USER_AUTH"}:
            continue

        timestamp = parse_timestamp(record.get("timestamp"), fallback=idx)

        rows.append(
            ParsedEvent(
                source_file=str(input_file),
                ingest_order=idx,
                pid=pid,
                event_type=event_type,
                syscall=syscall,
                timestamp=timestamp,
                raw=record,
            )
        )
    return rows


def select_pids(
    events: List[ParsedEvent],
    min_syscalls: int,
    max_syscalls: int,
    include_auth_only: bool,
) -> Dict[str, Dict[str, int]]:
    counts: Dict[str, Dict[str, int]] = {}

    for event in events:
        item = counts.setdefault(event.pid, {"syscalls": 0, "auth": 0})
        if event.event_type == "SYSCALL" and event.syscall:
            item["syscalls"] += 1
        elif event.event_type == "USER_AUTH":
            item["auth"] += 1

    selected: Dict[str, Dict[str, int]] = {}
    for pid, metrics in counts.items():
        syscall_count = metrics["syscalls"]
        auth_count = metrics["auth"]

        is_short = min_syscalls <= syscall_count <= max_syscalls
        is_auth_only = include_auth_only and syscall_count == 0 and auth_count > 0

        if is_short or is_auth_only:
            selected[pid] = metrics

    return selected


def write_selected_events(
    events: List[ParsedEvent],
    selected_pids: Dict[str, Dict[str, int]],
    output_file: Path,
) -> int:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    written = 0

    with output_file.open("w", encoding="utf-8") as handle:
        for event in events:
            if event.pid not in selected_pids:
                continue
            handle.write(json.dumps(event.raw, separators=(",", ":")))
            handle.write("\n")
            written += 1

    return written


def maybe_downsample_pids(
    selected_pids: Dict[str, Dict[str, int]],
    max_pids: int,
    seed: int,
) -> Dict[str, Dict[str, int]]:
    if max_pids <= 0 or len(selected_pids) <= max_pids:
        return selected_pids

    rng = random.Random(seed)
    keys = sorted(selected_pids.keys())
    rng.shuffle(keys)
    keep = set(keys[:max_pids])
    return {pid: selected_pids[pid] for pid in selected_pids if pid in keep}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build short-window dataset from training logs")
    parser.add_argument(
        "--benign-input",
        default="sample_set/training_data/benign/benign_parsed.json",
        help="Benign NDJSON input file",
    )
    parser.add_argument(
        "--malicious-input",
        default="sample_set/training_data/malicious/malicious_parsed.json",
        help="Malicious NDJSON input file",
    )
    parser.add_argument(
        "--out-dir",
        default="sample_set/short_windows",
        help="Output root directory for extracted short-window data",
    )
    parser.add_argument(
        "--min-syscalls",
        type=int,
        default=1,
        help="Minimum syscall count per pid window to keep (default: 1)",
    )
    parser.add_argument(
        "--max-syscalls",
        type=int,
        default=2,
        help="Maximum syscall count per pid window to keep (default: 2)",
    )
    parser.add_argument(
        "--no-auth-only",
        action="store_true",
        help="Disable inclusion of auth-only windows (default: include)",
    )
    parser.add_argument(
        "--max-pids-per-class",
        type=int,
        default=0,
        help="Optional cap per class (0 means no cap)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed used only when downsampling pids",
    )
    return parser.parse_args()


def run_one_class(
    input_file: Path,
    output_file: Path,
    min_syscalls: int,
    max_syscalls: int,
    include_auth_only: bool,
    max_pids_per_class: int,
    seed: int,
) -> Dict[str, Any]:
    events = build_events(input_file)
    selected = select_pids(
        events=events,
        min_syscalls=min_syscalls,
        max_syscalls=max_syscalls,
        include_auth_only=include_auth_only,
    )
    selected = maybe_downsample_pids(selected, max_pids=max_pids_per_class, seed=seed)

    event_count = write_selected_events(events, selected, output_file)

    short_pids = 0
    auth_only_pids = 0
    for metrics in selected.values():
        if 1 <= metrics["syscalls"] <= 2:
            short_pids += 1
        if metrics["syscalls"] == 0 and metrics["auth"] > 0:
            auth_only_pids += 1

    return {
        "input_file": str(input_file),
        "output_file": str(output_file),
        "selected_pid_count": len(selected),
        "selected_event_count": event_count,
        "short_pid_count": short_pids,
        "auth_only_pid_count": auth_only_pids,
    }


def main() -> None:
    args = parse_args()

    if args.min_syscalls < 0 or args.max_syscalls < 0:
        raise ValueError("min/max syscalls must be >= 0")
    if args.min_syscalls > args.max_syscalls:
        raise ValueError("min-syscalls cannot be greater than max-syscalls")

    out_dir = Path(args.out_dir)
    benign_out = out_dir / "benign" / "short_windows.json"
    malicious_out = out_dir / "malicious" / "short_windows.json"

    include_auth_only = not args.no_auth_only

    benign_stats = run_one_class(
        input_file=Path(args.benign_input),
        output_file=benign_out,
        min_syscalls=args.min_syscalls,
        max_syscalls=args.max_syscalls,
        include_auth_only=include_auth_only,
        max_pids_per_class=args.max_pids_per_class,
        seed=args.seed,
    )
    malicious_stats = run_one_class(
        input_file=Path(args.malicious_input),
        output_file=malicious_out,
        min_syscalls=args.min_syscalls,
        max_syscalls=args.max_syscalls,
        include_auth_only=include_auth_only,
        max_pids_per_class=args.max_pids_per_class,
        seed=args.seed,
    )

    summary = {
        "settings": {
            "min_syscalls": args.min_syscalls,
            "max_syscalls": args.max_syscalls,
            "include_auth_only": include_auth_only,
            "max_pids_per_class": args.max_pids_per_class,
            "seed": args.seed,
        },
        "benign": benign_stats,
        "malicious": malicious_stats,
    }

    stats_file = out_dir / "short_window_dataset_stats.json"
    stats_file.parent.mkdir(parents=True, exist_ok=True)
    with stats_file.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    print("=" * 72)
    print("NoEsc Short-Window Dataset Builder")
    print("=" * 72)
    print(f"Benign output      : {benign_out}")
    print(f"Malicious output   : {malicious_out}")
    print(f"Stats              : {stats_file}")
    print("-" * 72)
    print(
        "Benign: "
        f"pids={benign_stats['selected_pid_count']} "
        f"events={benign_stats['selected_event_count']} "
        f"short_pids={benign_stats['short_pid_count']} "
        f"auth_only_pids={benign_stats['auth_only_pid_count']}"
    )
    print(
        "Malicious: "
        f"pids={malicious_stats['selected_pid_count']} "
        f"events={malicious_stats['selected_event_count']} "
        f"short_pids={malicious_stats['short_pid_count']} "
        f"auth_only_pids={malicious_stats['auth_only_pid_count']}"
    )
    print("=" * 72)


if __name__ == "__main__":
    main()
