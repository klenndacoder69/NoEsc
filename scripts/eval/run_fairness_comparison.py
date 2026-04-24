#!/usr/bin/env python3
"""Run matched ML-only vs rules-only replay comparisons for fairness reporting.

This script automates repeated replays over the same audit log, capturing:
- ML listener metrics (coverage, malicious rate, length buckets)
- Rule-engine alert counts (severity and vector totals)
- Mean metrics across runs
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from statistics import mean
from typing import Dict, List

DROP_MSG = "ML Bridge Offline (Resource temporarily unavailable)"
TOKEN_RE = re.compile(r"([A-Za-z_]+)=([^ ]+)")
RULE_ALERT_RE = re.compile(r"\] ([A-Z]+) ALERT \[([^\]]+)\]:")
PID_RE = re.compile(r"\(pid=(\d+) ")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run repeated ML vs rules fairness comparisons")
    parser.add_argument("--input-log", default="sample_set/audit.log.1", help="Input audit log path")
    parser.add_argument("--repeats", type=int, default=3, help="Number of runs per mode")
    parser.add_argument(
        "--ml-replay-delay-ms",
        type=float,
        default=2.0,
        help="Delay between replayed audit lines for ML-only runs",
    )
    parser.add_argument(
        "--rules-replay-delay-ms",
        type=float,
        default=0.0,
        help="Delay between replayed audit lines for rules-only runs",
    )
    parser.add_argument(
        "--short-malicious-score-threshold",
        type=float,
        default=0.5,
        help="Threshold passed to model_interface short-model malicious gate",
    )
    parser.add_argument("--out-dir", default="out/fairness_comparison", help="Output directory")
    return parser.parse_args()


def count_input_events(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def parse_tokens(line: str) -> Dict[str, str]:
    return {k: v for k, v in TOKEN_RE.findall(line)}


def parse_ml_listener_log(path: Path) -> Dict[str, float]:
    metrics: Dict[str, float] = {
        "ml_total_detect": 0,
        "ml_evaluated": 0,
        "ml_skipped": 0,
        "ml_benign": 0,
        "ml_malicious": 0,
        "ml_source_short": 0,
        "ml_source_long": 0,
        "ml_auth_only": 0,
        "ml_auth_only_failed": 0,
        "ml_drop_count": 0,
        "len1_total": 0,
        "len1_mal": 0,
        "len2_total": 0,
        "len2_mal": 0,
        "len3plus_total": 0,
        "len3plus_mal": 0,
    }

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if DROP_MSG in line:
                metrics["ml_drop_count"] += 1

            if line.startswith("[ML-AUTH-ONLY]"):
                metrics["ml_auth_only"] += 1
                tokens = parse_tokens(line)
                try:
                    auth_failed = int(tokens.get("auth_failed", "0"))
                except ValueError:
                    auth_failed = 0
                if auth_failed > 0:
                    metrics["ml_auth_only_failed"] += 1
                continue

            if not line.startswith("[ML-DETECT]"):
                continue

            metrics["ml_total_detect"] += 1
            tokens = parse_tokens(line)
            if "skipped" in tokens:
                metrics["ml_skipped"] += 1
                continue

            metrics["ml_evaluated"] += 1
            label = tokens.get("label", "")
            source = tokens.get("model_source", "")

            if label == "MALICIOUS":
                metrics["ml_malicious"] += 1
            elif label == "BENIGN":
                metrics["ml_benign"] += 1

            if source == "short":
                metrics["ml_source_short"] += 1
            elif source == "long":
                metrics["ml_source_long"] += 1

            try:
                seq_len = int(tokens.get("seq_len", "0"))
            except ValueError:
                seq_len = 0

            if seq_len <= 1:
                metrics["len1_total"] += 1
                if label == "MALICIOUS":
                    metrics["len1_mal"] += 1
            elif seq_len == 2:
                metrics["len2_total"] += 1
                if label == "MALICIOUS":
                    metrics["len2_mal"] += 1
            else:
                metrics["len3plus_total"] += 1
                if label == "MALICIOUS":
                    metrics["len3plus_mal"] += 1

    return metrics


def parse_rules_alert_log(path: Path) -> Dict[str, float]:
    metrics: Dict[str, float] = {
        "rules_alert_total": 0,
        "rules_warning": 0,
        "rules_critical": 0,
        "rules_info": 0,
        "rules_vector_sudomisuse": 0,
        "rules_vector_privilegeescalation": 0,
        "rules_vector_sensitivefileaccess": 0,
        "rules_unique_pid_count": 0,
    }
    pid_set = set()

    if not path.exists():
        return metrics

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = RULE_ALERT_RE.search(line)
            if not match:
                continue

            severity = match.group(1)
            vector = match.group(2)
            metrics["rules_alert_total"] += 1

            key = f"rules_{severity.lower()}"
            if key in metrics:
                metrics[key] += 1

            vec_key = f"rules_vector_{vector.lower()}"
            if vec_key in metrics:
                metrics[vec_key] += 1

            pid_match = PID_RE.search(line)
            if pid_match:
                pid_set.add(pid_match.group(1))

    metrics["rules_unique_pid_count"] = float(len(pid_set))
    return metrics


def replay_to_daemon(
    daemon_args: List[str],
    input_log: Path,
    output_log: Path,
    delay_seconds: float,
) -> int:
    with output_log.open("w", encoding="utf-8") as log_handle:
        proc = subprocess.Popen(
            daemon_args,
            stdin=subprocess.PIPE,
            stdout=log_handle,
            stderr=log_handle,
            text=True,
        )
        assert proc.stdin is not None

        with input_log.open("r", encoding="utf-8", errors="replace") as input_handle:
            for idx, line in enumerate(input_handle, start=1):
                proc.stdin.write(line)
                if idx % 500 == 0:
                    proc.stdin.flush()
                if delay_seconds > 0.0:
                    time.sleep(delay_seconds)

        proc.stdin.close()
        return proc.wait()


def run_ml_repeat(
    root: Path,
    input_log: Path,
    run_index: int,
    out_dir: Path,
    delay_seconds: float,
    threshold: float,
) -> Dict[str, float]:
    listener_log = out_dir / f"ml_listener_run{run_index}.log"
    daemon_log = out_dir / f"ml_daemon_run{run_index}.log"

    socket_path = "/tmp/noesc_ml.sock"
    if os.path.exists(socket_path):
        try:
            os.unlink(socket_path)
        except PermissionError:
            raise RuntimeError(
                f"Cannot remove stale socket {socket_path} (owned by root). "
                f"Run: sudo rm -f {socket_path}"
            )

    listener_cmd = [
        sys.executable,
        "src/ml_engine/model_interface.py",
        "--short-seq-policy",
        "infer",
        "--emit-benign",
        "--emit-auth-only",
        "--short-model-enabled",
        "--short-model-path",
        "models/short_v1/svm_model.pkl",
        "--short-vectorizer-path",
        "models/short_v1/tfidf_vectorizer.pkl",
        "--short-metadata-path",
        "models/short_v1/training_metadata.json",
        "--short-model-max-seq-len",
        "2",
        "--short-malicious-score-threshold",
        f"{threshold}",
    ]

    with listener_log.open("w", encoding="utf-8") as listener_handle:
        listener_proc = subprocess.Popen(
            listener_cmd,
            cwd=root,
            stdout=listener_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )

        ready = False
        for _ in range(100):
            if os.path.exists(socket_path):
                ready = True
                break
            if listener_proc.poll() is not None:
                break
            time.sleep(0.1)

        if not ready:
            listener_proc.terminate()
            listener_proc.wait(timeout=10)
            raise RuntimeError(f"Listener did not become ready on run {run_index}")

        daemon_rc = replay_to_daemon(
            daemon_args=["./noesc_daemon", "--ml-only"],
            input_log=input_log,
            output_log=daemon_log,
            delay_seconds=delay_seconds,
        )

        # Let the listener window flush remaining PID buffers.
        time.sleep(2.5)

        if listener_proc.poll() is None:
            listener_proc.send_signal(signal.SIGINT)
            try:
                listener_proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                listener_proc.terminate()
                try:
                    listener_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    listener_proc.kill()
                    listener_proc.wait(timeout=5)

    metrics = parse_ml_listener_log(listener_log)
    metrics["ml_daemon_rc"] = float(daemon_rc)
    return metrics


def run_rules_repeat(
    root: Path,
    input_log: Path,
    run_index: int,
    out_dir: Path,
    delay_seconds: float,
) -> Dict[str, float]:
    daemon_log = out_dir / f"rules_daemon_run{run_index}.log"
    alert_log = root / "noesc_alerts.log"

    if alert_log.exists():
        alert_log.unlink()

    daemon_rc = replay_to_daemon(
        daemon_args=["./noesc_daemon", "--rules-only"],
        input_log=input_log,
        output_log=daemon_log,
        delay_seconds=delay_seconds,
    )

    metrics = parse_rules_alert_log(alert_log)
    metrics["rules_daemon_rc"] = float(daemon_rc)
    return metrics


def write_per_run_csv(path: Path, rows: List[Dict[str, float]]) -> None:
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def safe_rate(num: float, den: float) -> float:
    if den <= 0:
        return 0.0
    return 100.0 * num / den


def summarize(rows: List[Dict[str, float]]) -> Dict[str, float]:
    summary: Dict[str, float] = {}

    ml_rows = [r for r in rows if r.get("mode") == "ml"]
    rules_rows = [r for r in rows if r.get("mode") == "rules"]

    if ml_rows:
        summary["ml_mean_alerts"] = mean(r["alerts_total"] for r in ml_rows)
        summary["ml_mean_alert_rate_events_pct"] = mean(
            r["alert_rate_events_pct"] for r in ml_rows
        )
        summary["ml_mean_len1_rate_pct"] = mean(r["len1_mal_rate_pct"] for r in ml_rows)
        summary["ml_mean_len2_rate_pct"] = mean(r["len2_mal_rate_pct"] for r in ml_rows)
        summary["ml_mean_len3plus_rate_pct"] = mean(r["len3plus_mal_rate_pct"] for r in ml_rows)
        summary["ml_mean_drop_count"] = mean(r["ml_drop_count"] for r in ml_rows)

    if rules_rows:
        summary["rules_mean_alerts"] = mean(r["alerts_total"] for r in rules_rows)
        summary["rules_mean_alert_rate_events_pct"] = mean(
            r["alert_rate_events_pct"] for r in rules_rows
        )
        summary["rules_mean_warning"] = mean(r["rules_warning"] for r in rules_rows)
        summary["rules_mean_critical"] = mean(r["rules_critical"] for r in rules_rows)

    return summary


def write_summary_text(path: Path, summary: Dict[str, float], rows: List[Dict[str, float]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write("================================================================\n")
        handle.write("NoEsc Fairness Comparison Summary\n")
        handle.write("================================================================\n")
        handle.write(f"runs_per_mode: {len([r for r in rows if r.get('mode') == 'ml'])}\n")
        handle.write("----------------------------------------------------------------\n")

        if "ml_mean_alerts" in summary:
            handle.write("ML-only (calibrated dual-model)\n")
            handle.write(f"  mean alerts total             : {summary['ml_mean_alerts']:.2f}\n")
            handle.write(
                f"  mean alert rate / input events: {summary['ml_mean_alert_rate_events_pct']:.4f}%\n"
            )
            handle.write(f"  mean len1 malicious rate      : {summary['ml_mean_len1_rate_pct']:.4f}%\n")
            handle.write(f"  mean len2 malicious rate      : {summary['ml_mean_len2_rate_pct']:.4f}%\n")
            handle.write(
                f"  mean len3+ malicious rate     : {summary['ml_mean_len3plus_rate_pct']:.4f}%\n"
            )
            handle.write(f"  mean bridge drop count        : {summary['ml_mean_drop_count']:.2f}\n")
            handle.write("----------------------------------------------------------------\n")

        if "rules_mean_alerts" in summary:
            handle.write("Rules-only\n")
            handle.write(f"  mean alerts total             : {summary['rules_mean_alerts']:.2f}\n")
            handle.write(
                f"  mean alert rate / input events: {summary['rules_mean_alert_rate_events_pct']:.4f}%\n"
            )
            handle.write(f"  mean WARNING alerts           : {summary['rules_mean_warning']:.2f}\n")
            handle.write(f"  mean CRITICAL alerts          : {summary['rules_mean_critical']:.2f}\n")
            handle.write("----------------------------------------------------------------\n")


def main() -> None:
    args = parse_args()

    if args.repeats < 1:
        raise ValueError("--repeats must be >= 1")

    root = Path(__file__).resolve().parents[2]
    input_log = (root / args.input_log).resolve()
    if not input_log.exists():
        raise FileNotFoundError(f"Missing input log: {input_log}")

    out_dir = (root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    input_event_count = count_input_events(input_log)
    rows: List[Dict[str, float]] = []

    for run_idx in range(1, args.repeats + 1):
        print(f"[*] Run {run_idx}/{args.repeats}: ML-only replay", flush=True)
        ml_metrics = run_ml_repeat(
            root=root,
            input_log=input_log,
            run_index=run_idx,
            out_dir=out_dir,
            delay_seconds=max(0.0, args.ml_replay_delay_ms / 1000.0),
            threshold=args.short_malicious_score_threshold,
        )

        ml_row: Dict[str, float] = {
            "run": float(run_idx),
            "mode": "ml",
            "input_event_count": float(input_event_count),
            "alerts_total": ml_metrics["ml_malicious"],
            "alert_rate_events_pct": safe_rate(ml_metrics["ml_malicious"], input_event_count),
            "ml_total_detect": ml_metrics["ml_total_detect"],
            "ml_evaluated": ml_metrics["ml_evaluated"],
            "ml_skipped": ml_metrics["ml_skipped"],
            "ml_benign": ml_metrics["ml_benign"],
            "ml_malicious": ml_metrics["ml_malicious"],
            "ml_source_short": ml_metrics["ml_source_short"],
            "ml_source_long": ml_metrics["ml_source_long"],
            "ml_auth_only": ml_metrics["ml_auth_only"],
            "ml_auth_only_failed": ml_metrics["ml_auth_only_failed"],
            "ml_drop_count": ml_metrics["ml_drop_count"],
            "len1_total": ml_metrics["len1_total"],
            "len1_mal": ml_metrics["len1_mal"],
            "len1_mal_rate_pct": safe_rate(ml_metrics["len1_mal"], ml_metrics["len1_total"]),
            "len2_total": ml_metrics["len2_total"],
            "len2_mal": ml_metrics["len2_mal"],
            "len2_mal_rate_pct": safe_rate(ml_metrics["len2_mal"], ml_metrics["len2_total"]),
            "len3plus_total": ml_metrics["len3plus_total"],
            "len3plus_mal": ml_metrics["len3plus_mal"],
            "len3plus_mal_rate_pct": safe_rate(
                ml_metrics["len3plus_mal"], ml_metrics["len3plus_total"]
            ),
            "ml_daemon_rc": ml_metrics["ml_daemon_rc"],
        }
        rows.append(ml_row)

        print(f"[*] Run {run_idx}/{args.repeats}: Rules-only replay", flush=True)
        rules_metrics = run_rules_repeat(
            root=root,
            input_log=input_log,
            run_index=run_idx,
            out_dir=out_dir,
            delay_seconds=max(0.0, args.rules_replay_delay_ms / 1000.0),
        )

        rules_row: Dict[str, float] = {
            "run": float(run_idx),
            "mode": "rules",
            "input_event_count": float(input_event_count),
            "alerts_total": rules_metrics["rules_alert_total"],
            "alert_rate_events_pct": safe_rate(rules_metrics["rules_alert_total"], input_event_count),
            "rules_alert_total": rules_metrics["rules_alert_total"],
            "rules_warning": rules_metrics["rules_warning"],
            "rules_critical": rules_metrics["rules_critical"],
            "rules_info": rules_metrics["rules_info"],
            "rules_vector_sudomisuse": rules_metrics["rules_vector_sudomisuse"],
            "rules_vector_privilegeescalation": rules_metrics["rules_vector_privilegeescalation"],
            "rules_vector_sensitivefileaccess": rules_metrics["rules_vector_sensitivefileaccess"],
            "rules_unique_pid_count": rules_metrics["rules_unique_pid_count"],
            "rules_daemon_rc": rules_metrics["rules_daemon_rc"],
        }
        rows.append(rules_row)

    per_run_csv = out_dir / "per_run_metrics.csv"
    write_per_run_csv(per_run_csv, rows)

    summary = summarize(rows)
    summary_txt = out_dir / "summary.txt"
    write_summary_text(summary_txt, summary, rows)

    print("=" * 72)
    print("NoEsc Fairness Comparison Completed")
    print("=" * 72)
    print(f"input_log             : {input_log}")
    print(f"repeats_per_mode      : {args.repeats}")
    print(f"output_dir            : {out_dir}")
    print(f"per_run_metrics_csv   : {per_run_csv}")
    print(f"summary_txt           : {summary_txt}")
    print("=" * 72)


if __name__ == "__main__":
    main()
