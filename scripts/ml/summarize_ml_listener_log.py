#!/usr/bin/env python3
"""Summarize NoEsc ML listener outputs for coverage and confidence reporting."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

DETECT_RE = re.compile(r"\[ML-DETECT\](.*)")
AUTH_ONLY_RE = re.compile(r"\[ML-AUTH-ONLY\](.*)")


def parse_kv_pairs(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for token in text.strip().split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        out[key] = value
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize final_ml_listener.log style output")
    parser.add_argument("--log", default="final_ml_listener.log", help="Path to listener log")
    args = parser.parse_args()

    path = Path(args.log)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    total_detect = 0
    skipped = 0
    benign = 0
    malicious = 0
    short_inferred = 0
    full_length = 0
    mal_short = 0
    mal_full = 0
    auth_only = 0
    auth_only_failed = 0
    model_short = 0
    model_long = 0

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            detect_match = DETECT_RE.search(line)
            if detect_match:
                total_detect += 1
                fields = parse_kv_pairs(detect_match.group(1))

                if fields.get("skipped") == "min_events_gate":
                    skipped += 1
                    continue

                label = fields.get("label", "")
                short_seq = fields.get("short_seq", "")
                model_source = fields.get("model_source", "")

                if label == "BENIGN":
                    benign += 1
                elif label == "MALICIOUS":
                    malicious += 1

                if short_seq == "inferred":
                    short_inferred += 1
                    if label == "MALICIOUS":
                        mal_short += 1
                elif short_seq == "no":
                    full_length += 1
                    if label == "MALICIOUS":
                        mal_full += 1

                if model_source == "short":
                    model_short += 1
                elif model_source == "long":
                    model_long += 1
                continue

            auth_match = AUTH_ONLY_RE.search(line)
            if auth_match:
                auth_only += 1
                fields = parse_kv_pairs(auth_match.group(1))
                try:
                    failed = int(fields.get("auth_failed", "0"))
                except ValueError:
                    failed = 0
                if failed > 0:
                    auth_only_failed += 1

    evaluated = benign + malicious
    coverage = (evaluated / total_detect) if total_detect else 0.0
    skip_rate = (skipped / total_detect) if total_detect else 0.0

    print("=" * 72)
    print("NoEsc ML Listener Summary")
    print("=" * 72)
    print(f"log_file                    : {path}")
    print(f"total_ml_detect_lines       : {total_detect}")
    print(f"evaluated_predictions       : {evaluated}")
    print(f"skipped_min_events          : {skipped}")
    print(f"coverage                    : {coverage:.2%}")
    print(f"skip_rate                   : {skip_rate:.2%}")
    print("-" * 72)
    print(f"benign_predictions          : {benign}")
    print(f"malicious_predictions       : {malicious}")
    print(f"full_length_predictions     : {full_length}")
    print(f"short_inferred_predictions  : {short_inferred}")
    print(f"malicious_full_length       : {mal_full}")
    print(f"malicious_short_inferred    : {mal_short}")
    print(f"model_source_short          : {model_short}")
    print(f"model_source_long           : {model_long}")
    print("-" * 72)
    print(f"auth_only_windows           : {auth_only}")
    print(f"auth_only_with_failures     : {auth_only_failed}")
    print("=" * 72)


if __name__ == "__main__":
    main()
