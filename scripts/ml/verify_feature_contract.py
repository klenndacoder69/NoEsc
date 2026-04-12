#!/usr/bin/env python3
"""Verify train-serve feature contract and optional metadata compatibility."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ML_ENGINE_DIR = PROJECT_ROOT / "src" / "ml_engine"
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))

from feature_contract import (  # noqa: E402
    CONTEXT_FEATURE_COLUMNS,
    EVENT_TYPES_INCLUDED,
    FEATURE_CONTRACT_VERSION,
    PAYLOAD_FIELDS,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate NoEsc ML feature contract")
    parser.add_argument(
        "--metadata",
        default="",
        help="Optional path to training metadata.json for compatibility checks.",
    )
    return parser.parse_args()


def verify_metadata(metadata_path: Path) -> None:
    with metadata_path.open("r", encoding="utf-8") as handle:
        meta = json.load(handle)

    expected = {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "payload_fields": list(PAYLOAD_FIELDS),
        "context_feature_columns": list(CONTEXT_FEATURE_COLUMNS),
        "event_types_included": list(EVENT_TYPES_INCLUDED),
    }

    mismatches = []
    for key, expected_value in expected.items():
        actual = meta.get(key)
        if actual != expected_value:
            mismatches.append((key, expected_value, actual))

    if mismatches:
        print("[-] Metadata compatibility check failed:")
        for key, expected_value, actual in mismatches:
            print(f"    {key}: expected={expected_value} actual={actual}")
        raise SystemExit(1)

    print(f"[+] Metadata is compatible: {metadata_path}")


def main() -> None:
    args = parse_args()

    print(f"[+] Feature contract version: {FEATURE_CONTRACT_VERSION}")
    print(f"[+] Payload fields: {list(PAYLOAD_FIELDS)}")
    print(f"[+] Event types: {list(EVENT_TYPES_INCLUDED)}")
    print(f"[+] Context features: {list(CONTEXT_FEATURE_COLUMNS)}")

    if args.metadata:
        verify_metadata(Path(args.metadata))


if __name__ == "__main__":
    main()
