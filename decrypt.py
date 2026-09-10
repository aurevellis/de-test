#!/usr/bin/env python3
"""Unlock a staged interview blob. The interviewer gives you the password."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import stagecrypt

ROOT = Path(__file__).resolve().parent
STAGES = {
    2: (ROOT / "stage2.bin", ROOT / "stage2"),
    3: (ROOT / "stage3.bin", ROOT / "tools"),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt a stage. Ask the interviewer for the password when they say you have reached that stage."
    )
    parser.add_argument("stage", type=int, choices=sorted(STAGES), help="2 or 3")
    parser.add_argument("password", help="password from the interviewer")
    args = parser.parse_args()
    blob_path, dest = STAGES[args.stage]
    if not blob_path.is_file():
        print(f"missing {blob_path.name}", file=sys.stderr)
        return 1
    try:
        stagecrypt.decrypt_dir(blob_path.read_bytes(), args.password, dest)
    except stagecrypt.DecryptError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"stage {args.stage} -> {dest.relative_to(ROOT)}/")
    for path in sorted(p.relative_to(dest) for p in dest.rglob("*") if p.is_file()):
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
