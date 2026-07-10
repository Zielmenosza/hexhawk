#!/usr/bin/env python3
"""Minimal HexHawk analysis benchmark for tiny safe synthetic fixtures.

Emits only metrics computed from local ground truth: DecodeSuccessRate,
BadByteRate, CFGNodeCount, CFGEdgeCount, generated_at, and commit.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC_TAURI = REPO / "src-tauri"
OUT_DIR = REPO / "docs" / "metrics"

FIXTURES = [
    {
        "name": "x86_nop_mov_ret",
        "bytes": bytes([0x90, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]),
        "offset": 0,
        "length": 7,
    },
    {
        "name": "x86_conditional_branch_ret",
        "bytes": bytes([0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3]),
        "offset": 0,
        "length": 6,
    },
    {
        "name": "x86_call_ret",
        "bytes": bytes([0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3]),
        "offset": 0,
        "length": 6,
    },
]


def run_json(args: list[str]) -> dict:
    completed = subprocess.run(
        args,
        cwd=SRC_TAURI,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return json.loads(completed.stdout)


def git_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()


def main() -> None:
    fixtures = []
    with tempfile.TemporaryDirectory(prefix="hexhawk-analysis-benchmark-") as tmp:
        tmp_path = Path(tmp)
        for fixture in FIXTURES:
            sample = tmp_path / f"{fixture['name']}.bin"
            sample.write_bytes(fixture["bytes"])
            disassembly = run_json([
                "cargo", "run", "--quiet", "--bin", "nest_cli", "--",
                "disassemble", str(sample), str(fixture["offset"]), str(fixture["length"]),
            ])
            cfg = run_json([
                "cargo", "run", "--quiet", "--bin", "nest_cli", "--",
                "cfg", str(sample), str(fixture["offset"]), str(fixture["length"]),
            ])
            byte_count = len(fixture["bytes"])
            bad_bytes = int(disassembly.get("bad_bytes", 0))
            fixtures.append({
                "name": fixture["name"],
                "byte_count": byte_count,
                "DecodeSuccessRate": round((byte_count - bad_bytes) / byte_count, 6),
                "BadByteRate": round(bad_bytes / byte_count, 6),
                "CFGNodeCount": len(cfg.get("nodes", [])),
                "CFGEdgeCount": len(cfg.get("edges", [])),
            })

    payload = {
        "schema": "hexhawk.analysis_baseline.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commit": git_head(),
        "fixtures": fixtures,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = OUT_DIR / f"hexhawk-analysis-baseline-{stamp}.json"
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
