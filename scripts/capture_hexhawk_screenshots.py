#!/usr/bin/env python3
"""Interactive HexHawk screenshot capture helper.

This script is intentionally conservative: it captures the active window when
possible, falls back to full-screen capture when active-window bounds are not
available, backs up existing PNGs before overwrite, and writes a manifest so
manual/docs captions can distinguish native Tauri/WebView2 proof from browser
or unknown runtime screenshots.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ImageGrab
except Exception as exc:  # pragma: no cover - environment guard
    raise SystemExit(
        "Pillow/PIL is required for screenshots. Install with: python -m pip install pillow"
    ) from exc

try:
    import pygetwindow as gw  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    gw = None

try:
    import pyautogui  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pyautogui = None

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "docs" / "assets" / "hexhawk-for-dummies"
MANIFEST_PATH = OUT_DIR / "capture_manifest.json"


@dataclass(frozen=True)
class ShotPlan:
    filename: str
    screen: str
    avoid: str
    caveat: str


PLAN: list[ShotPlan] = [
    ShotPlan(
        "01-launch-home.png",
        "HexHawk launch/home or first visible application screen.",
        "Do not show unrelated windows, private desktop, tokens, license keys, or docs/credentials.md.",
        "Visual orientation only unless native runtime proof is separately recorded.",
    ),
    ShotPlan(
        "02-open-safe-sample.png",
        "Load/Open/Browse view with an authorized safe sample path or file picker.",
        "Avoid private paths/customer names. Use a toy fixture or Challenges/ch76/keygenme.exe only if authorized.",
        "Shows how to select a sample; does not prove analysis correctness.",
    ),
    ShotPlan(
        "03-analysis-workspace.png",
        "Main workspace after a safe sample is loaded.",
        "Avoid unrelated windows and private file paths if possible; crop if needed.",
        "Workspace orientation only; authority remains in GYRE/NEST exports.",
    ),
    ShotPlan(
        "04-strings-view.png",
        "Strings panel after scanning/extracting strings.",
        "Do not capture secrets embedded in a real/private binary. Use a safe sample.",
        "Strings are evidence, not standalone malware proof.",
    ),
    ShotPlan(
        "05-disassembly-view.png",
        "Disassembly workspace/instructions or bounded workspace tabs.",
        "Use safe sample ranges only; avoid private paths.",
        "Disassembly helps analysis but does not change GYRE authority.",
    ),
    ShotPlan(
        "06-gyre-verdict.png",
        "Binary Verdict / Threat Assessment / GYRE-linked verdict display.",
        "Avoid private sample identifiers; verify classification is not overclaimed in captions.",
        "GYRE remains sole verdict authority; screenshot is presentation only.",
    ),
    ShotPlan(
        "07-nest-evidence.png",
        "NEST evidence/session panel if available, or gated/unavailable state if not.",
        "Do not fake Enterprise/NEST access or evidence bundles.",
        "NEST converges/packages evidence; it does not replace GYRE.",
    ),
    ShotPlan(
        "08-aetherframe-lineage.png",
        "AETHERFRAME/Forge uplift or lineage disclosure if visibly available.",
        "Do not invent a lineage view. Capture unavailable/gated state or skip if needed.",
        "AETHERFRAME/Forge are optional and non-authoritative.",
    ),
    ShotPlan(
        "09-report-export.png",
        "Report/CREST export screen.",
        "Do not capture private report notes, secrets, or customer data.",
        "CREST/report export packages evidence; it does not create new authority.",
    ),
    ShotPlan(
        "10-authority-fields.png",
        "Exported report authority fields such as source_engine or gyre_is_sole_verdict_source.",
        "Do not manually fabricate report fields; capture only real exported/generated output.",
        "If typed NEST evidence bundle is absent, record that honestly.",
    ),
    ShotPlan(
        "11-cli-identify.png",
        "Terminal showing nest_cli identify against an authorized safe sample.",
        "Keep only the relevant command/output visible; avoid private shell history/path details.",
        "CLI smoke identifies file facts; it is not a malware verdict.",
    ),
    ShotPlan(
        "12-gated-state.png",
        "A gated feature state such as Enterprise/NEST gating if applicable.",
        "Do not expose license keys or account details.",
        "Gating is product access control, not an authority hierarchy.",
    ),
    ShotPlan(
        "13-troubleshooting-native-runtime.png",
        "Native/browser runtime diagnostic indicators if visible.",
        "Avoid devtools secrets, env vars, unrelated tabs, or token-bearing URLs.",
        "Native proof requires explicit evidence; browser screenshots are UI orientation only.",
    ),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def backup_existing(out_dir: Path) -> Path | None:
    existing = [out_dir / p.filename for p in PLAN if (out_dir / p.filename).exists()]
    if not existing:
        return None
    backup_dir = out_dir / ("placeholder-backup-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    backup_dir.mkdir(parents=True, exist_ok=False)
    for path in existing:
        shutil.copy2(path, backup_dir / path.name)
    return backup_dir


def active_window_bbox() -> tuple[int, int, int, int] | None:
    if gw is None:
        return None
    try:
        win = gw.getActiveWindow()
        if not win:
            return None
        left, top, width, height = int(win.left), int(win.top), int(win.width), int(win.height)
        if width <= 0 or height <= 0:
            return None
        return (left, top, left + width, top + height)
    except Exception:
        return None


def capture_image(method: str) -> tuple[Image.Image, str, dict[str, Any]]:
    if method == "active-window":
        bbox = active_window_bbox()
        if bbox:
            return ImageGrab.grab(bbox=bbox), "active-window", {"bbox": bbox}
        # fall through to full-screen if active window unavailable
    if method == "pyautogui" and pyautogui is not None:
        img = pyautogui.screenshot()
        return img, "full-screen", {"fallback_from": method}
    img = ImageGrab.grab()
    return img, "full-screen", {"fallback_from": method}


def load_manifest() -> dict[str, Any]:
    if MANIFEST_PATH.exists():
        try:
            return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {"entries": []}
    return {"entries": []}


def save_manifest(manifest: dict[str, Any]) -> None:
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def prompt_choice(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(prompt + suffix + ": ").strip()
    return value or default


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    backup_dir = None if args.no_backup else backup_existing(OUT_DIR)

    manifest = load_manifest()
    run_record = {
        "started_at": now_iso(),
        "script": str(Path(__file__).resolve()),
        "output_dir": str(OUT_DIR),
        "backup_dir": str(backup_dir) if backup_dir else None,
        "operator_runtime_mode_default": args.runtime_mode,
        "sample_default": args.sample,
        "entries": [],
    }

    print("HexHawk screenshot capture helper")
    print(f"Output: {OUT_DIR}")
    if backup_dir:
        print(f"Backed up existing images to: {backup_dir}")
    print("Safety: close credentials, tokens, license keys, private customer data, and unrelated windows before capture.")
    print("Press Enter at each step to capture, type 'skip' to record not captured, or Ctrl+C to stop.\n")

    for idx, shot in enumerate(PLAN, start=1):
        print("=" * 80)
        print(f"{idx:02d}/{len(PLAN)} target: {shot.filename}")
        print(f"Screen should show: {shot.screen}")
        print(f"Avoid: {shot.avoid}")
        print(f"Caveat: {shot.caveat}")
        runtime_mode = prompt_choice(
            "Runtime mode for this shot (native-tauri, browser-dev, unknown, not-captured)",
            args.runtime_mode,
        )
        sample = prompt_choice("Sample/source shown", args.sample)
        note = prompt_choice("Crop/redaction/privacy notes", "none")
        command = input("Press Enter to capture, or type skip: ").strip().lower()
        entry: dict[str, Any] = {
            "filename": shot.filename,
            "timestamp": now_iso(),
            "planned_screen": shot.screen,
            "runtime_mode": runtime_mode,
            "source_sample": sample,
            "secrets_private_paths_visible": "operator-reviewed-no" if note == "none" else "operator-reviewed-see-notes",
            "crop_redaction_notes": note,
            "validation_caveats": shot.caveat,
        }
        if command == "skip" or runtime_mode == "not-captured":
            entry.update({"status": "not-captured", "capture_method": "none", "size_bytes": 0})
            print(f"Recorded not captured: {shot.filename}")
        else:
            time.sleep(args.delay)
            image, method_used, meta = capture_image(args.method)
            target = OUT_DIR / shot.filename
            image.save(target)
            entry.update({
                "status": "captured",
                "capture_method": method_used,
                "capture_meta": meta,
                "size_bytes": target.stat().st_size,
                "width": image.width,
                "height": image.height,
            })
            print(f"Saved {target} ({target.stat().st_size} bytes, {method_used})")
        run_record["entries"].append(entry)
        manifest.setdefault("entries", []).append(entry)
        manifest.setdefault("runs", []).append(run_record) if False else None
        save_manifest({"last_run": run_record, "entries": manifest.get("entries", [])})

    run_record["finished_at"] = now_iso()
    current = load_manifest()
    current["last_run"] = run_record
    save_manifest(current)
    print(f"\nManifest written: {MANIFEST_PATH}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", choices=["active-window", "pyautogui", "full-screen"], default="active-window")
    parser.add_argument("--runtime-mode", choices=["native-tauri", "browser-dev", "unknown", "not-captured"], default="unknown")
    parser.add_argument("--sample", default="Challenges/ch76/keygenme.exe")
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--no-backup", action="store_true")
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(run(parse_args(sys.argv[1:])))
