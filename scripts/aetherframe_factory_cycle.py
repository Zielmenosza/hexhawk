#!/usr/bin/env python3
"""
AetherFrame Advancement Factory — Cycle Reporter
scripts/aetherframe_factory_cycle.py

Purpose:
  Run a bounded local factory cycle report. Does NOT change product code,
  deploy, sign, tag release candidates, delete folders, use credentials,
  run destructive cleanup, or make public claims.

Usage:
  python scripts/aetherframe_factory_cycle.py
  python scripts/aetherframe_factory_cycle.py --run-checks  # run lightweight validations
  python scripts/aetherframe_factory_cycle.py --out-dir docs/aetherframe-runs

Authority boundary:
  GYRE = sole verdict/classification authority.
  AETHERFRAME = factory orchestration, scoring, recommendation only.
  This script = read-only reporter. Verdicts stay with GYRE.
"""

import argparse
import datetime
import os
import subprocess
import sys


# ── Config ───────────────────────────────────────────────────────────────────

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEY_VALIDATION_SCRIPTS = [
    "scripts/release/release-hardening.ps1",
    "scripts/run_ai_workflow_cdp_probe.py",
    "scripts/native_gui_parity_probe.py",
    "scripts/strike_trace_import_native_probe.py",
]

KEY_SMOKE_FOLDERS = [
    "docs/aetherframe-runs",
    "nest_tests/strike_benchmarks",
    "gui-evidence",
    "docs/release-evidence",
]

AUTHORITY_CHECKLIST = [
    ("GYRE is sole verdict authority", "docs/ENGINE_BOUNDARY_DOCTRINE.md"),
    ("AETHERFRAME advisory only", "docs/AETHERFRAME_FACTORY.md"),
    ("NEST evidence orchestration only", "docs/ENGINE_BOUNDARY_DOCTRINE.md"),
    ("No release-candidate tag without full gate", "docs/AETHERFRAME_FACTORY.md"),
    ("No public deployment without explicit approval", "docs/AETHERFRAME_FACTORY.md"),
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def run(cmd, cwd=None, timeout=30):
    """Run a shell command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd or REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"TIMEOUT after {timeout}s", -1
    except Exception as e:
        return "", f"ERROR: {e}", -1


def file_exists(relpath):
    return os.path.isfile(os.path.join(REPO_ROOT, relpath))


def dir_exists(relpath):
    return os.path.isdir(os.path.join(REPO_ROOT, relpath))


def classify_candidate(tags, ci_status, is_clean):
    """
    Advisory classification of current HEAD.
    NOT a GYRE verdict — this is factory posture only.
    """
    if not is_clean:
        return "DIRTY_TREE — not a candidate"
    if ci_status == "red":
        return "CI_FAILING — not a candidate"
    if ci_status == "unknown":
        return "CI_UNKNOWN — treat as not a candidate"
    # green CI + clean tree
    if any("-rc" in t or "release-candidate" in t for t in tags):
        return "RELEASE_CANDIDATE (advisory — requires full gate before public release)"
    return "CLEAN_BUILD — internal tester candidate only (no signing proven)"


def check_gh_available():
    _, _, rc = run("gh --version")
    return rc == 0


def get_ci_status():
    """Return (status_str, run_id, details). status_str: green/red/unknown."""
    if not check_gh_available():
        return "unknown", None, "gh CLI not available"
    stdout, stderr, rc = run("gh run list --limit 5 --json conclusion,headBranch,databaseId,name", timeout=15)
    if rc != 0:
        return "unknown", None, f"gh run list failed: {stderr[:200]}"
    import json
    try:
        runs = json.loads(stdout)
    except Exception:
        return "unknown", None, "could not parse gh run list output"
    # Filter to main branch
    main_runs = [r for r in runs if r.get("headBranch") == "main"]
    if not main_runs:
        return "unknown", None, "no runs found for main"
    latest = main_runs[0]
    conclusion = latest.get("conclusion", "unknown")
    run_id = latest.get("databaseId", "unknown")
    name = latest.get("name", "unknown")
    if conclusion == "success":
        return "green", run_id, f"Latest: {name} ({run_id}) — success"
    elif conclusion == "failure":
        return "red", run_id, f"Latest: {name} ({run_id}) — FAILURE"
    else:
        return "unknown", run_id, f"Latest: {name} ({run_id}) — {conclusion}"


def suggest_next_target(ci_status, tags, is_clean):
    """Advisory suggestion for next factory cycle target."""
    if ci_status == "red":
        return (
            "CI stabilization — CI is failing on main. Fix CI before any new product work.\n"
            "  Known failures (as of 2026-06-30):\n"
            "    1. Yarn workspace install: TypeScript jobs fail because CI uses system yarn 1,\n"
            "       but repo requires Yarn 4 (workspace:* protocol). Fix: corepack enable.\n"
            "    2. Rust ptrace::write: mismatched type in debugger.rs L1790/L1805 on Linux.\n"
            "       nix 0.29 ptrace::write expects c_long as data arg, not *mut _."
        )
    if not is_clean:
        return "Clean working tree — stage or reset outstanding changes before next cycle."
    return (
        "CI is green and tree is clean. Choose next target from:\n"
        "  - Release gate gap: signing, installer smoke, CDP parity\n"
        "  - Authority boundary drift in docs or GUI\n"
        "  - Product capability gap with existing tests\n"
        "  - Test coverage gap for shipped code"
    )


def tests_recommended(ci_status):
    if ci_status == "red":
        return (
            "  - cargo test --workspace (verify Rust ptrace fix compiles and passes)\n"
            "  - yarn workspace hexhawk-ui exec tsc --noEmit (verify TS after install fix)\n"
            "  - yarn workspace hexhawk-ui exec vitest run (verify test suite still passes)\n"
            "  - git diff --check (no whitespace noise in CI fix)"
        )
    return (
        "  - Targeted test for the selected improvement slice\n"
        "  - tsc --noEmit if TypeScript touched\n"
        "  - cargo test --workspace if Rust touched\n"
        "  - git diff --check always"
    )


def release_gate_allowed(ci_status, is_clean):
    if ci_status != "green":
        return False, "CI must be green"
    if not is_clean:
        return False, "Working tree must be clean"
    if not file_exists("docs/TESTER_RELEASE_STATUS.md"):
        return False, "TESTER_RELEASE_STATUS.md missing"
    return False, "Authenticode signing and full release gate not yet proven — not allowed"


# ── Report Generation ─────────────────────────────────────────────────────────

def build_report(run_checks=False):
    lines = []
    now = datetime.datetime.now()
    ts = now.strftime("%Y%m%d-%H%M%S")

    def h1(text):
        lines.append(f"\n# {text}\n")

    def h2(text):
        lines.append(f"\n## {text}\n")

    def row(label, value):
        lines.append(f"- **{label}:** {value}")

    def bullet(text):
        lines.append(f"  {text}")

    # Header
    lines.append(f"# AetherFrame Factory Cycle Report")
    lines.append(f"\nGenerated: {now.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Script: scripts/aetherframe_factory_cycle.py")
    lines.append(f"Repo: {REPO_ROOT}")

    # ── Current HEAD ──
    h2("Current HEAD")
    head_out, _, _ = run("git log --oneline -5")
    for l in head_out.splitlines():
        lines.append(f"  {l}")

    # ── Working Tree Status ──
    h2("Working Tree Status")
    status_out, _, _ = run("git status --short")
    is_clean = not status_out.strip()
    if is_clean:
        lines.append("  Clean — no uncommitted changes.")
    else:
        lines.append("  DIRTY — uncommitted changes present:")
        for l in status_out.splitlines():
            lines.append(f"    {l}")

    # ── Latest Tags ──
    h2("Latest Tags")
    tags_out, _, _ = run("git tag --sort=-creatordate | head -10")
    tags_list = [t.strip() for t in tags_out.splitlines() if t.strip()]
    for t in tags_list:
        lines.append(f"  {t}")

    # ── CI Status ──
    h2("CI Status")
    ci_status, ci_run_id, ci_detail = get_ci_status()
    row("Status", ci_status.upper())
    row("Detail", ci_detail)
    if ci_run_id:
        row("Last run ID", ci_run_id)
        row("View", f"gh run view {ci_run_id}")

    # ── Candidate Classification ──
    h2("Candidate Classification (Advisory)")
    classification = classify_candidate(tags_list, ci_status, is_clean)
    lines.append(f"  {classification}")
    lines.append("")
    lines.append("  NOTE: This is factory posture only. GYRE is sole verdict/classification authority.")
    lines.append("  This classification does not substitute for the full release gate.")

    # ── Known Blockers ──
    h2("Known Blockers")
    blockers = []
    if ci_status == "red":
        blockers.append("[CI] CI is failing on main — see CI Status above")
        blockers.append("[CI] Yarn workspace install: corepack not enabled in CI (workspace:* resolution fails)")
        blockers.append("[CI] Rust ptrace::write type mismatch in debugger.rs (Linux, nix 0.29)")
    if not is_clean:
        blockers.append("[CUSTODY] Working tree is dirty — stage or reset before release gate")

    # Check signing
    tauri_conf_path = os.path.join(REPO_ROOT, "src-tauri", "tauri.conf.json")
    if os.path.isfile(tauri_conf_path):
        with open(tauri_conf_path) as f:
            tc = f.read()
        if "cmd /C echo" in tc or '"signCommand": ""' in tc:
            blockers.append("[SIGNING] tauri.conf.json has no-op signCommand — Authenticode not configured")
    else:
        blockers.append("[SIGNING] src-tauri/tauri.conf.json not found — cannot verify signing config")

    if blockers:
        for b in blockers:
            lines.append(f"  {b}")
    else:
        lines.append("  No known blockers detected by this script.")
        lines.append("  Manual review still required before any release gate.")

    # ── Key Smoke / Release Folders ──
    h2("Key Folders")
    for folder in KEY_SMOKE_FOLDERS:
        exists = dir_exists(folder)
        state = "EXISTS" if exists else "MISSING"
        lines.append(f"  [{state}] {folder}")

    # ── Validation Scripts ──
    h2("Validation Scripts")
    for script in KEY_VALIDATION_SCRIPTS:
        exists = file_exists(script)
        state = "PRESENT" if exists else "MISSING"
        lines.append(f"  [{state}] {script}")

    # ── Optional Lightweight Checks ──
    if run_checks:
        h2("Lightweight Checks (--run-checks)")

        # Python syntax check on this script
        _, err, rc = run(f"python -m py_compile {os.path.join(REPO_ROOT, 'scripts', 'aetherframe_factory_cycle.py')}")
        lines.append(f"  py_compile self-check: {'PASS' if rc == 0 else 'FAIL: ' + err}")

        # git diff --check
        _, err2, rc2 = run("git diff --check")
        lines.append(f"  git diff --check: {'PASS' if rc2 == 0 else 'WARNINGS: ' + err2[:200]}")

        # Rust check (Windows: skipped for Linux ptrace, so just syntax)
        if sys.platform != "linux":
            lines.append("  cargo check: SKIPPED (not Linux — ptrace code is Linux-only, run in CI)")
        else:
            _, err3, rc3 = run("cargo check --workspace", timeout=120)
            lines.append(f"  cargo check: {'PASS' if rc3 == 0 else 'FAIL: ' + err3[:300]}")

    # ── Suggested Next Improvement Slice ──
    h2("Suggested Next Improvement Slice")
    suggestion = suggest_next_target(ci_status, tags_list, is_clean)
    for l in suggestion.splitlines():
        lines.append(f"  {l}")

    # ── Tests Recommended ──
    h2("Tests Recommended for Next Slice")
    for l in tests_recommended(ci_status).splitlines():
        lines.append(f"{l}")

    # ── Authority Boundary Checklist ──
    h2("Authority Boundary Checklist")
    for item, doc in AUTHORITY_CHECKLIST:
        doc_ok = file_exists(doc)
        marker = "OK" if doc_ok else "DOC MISSING"
        lines.append(f"  [{marker}] {item}")
        lines.append(f"          ref: {doc}")

    # ── Release Gate Allowed ──
    h2("Release Gate Allowed?")
    allowed, reason = release_gate_allowed(ci_status, is_clean)
    lines.append(f"  {'YES' if allowed else 'NO'} — {reason}")

    # ── Safety Reminder ──
    h2("Safety Reminder")
    lines.append("  This report is read-only. It does NOT:")
    lines.append("    - Modify product code")
    lines.append("    - Deploy to any endpoint")
    lines.append("    - Sign any artifact")
    lines.append("    - Tag a release candidate")
    lines.append("    - Use credentials")
    lines.append("    - Run destructive cleanup")
    lines.append("    - Make public claims")
    lines.append("")
    lines.append("  GYRE is the sole verdict/classification authority.")
    lines.append("  AETHERFRAME is advisory/factory orchestration only.")

    return "\n".join(lines), ts


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AetherFrame factory cycle reporter")
    parser.add_argument("--run-checks", action="store_true", help="Run lightweight validation checks")
    parser.add_argument("--out-dir", default="docs/aetherframe-runs", help="Output directory for reports")
    parser.add_argument("--stdout", action="store_true", help="Also print report to stdout")
    args = parser.parse_args()

    report, ts = build_report(run_checks=args.run_checks)

    # Ensure output directory exists
    out_dir = os.path.join(REPO_ROOT, args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    # Write report
    report_path = os.path.join(out_dir, f"factory-cycle-{ts}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Report written: {report_path}")

    if args.stdout:
        print("\n" + "=" * 72)
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
