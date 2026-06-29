"""Launch wrapper for the installed native HexHawk AI workflow CDP probe.

This is QA/probe-support tooling, not production app code. It starts a local
installed HexHawk build with WebView2 remote debugging enabled, waits for CDP
with a hard timeout, runs ai_workflow_cdp_probe.py, and cleans up only
path-verified processes under INSTALL_DIR. Local-development defaults can be
overridden with INSTALL_DIR, CDP_PORT, PROBE_TIMEOUT, KEEP_HEXHAWK, OUTDIR, and
CDP_READY_TIMEOUT.
"""

import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

INSTALL_DIR = pathlib.Path(os.environ.get("INSTALL_DIR", r"D:\Project\HexHawk-ai-probe-install"))
CDP_PORT = int(os.environ.get("CDP_PORT", "9500"))
PROBE_TIMEOUT = int(os.environ.get("PROBE_TIMEOUT", "240"))
CDP_READY_TIMEOUT = float(os.environ.get("CDP_READY_TIMEOUT", "30"))
KEEP_HEXHAWK = os.environ.get("KEEP_HEXHAWK", "0").lower() in {"1", "true", "yes"}
OUTDIR = pathlib.Path(os.environ.get("OUTDIR", r"D:\Project\HexHawk-ai-probe-results"))
PROBE_SCRIPT = pathlib.Path(__file__).with_name("ai_workflow_cdp_probe.py")
EXE = INSTALL_DIR / "hexhawk-backend.exe"


def powershell(script: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def kill_installed_hexhawk() -> None:
    # Path-verified cleanup only: do not kill developer-tree HexHawk processes.
    install_prefix = str(INSTALL_DIR).replace("'", "''")
    ps = (
        "Get-Process hexhawk-backend -EA SilentlyContinue | "
        f"Where-Object {{ $_.Path -like '{install_prefix}*' }} | "
        "Stop-Process -Force -EA SilentlyContinue"
    )
    powershell(ps, timeout=20)


def wait_for_cdp() -> list[dict]:
    last_error = None
    url = f"http://127.0.0.1:{CDP_PORT}/json/list"
    deadline = time.time() + CDP_READY_TIMEOUT
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                pages = json.loads(resp.read())
            if pages:
                return pages
        except Exception as exc:  # noqa: BLE001 - diagnostic wrapper
            last_error = repr(exc)
        time.sleep(0.25)
    raise RuntimeError(f"CDP_NOT_READY after {CDP_READY_TIMEOUT}s {last_error}")


def main() -> int:
    if not EXE.exists():
        print(f"ERROR missing executable: {EXE}", file=sys.stderr)
        return 2
    if not PROBE_SCRIPT.exists():
        print(f"ERROR missing probe script: {PROBE_SCRIPT}", file=sys.stderr)
        return 2

    kill_installed_hexhawk()

    env = os.environ.copy()
    env["INSTALL_DIR"] = str(INSTALL_DIR)
    env["CDP_PORT"] = str(CDP_PORT)
    env["OUTDIR"] = str(OUTDIR)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={CDP_PORT} --remote-allow-origins=*"
    )

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    proc = subprocess.Popen(
        [str(EXE)],
        cwd=str(INSTALL_DIR),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )

    try:
        pages = wait_for_cdp()
        print(f"CDP_READY pages={len(pages)} title={pages[0].get('title')!r} pid={proc.pid}", flush=True)
        probe = subprocess.run(
            [sys.executable, str(PROBE_SCRIPT)],
            cwd=str(PROBE_SCRIPT.parent.parent),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=PROBE_TIMEOUT,
        )
        print(probe.stdout, end="")
        print(f"PROBE_EXIT {probe.returncode}", flush=True)
        return probe.returncode
    except subprocess.TimeoutExpired as exc:
        print(f"PROBE_TIMEOUT after {PROBE_TIMEOUT}s", file=sys.stderr)
        if exc.stdout:
            print(exc.stdout, end="")
        return 124
    finally:
        if KEEP_HEXHAWK:
            print(f"KEEP_HEXHAWK pid={proc.pid}", flush=True)
        else:
            if proc.poll() is None:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    proc.kill()
            kill_installed_hexhawk()


if __name__ == "__main__":
    raise SystemExit(main())
