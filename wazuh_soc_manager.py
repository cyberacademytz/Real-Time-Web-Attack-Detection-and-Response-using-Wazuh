#!/usr/bin/env python3
"""
WAZUH SOC DEMO MANAGER  -  Author: www.tca.ac.tz  -  Version 1.0.0

RUNS ON:  the Wazuh Server (installs and operates the Wazuh manager, indexer
          and dashboard - a single-node SOC stack for a training lab).

FOR AUTHORIZED SECURITY TRAINING USE ONLY. This tool installs a system that
automatically fires live firewall rules against IPs it judges to be
attackers (Wazuh Active Response). Keep it on an isolated lab network that
you own or are explicitly authorized to test - never production or
internet-facing.

Run:   sudo python3 wazuh_soc_manager.py

Menu:  1  Setup / repair       - installs the full Wazuh stack automatically
       2  Response ON / OFF    - toggle live Active Response blocking
       3  Live alert view      - attacker IP, rule, severity, block events
       4  Summary              - totals by category, top source IPs
       5  Health check         - services, agent, dashboard, auto-repair
       6  Attacker cheat-sheet - ready-to-copy hydra/nikto/sqlmap commands
       7  Tools                - clear alerts, show config, reset, creds

Fully automated: re-execs itself with sudo, waits out apt/dpkg locks,
repairs broken packages, regenerates partial TLS certs, retries a stuck
indexer (memory / vm.max_map_count), and restarts the stack in dependency
order when the dashboard stalls. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shlex
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "1.0.0"
AUTHOR = "www.tca.ac.tz"

# Single source of truth for the Wazuh version - manager, indexer and
# dashboard here, and the value Script B (the victim's agent) must match.
WAZUH_VERSION = "4.9.2"
WAZUH_INSTALL_SCRIPT_URL = "https://packages.wazuh.com/4.9/wazuh-install.sh"

APP_NAME = "wazuh_soc_manager"
STATE_DIR = Path("/etc/wazuh-soc-lab")
STATE_FILE = STATE_DIR / "state.json"
BACKUP_DIR = STATE_DIR / "config_backups"
ERROR_LOG = STATE_DIR / "error.log"
CREDS_FILE = Path("/root/wazuh-soc-lab-credentials.txt")

OSSEC_CONF = Path("/var/ossec/etc/ossec.conf")
ALERTS_JSON = Path("/var/ossec/logs/alerts/alerts.json")

REQUIRED_PORTS = {443: "dashboard", 1514: "agent event data", 1515: "agent enrollment"}

AR_START_MARKER = "<!-- BEGIN wazuh-soc-lab Active Response (ssh brute force) -->"
AR_END_MARKER = "<!-- END wazuh-soc-lab Active Response (ssh brute force) -->"
FALLBACK_SSHD_BRUTEFORCE_RULE_ID = "5712"
AR_DEFAULT_TIMEOUT_SECONDS = 60

REEXEC_MARKER = "_WAZUH_SOC_MANAGER_REEXEC"
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

# --------------------------------------------------------------------------- #
# terminal / layout helpers (colour, centering, clearing - shared look with
# the other lab tools: owasp_lab_manager.py and waf_demo_manager.py)
# --------------------------------------------------------------------------- #
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
UTF8 = "utf" in (getattr(sys.stdout, "encoding", "") or "").lower()
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"
COLOR256 = USE_COLOR and ("256" in os.environ.get("TERM", "") or bool(os.environ.get("COLORTERM")))
CONTENT_WIDTH = 100


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def dim(t): return _c("2", t)
def bold(t): return _c("1", t)
def green(t): return _c("1;32", t)
def red(t): return _c("1;31", t)
def yellow(t): return _c("1;33", t)
def cyan(t): return _c("1;36", t)
def magenta(t): return _c("1;35", t)


def vlen(s: str) -> int:
    return len(ANSI_RE.sub("", s))


def tsize():
    return shutil.get_terminal_size((100, 30))


def margin() -> str:
    cols = tsize().columns
    width = min(CONTENT_WIDTH, cols - 2)
    return " " * max(0, (cols - width) // 2)


def out(text: str = "") -> None:
    m = margin()
    for line in str(text).split("\n"):
        print(m + line)


def ok(msg: str) -> None: out(green("[ OK ] ") + msg)
def warn(msg: str) -> None: out(yellow("[WARN] ") + msg)
def err(msg: str) -> None: out(red("[FAIL] ") + msg)
def info(msg: str) -> None: out(cyan("[INFO] ") + msg)
def step(msg: str) -> None: out(cyan("==> ") + msg)


def header(title: str) -> None:
    out()
    out(cyan(("━━ " if UTF8 else "== ") + title.upper() + (" ━━" if UTF8 else " ==")))
    out()


def clear_screen() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[H\033[2J\033[3J")
        sys.stdout.flush()


def center_line(text: str) -> str:
    pad = max(0, (tsize().columns - vlen(text)) // 2)
    return " " * pad + text


def center_block(lines: List[str]) -> Tuple[List[str], int]:
    width = max((vlen(l) for l in lines), default=0)
    pad = max(0, (tsize().columns - width) // 2)
    return [" " * pad + l for l in lines], pad


def box(lines: List[str], title: str = "") -> List[str]:
    tl, tr, bl, br, h, v = ("╔", "╗", "╚", "╝", "═", "║") if UTF8 else ("+", "+", "+", "+", "-", "|")
    inner = max([vlen(l) for l in lines] + [vlen(title) + 6]) + 4
    if title:
        side = inner - vlen(title) - 2
        left = side // 2
        top = cyan(tl + h * left + " ") + cyan(bold(title)) + cyan(" " + h * (side - left) + tr)
    else:
        top = cyan(tl + h * inner + tr)
    body = [cyan(v) + "  " + l + " " * (inner - vlen(l) - 2) + cyan(v) for l in lines]
    return [top] + body + [cyan(bl + h * inner + br)]


# Block-letter "WAZUH" logo (ANSI Shadow style), matching the look of the
# other lab tools' banners.
ART = [
    "██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗",
    "██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║",
    "██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║",
    "██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║",
    "╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║",
    " ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝",
]
GRADIENT_256 = ["38;5;46", "38;5;40", "38;5;34", "38;5;28", "38;5;22", "38;5;22"]
GRADIENT_8 = ["1;32", "1;32", "32", "32", "2;32", "2;32"]


def banner_lines(compact: bool) -> List[str]:
    if compact or not UTF8:
        t = "WAZUH SOC DEMO MANAGER"
        line = (_c("1;32", "▌ ") if UTF8 else "") + _c("1;37", t) + (_c("1;32", " ▐") if UTF8 else "")
        sub = (dim("Manager Console - Wazuh Server") + dim("  |  ") + yellow(f"Author: {AUTHOR}") +
               dim("  |  ") + yellow(f"v{VERSION}"))
        return [center_line(line), center_line(sub)]
    grad = GRADIENT_256 if COLOR256 else GRADIENT_8
    lines = [center_line(_c(grad[i], a)) for i, a in enumerate(ART)]
    lines.append("")
    lines.append(center_line(green("S O C   D E M O   L A B   -   M A N A G E R   C O N S O L E")))
    lines.append(center_line(dim(f"Wazuh {WAZUH_VERSION}  |  manager + indexer + dashboard, single-node")))
    lines.append("")
    lines.append(center_line(yellow("Author: " + AUTHOR) + dim("   │   ") + yellow("Version: " + VERSION)))
    lines.append(center_line(red("FOR AUTHORIZED SECURITY TRAINING USE ONLY")))
    return lines


def print_screen_top(compact: bool, extra: Optional[List[str]] = None, vcenter_height: int = 0) -> None:
    clear_screen()
    lines = banner_lines(compact) + [""] + (extra or [])
    if vcenter_height:
        total = len(lines) + vcenter_height
        for _ in range(max(0, (tsize().lines - total) // 2 - 1)):
            print()
    for l in lines:
        print(l)


class Spinner:
    """Context-manager progress spinner, centered under the content margin."""
    def __init__(self, label: str):
        self.label = label
        self._i = 0
        self._frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if UTF8 else "|/-\\"
        self._start = time.time()

    def __enter__(self):
        self.tick()
        return self

    def tick(self, suffix: str = "") -> None:
        if not sys.stdout.isatty():
            return
        frame = self._frames[self._i % len(self._frames)]
        self._i += 1
        elapsed = int(time.time() - self._start)
        sys.stdout.write("\r" + margin() + cyan(frame) + f" {self.label} ({elapsed}s) {suffix}\033[K")
        sys.stdout.flush()

    def __exit__(self, *exc):
        if sys.stdout.isatty():
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


def pause() -> None:
    try:
        input(margin() + dim("Press Enter to continue ..."))
    except (EOFError, KeyboardInterrupt):
        print()


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_error_full(context: str, exc: BaseException) -> None:
    try:
        ensure_state_dir()
        with open(ERROR_LOG, "a") as f:
            f.write(f"\n----- {now_iso()} :: {context} -----\n")
            f.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# state (atomic JSON writes)
# --------------------------------------------------------------------------- #
DEFAULT_STATE = {
    "installed": False,
    "wazuh_version": WAZUH_VERSION,
    "response_enabled": False,
    "whitelist": None,
    "credentials_file": str(CREDS_FILE),
    "victim_ip": None,
    "victim_hostname": None,
    "server_ip": None,
    "install_completed_at": None,
    "last_repair_at": None,
}


def load_state() -> Dict[str, Any]:
    ensure_state_dir()
    if not STATE_FILE.exists():
        return dict(DEFAULT_STATE)
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        merged = dict(DEFAULT_STATE)
        merged.update(data)
        return merged
    except Exception as e:
        log_error_full("load_state (corrupt state file, resetting)", e)
        return dict(DEFAULT_STATE)


def save_state(state: Dict[str, Any]) -> None:
    ensure_state_dir()
    tmp = STATE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE_FILE)


# --------------------------------------------------------------------------- #
# shell helpers
# --------------------------------------------------------------------------- #
class CmdResult:
    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(cmd, timeout: Optional[int] = 120, check: bool = False, input_text: Optional[str] = None,
        env: Optional[Dict[str, str]] = None) -> CmdResult:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input=input_text, env=env)
        if check and proc.returncode != 0:
            raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
        return CmdResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as e:
        return CmdResult(124, e.stdout or "", f"timed out after {timeout}s")


def which(binary: str) -> bool:
    return shutil.which(binary) is not None


def dry_run_announce(action: str) -> None:
    out(magenta("[dry-run] would: ") + action)


# --------------------------------------------------------------------------- #
# pre-flight checks
# --------------------------------------------------------------------------- #
SUPPORTED_CODENAMES = {"jammy", "noble"}


def read_os_release() -> Dict[str, str]:
    data = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    k, v = line.split("=", 1)
                    data[k] = v.strip('"')
    except FileNotFoundError:
        pass
    return data


def check_os() -> None:
    osr = read_os_release()
    codename = osr.get("VERSION_CODENAME", "")
    pretty = osr.get("PRETTY_NAME", "unknown")
    if osr.get("ID") != "ubuntu" or codename not in SUPPORTED_CODENAMES:
        warn(f"Detected '{pretty}'. This script is validated against Ubuntu 22.04 (jammy) / "
             f"24.04 (noble) LTS, which is what Wazuh {WAZUH_VERSION} officially supports. "
             f"Continuing anyway.")
    else:
        ok(f"OS check passed: {pretty}")


def check_resources() -> Dict[str, Any]:
    mem_kb = None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_kb = int(line.split()[1])
                    break
    except Exception:
        pass
    mem_gb = (mem_kb / 1024 / 1024) if mem_kb else None

    disk_free_gb = None
    try:
        disk_free_gb = shutil.disk_usage("/").free / (1024 ** 3)
    except Exception:
        pass

    cores = os.cpu_count() or 1

    if mem_gb is not None:
        if mem_gb < 4:
            err(f"RAM is {mem_gb:.1f} GB. Below ~4 GB the Wazuh indexer is very likely to fail "
                f"to start. Strongly recommend resizing the VM before continuing.")
        elif mem_gb < 8:
            warn(f"RAM is {mem_gb:.1f} GB. ~8 GB+ is recommended for a smooth demo; continuing "
                 f"anyway - expect the indexer self-heal path to run.")
        else:
            ok(f"RAM: {mem_gb:.1f} GB")
    else:
        warn("Could not determine total RAM from /proc/meminfo.")

    if disk_free_gb is not None:
        if disk_free_gb < 50:
            warn(f"Free disk is {disk_free_gb:.1f} GB (recommend 50+ GB free).")
        else:
            ok(f"Free disk: {disk_free_gb:.1f} GB")

    ok(f"CPU cores: {cores}")
    return {"mem_gb": mem_gb, "disk_free_gb": disk_free_gb, "cores": cores}


def set_max_map_count(dry_run: bool = False) -> bool:
    target_file = Path("/etc/sysctl.d/99-wazuh-soc-lab.conf")
    desired = "vm.max_map_count=262144\n"
    if dry_run:
        dry_run_announce(f"write {target_file} with '{desired.strip()}' and sysctl --system")
        return True
    try:
        current = target_file.read_text() if target_file.exists() else ""
    except Exception:
        current = ""
    if current.strip() != desired.strip():
        target_file.write_text(desired)
    r = run(["sysctl", "--system"])
    if not r.ok:
        warn(f"sysctl --system returned nonzero: {r.stderr.strip()}")
    live_val = run(["sysctl", "-n", "vm.max_map_count"]).stdout.strip()
    if live_val == "262144":
        ok("vm.max_map_count=262144 set (persisted + live).")
        return True
    warn(f"vm.max_map_count currently reports '{live_val}', expected 262144. Indexer-start "
         f"repair logic covers this too.")
    return False


def check_ufw_and_open_ports(dry_run: bool = False) -> None:
    if not which("ufw"):
        info("ufw not installed; skipping firewall port step.")
        return
    status = run(["ufw", "status"])
    if "Status: active" not in status.stdout:
        info("ufw present but inactive; required ports are not blocked.")
        return
    info("ufw is active - opening required ports.")
    for port, label in REQUIRED_PORTS.items():
        if dry_run:
            dry_run_announce(f"ufw allow {port}/tcp  # {label}")
            continue
        r = run(["ufw", "allow", f"{port}/tcp"])
        (ok if r.ok else warn)(f"ufw: {'allowed' if r.ok else 'FAILED to allow'} {port}/tcp ({label})")


def check_repo_reachability() -> bool:
    host = "packages.wazuh.com"
    try:
        socket.create_connection((host, 443), timeout=5).close()
        ok(f"Wazuh package repository ({host}) is reachable.")
        return True
    except OSError as e:
        warn(f"Cannot reach {host}:443 ({e}).")
        out(yellow("OFFLINE INSTALL GUIDANCE:"))
        out(textwrap.indent(textwrap.dedent(f"""\
            This lab network looks isolated from the internet - fine for attack
            traffic, but the Wazuh install script needs to fetch packages once.
              1) Temporarily bridge the Wazuh Server to a NAT/internet-reachable
                 network, run Setup, then switch it back to the isolated network.
              2) Pre-stage the .deb packages for wazuh-manager, wazuh-indexer and
                 wazuh-dashboard (version {WAZUH_VERSION}) on this host and install
                 with `dpkg -i` + `apt-get install -f`.
              3) Stand up a local apt mirror/proxy reachable from this network.""").rstrip(), "  "))
        return False


def run_preflight(dry_run: bool = False) -> None:
    step("Running pre-flight checks")
    check_os()
    check_resources()
    set_max_map_count(dry_run)
    check_ufw_and_open_ports(dry_run)
    check_repo_reachability()


# --------------------------------------------------------------------------- #
# root elevation
# --------------------------------------------------------------------------- #
def ensure_root() -> None:
    if os.geteuid() == 0:
        return
    if os.environ.get(REEXEC_MARKER) == "1":
        err("Already attempted sudo re-exec and still not root. Aborting to avoid an infinite "
            "loop. Run this script with sudo manually.")
        sys.exit(1)
    if not which("sudo"):
        err("This script needs root privileges and 'sudo' is not available. Re-run as root.")
        sys.exit(1)
    info("Not running as root - re-executing with sudo...")
    env = os.environ.copy()
    env[REEXEC_MARKER] = "1"
    os.execvpe("sudo", ["sudo", "-E", sys.executable] + sys.argv, env)


# --------------------------------------------------------------------------- #
# risk acknowledgement
# --------------------------------------------------------------------------- #
CONFIRM_PHRASE = "I UNDERSTAND"


def risk_acknowledgement(accept_risk: bool = False) -> bool:
    if accept_risk:
        info("--accept-risk supplied: skipping interactive risk prompt.")
        return True
    header("Security notice")
    out(f"This Setup will:")
    out(f" * generate a self-signed TLS certificate and an admin password shown to you ONCE\n"
        f"   (also saved to {CREDS_FILE});")
    out(f" * install and can enable a system (Wazuh Active Response) that AUTOMATICALLY issues\n"
        f"   live firewall rules against IP addresses it judges to be attackers;")
    out(f" * is intended for an ISOLATED lab network only - do not run this on a production\n"
        f"   host or anywhere internet-facing.")
    out()
    try:
        typed = input(margin() + f"Type '{CONFIRM_PHRASE}' to proceed: ").strip()
    except EOFError:
        typed = ""
    if typed != CONFIRM_PHRASE:
        err("Confirmation phrase not matched. Aborting Setup.")
        return False
    return True


# --------------------------------------------------------------------------- #
# install pipeline
# --------------------------------------------------------------------------- #
def apt_lock_held() -> bool:
    for lockfile in ("/var/lib/dpkg/lock-frontend", "/var/lib/apt/lists/lock", "/var/lib/dpkg/lock"):
        if run(["fuser", lockfile], timeout=10).returncode == 0:
            return True
    return False


def wait_for_apt_lock(timeout_s: int = 300, dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce(f"wait for apt/dpkg lock to free, up to {timeout_s}s")
        return True
    if not apt_lock_held():
        return True
    step(f"apt/dpkg lock is held by another process (likely unattended-upgrades) - waiting up "
         f"to {timeout_s}s...")
    waited = 0
    with Spinner("Waiting for apt/dpkg lock") as sp:
        while waited < timeout_s:
            if not apt_lock_held():
                ok("apt/dpkg lock released.")
                return True
            time.sleep(5)
            waited += 5
            sp.tick(f"({waited}s)")
    warn("apt/dpkg lock still held after timeout; proceeding anyway.")
    return False


def repair_broken_packages(dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce("dpkg --configure -a && apt-get install -f -y")
        return True
    step("Running package-repair sequence (dpkg --configure -a, apt-get -f install)")
    run(["dpkg", "--configure", "-a"], timeout=300)
    r = run(["apt-get", "install", "-f", "-y"], timeout=300)
    (ok if r.ok else warn)("Package repair sequence " + ("completed." if r.ok
                            else f"returned nonzero: {r.stderr.strip()[:300]}"))
    return r.ok


def download_install_script(dry_run: bool = False) -> Path:
    dest = Path("/tmp/wazuh-install.sh")
    if dry_run:
        dry_run_announce(f"curl -so {dest} {WAZUH_INSTALL_SCRIPT_URL}")
        return dest
    if dest.exists() and dest.stat().st_size > 0:
        info(f"Reusing cached installer at {dest}")
        return dest
    r = run(["curl", "-sSL", "-o", str(dest), WAZUH_INSTALL_SCRIPT_URL], timeout=120)
    if not r.ok or not dest.exists():
        raise RuntimeError(f"Failed to download Wazuh install script: {r.stderr}")
    os.chmod(dest, 0o750)
    return dest


def detect_partial_cert_state() -> bool:
    cert_paths = [Path("/etc/wazuh-indexer/certs"), Path("/etc/wazuh-dashboard/certs")]
    return any(p.exists() and any(p.iterdir()) for p in cert_paths if p.exists())


def _run_with_live_spinner(cmd: List[str], label: str, timeout_s: Optional[int] = None) -> Tuple[str, int]:
    """Run `cmd`, streaming its combined stdout/stderr, while keeping the
    spinner's elapsed-time counter ticking on a real 0.2s clock rather than
    on `readline()`.

    Why this exists: a naive "read a line, then tick" loop freezes the
    on-screen timer for as long as the child process stays quiet - which,
    for the Wazuh installer, can be several minutes while apt-get silently
    downloads/unpacks the large wazuh-indexer package (its progress bar is
    disabled once stdout isn't a real terminal). That looked like the
    install had hung. Here, a background thread does the blocking
    `readline()` work and hands lines to the main thread through a queue;
    the main thread ticks every 0.2s regardless, and shows the most recent
    real output line next to the spinner so there's always visible
    evidence of what is actually happening.
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line_q: "queue.Queue[Optional[str]]" = queue.Queue()

    def reader() -> None:
        try:
            for line in iter(proc.stdout.readline, ""):
                line_q.put(line)
        finally:
            line_q.put(None)  # sentinel: child's stdout closed (process finished)

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    out_lines: List[str] = []
    last_line = ""
    start = time.time()
    reader_done = False
    with Spinner(label) as sp:
        while not reader_done:
            if timeout_s is not None and (time.time() - start) > timeout_s:
                proc.kill()
                break
            try:
                line = line_q.get(timeout=0.2)
            except queue.Empty:
                sp.tick(dim(last_line[-60:]) if last_line else "")
                continue
            if line is None:
                reader_done = True
                break
            out_lines.append(line)
            last_line = line.strip()
            sp.tick(dim(last_line[-60:]))

    rc = proc.wait()
    return "".join(out_lines), rc


def run_official_installer(dry_run: bool = False) -> bool:
    script_path = download_install_script(dry_run)
    state = load_state()

    cert_flag = []
    if detect_partial_cert_state() and not state["installed"]:
        warn("Detected leftover certificate material from a previous incomplete run. "
             "Regenerating cleanly (-o/--overwrite) instead of failing on 'already exists'.")
        cert_flag = ["-o"]

    if dry_run:
        dry_run_announce(f"bash {script_path} -a {' '.join(cert_flag)} "
                          "(single-node manager+indexer+dashboard install)")
        return True

    step(f"Installing Wazuh {WAZUH_VERSION} (manager + indexer + dashboard, single-node)... "
         f"this commonly takes 5-20 minutes - the indexer package is the largest piece.")
    full_out, rc = _run_with_live_spinner(
        ["bash", str(script_path), "-a"] + cert_flag,
        "Running official Wazuh installer",
    )
    if rc != 0:
        err("Wazuh installer exited with a nonzero status.")
        repair_broken_packages(dry_run)
        info("Retrying installer once after package repair...")
        retry_out, retry_rc = _run_with_live_spinner(
            ["bash", str(script_path), "-a", "-o"],
            "Retrying Wazuh installer",
        )
        if retry_rc != 0:
            log_path = STATE_DIR / "wazuh-install-failure.log"
            ensure_state_dir()
            log_path.write_text(full_out + "\n----RETRY----\n" + retry_out)
            err(f"Install still failing after one repair+retry. Full output saved to {log_path}.")
            return False
        # The retry is what actually succeeded - its output (which includes
        # the real generated credentials) is what must be saved below, not
        # the first, failed attempt's output.
        full_out = retry_out

    ensure_state_dir()
    with open(CREDS_FILE, "w") as f:
        f.write(f"# Generated {now_iso()}\n")
        f.write(full_out)
    os.chmod(CREDS_FILE, 0o600)
    ok(f"Install finished. Full installer output (including generated credentials) saved to "
       f"{CREDS_FILE} (root-only readable).")
    return True


def detect_indexer_memory_or_mapcount_failure(service_name: str = "wazuh-indexer") -> bool:
    r = run(["journalctl", "-u", service_name, "-n", "100", "--no-pager"], timeout=20)
    text = r.stdout.lower()
    return ("max virtual memory areas" in text or "max_map_count" in text
            or "outofmemoryerror" in text or "not enough memory" in text)


def start_service_with_repair(service: str, max_attempts: int = 3, dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce(f"systemctl enable --now {service} (with repair-on-failure)")
        return True
    for attempt in range(1, max_attempts + 1):
        run(["systemctl", "enable", "--now", service], timeout=120)
        time.sleep(3)
        status = run(["systemctl", "is-active", service]).stdout.strip()
        if status == "active":
            ok(f"{service} is active (attempt {attempt}).")
            return True
        warn(f"{service} not active after attempt {attempt}.")
        if service == "wazuh-indexer" and detect_indexer_memory_or_mapcount_failure(service):
            warn("Logs indicate a memory / vm.max_map_count issue - re-applying the sysctl fix.")
            set_max_map_count()
        else:
            repair_broken_packages(dry_run)
        time.sleep(3)
    err(f"{service} failed to reach 'active' state after {max_attempts} attempts. Check: "
        f"journalctl -u {service} -n 200")
    return False


def poll_dashboard(timeout_s: int = 90) -> bool:
    import ssl
    import http.client
    step(f"Polling dashboard on :443 (timeout {timeout_s}s)")
    deadline = time.time() + timeout_s
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with Spinner("Waiting for dashboard") as sp:
        while time.time() < deadline:
            try:
                conn = http.client.HTTPSConnection("localhost", 443, timeout=5, context=ctx)
                conn.request("GET", "/")
                resp = conn.getresponse()
                if resp.status < 500:
                    ok(f"Dashboard responded with HTTP {resp.status}.")
                    return True
            except Exception:
                pass
            sp.tick()
            time.sleep(3)
    return False


def ordered_restart_repair(dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce("ordered restart: wazuh-indexer -> wazuh-manager -> wazuh-dashboard")
        return True
    warn("Dashboard stalled - running ordered repair restart (indexer -> manager -> dashboard).")
    ok1 = start_service_with_repair("wazuh-indexer")
    ok2 = start_service_with_repair("wazuh-manager")
    ok3 = start_service_with_repair("wazuh-dashboard")
    return ok1 and ok2 and ok3


def _systemd_unit_exists(unit: str) -> bool:
    """True only if the unit file actually exists.

    `systemctl list-unit-files <unit>` prints a non-empty header/footer even
    when the unit does NOT exist - it signals that case via a nonzero return
    code, not via empty stdout. We check the return code and additionally
    require the unit's own name to appear in the listing.
    """
    r = run(["systemctl", "list-unit-files", unit], timeout=15)
    return r.returncode == 0 and unit in r.stdout


def detect_existing_install() -> bool:
    """Used by Setup to decide 'fresh install' vs 'repair existing'.

    Prefers concrete evidence (dpkg package status, then the manager's own
    control binary) over systemd unit presence, which can linger even for a
    partially-removed install.
    """
    state = load_state()
    if state["installed"]:
        return True
    pkg = run(["dpkg-query", "-W", "-f=${Status}", "wazuh-manager"], timeout=15)
    if pkg.ok and "install ok installed" in pkg.stdout:
        return True
    if Path("/var/ossec/bin/wazuh-control").exists():
        return True
    units = ("wazuh-manager.service", "wazuh-indexer.service", "wazuh-dashboard.service")
    return all(_systemd_unit_exists(u) for u in units)


def guess_default_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def do_setup(dry_run: bool = False, accept_risk: bool = False, whitelist: Optional[str] = None,
             non_interactive: bool = False) -> bool:
    ensure_root()
    run_preflight(dry_run)

    if detect_existing_install():
        info("Existing Wazuh install detected (state file and/or live services).")
        answer = "r" if non_interactive else (
            input(margin() + "Repair/verify existing install, or leave alone? [R]epair / "
                             "[L]eave: ").strip().lower() or "r")
        if answer.startswith("l"):
            info("Leaving existing install untouched, per operator choice.")
            return True
        step("Repair mode: verifying/fixing services without reinstalling.")
        ok1 = start_service_with_repair("wazuh-indexer", dry_run=dry_run)
        ok2 = start_service_with_repair("wazuh-manager", dry_run=dry_run)
        ok3 = start_service_with_repair("wazuh-dashboard", dry_run=dry_run)
        if not poll_dashboard():
            ordered_restart_repair(dry_run)
        state = load_state()
        state["last_repair_at"] = now_iso()
        save_state(state)
        return ok1 and ok2 and ok3

    if not risk_acknowledgement(accept_risk):
        return False

    if not run_official_installer(dry_run):
        return False

    for svc in ("wazuh-indexer", "wazuh-manager", "wazuh-dashboard"):
        if not start_service_with_repair(svc, dry_run=dry_run):
            err(f"Setup could not bring {svc} up. See {ERROR_LOG} and journalctl -u {svc}.")
            return False

    if not poll_dashboard():
        if not ordered_restart_repair(dry_run):
            err("Dashboard still not responding after ordered repair restart. Setup did not "
                "fully succeed.")
            return False

    if whitelist is None and not non_interactive:
        default_ip = guess_default_ip()
        whitelist = input(margin() + f"Presenter/management IP or CIDR to whitelist so it can "
                                     f"never be auto-blocked [{default_ip}]: ").strip() or default_ip
    elif whitelist is None:
        whitelist = guess_default_ip()

    state = load_state()
    state["installed"] = True
    state["wazuh_version"] = WAZUH_VERSION
    state["whitelist"] = whitelist
    state["server_ip"] = guess_default_ip()
    state["install_completed_at"] = now_iso()
    save_state(state)

    configure_active_response(enable=False, whitelist=whitelist, dry_run=dry_run)

    ok(f"Setup complete. Dashboard: https://<this-vm-ip>/   Credentials: {CREDS_FILE}")
    print_handoff_command()
    return True


# --------------------------------------------------------------------------- #
# Active Response config editing
# --------------------------------------------------------------------------- #
def backup_ossec_conf() -> Optional[Path]:
    ensure_state_dir()
    if not OSSEC_CONF.exists():
        return None
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = BACKUP_DIR / f"ossec.conf.{ts}.bak"
    shutil.copy2(OSSEC_CONF, dest)
    return dest


def restore_latest_backup() -> bool:
    backups = sorted(BACKUP_DIR.glob("ossec.conf.*.bak"))
    if not backups:
        err("No backup available to restore - manual intervention needed.")
        return False
    latest = backups[-1]
    shutil.copy2(latest, OSSEC_CONF)
    warn(f"Restored {OSSEC_CONF} from backup {latest}.")
    return True


def discover_sshd_bruteforce_rule_id() -> str:
    """Find the sshd BRUTE-FORCE (repeated-failure correlation) rule, not
    just any sshd/fail rule. A single failed login (e.g. rule 5716, "sshd:
    authentication failed.") is a loose match on "sshd" + "fail" but is NOT
    the rule we want Active Response triggering on - that would block an
    attacker (or a legitimate user who mistypes a password once) on their
    very first attempt. Strict matches (the actual "multiple authentication
    failures" correlation rule) are always preferred; the loose match is
    only used if no strict match exists at all, and that fact is called
    out explicitly so it gets verified rather than silently trusted.
    """
    ruleset_dir = Path("/var/ossec/ruleset/rules")
    strict_candidates = []
    loose_candidates = []
    if ruleset_dir.exists():
        for f in ruleset_dir.glob("*sshd*"):
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for m in re.finditer(r'<rule id="(\d+)"[^>]*>.*?<description>([^<]*)</description>',
                                 text, re.DOTALL):
                rid, desc = m.group(1), m.group(2)
                desc_l = desc.lower()
                if "multiple authentication failures" in desc_l:
                    strict_candidates.append((rid, desc))
                elif "sshd" in desc_l and "fail" in desc_l:
                    loose_candidates.append((rid, desc))
    if strict_candidates:
        rid, desc = strict_candidates[0]
        info(f"Discovered sshd brute-force rule id={rid} ('{desc}') from {ruleset_dir}.")
        return rid
    if loose_candidates:
        rid, desc = loose_candidates[0]
        warn(f"No rule explicitly saying 'multiple authentication failures' was found; "
             f"using the closest sshd/fail match instead: id={rid} ('{desc}'). VERIFY this "
             f"is actually a repeated-failure/brute-force rule, not a single-failed-login "
             f"rule, before trusting Active Response to trigger on it: "
             f"grep -rn 'id=\"{rid}\"' -A5 {ruleset_dir}")
        return rid
    warn(f"Could not locate the sshd brute-force rule in {ruleset_dir}. Falling back to "
         f"{FALLBACK_SSHD_BRUTEFORCE_RULE_ID} - VERIFY manually with: "
         f"grep -r 'multiple authentication failures' {ruleset_dir}")
    return FALLBACK_SSHD_BRUTEFORCE_RULE_ID


WL_START_MARKER = "<!-- BEGIN wazuh-soc-lab whitelist (presenter IP) -->"
WL_END_MARKER = "<!-- END wazuh-soc-lab whitelist (presenter IP) -->"


def build_active_response_block(rule_id: str, timeout_s: int) -> str:
    """The <active-response> element itself - this one IS a valid direct
    child of <ossec_config> (sibling of <global>, <rules>, <command>...)."""
    ar = ET.Element("active-response")
    ET.SubElement(ar, "disabled").text = "no"
    ET.SubElement(ar, "command").text = "firewall-drop"
    ET.SubElement(ar, "location").text = "local"
    ET.SubElement(ar, "rules_id").text = rule_id
    ET.SubElement(ar, "timeout").text = str(timeout_s)
    return AR_START_MARKER + "\n" + ET.tostring(ar, encoding="unicode") + "\n" + AR_END_MARKER


def insert_whitelist_into_global(text: str, whitelist: str) -> Tuple[str, bool]:
    """Wazuh requires <white_list> to live INSIDE <global>, not as a
    sibling top-level tag under <ossec_config>. Placing it at the top
    level (what this script used to do) is rejected by the manager's own
    config validation at startup - that is the real cause of
    'control process exited with error code' persisting even after the
    duplicate-<active-response> bug was fixed. This inserts it just
    before the FIRST closing </global> tag instead. Returns
    (new_text, inserted) so the caller can warn plainly if no <global>
    section exists to put it in, rather than silently doing nothing."""
    wl_fragment = (f"{WL_START_MARKER}\n    <white_list>{whitelist}</white_list>\n"
                   f"{WL_END_MARKER}\n  ")
    if "</global>" in text:
        return text.replace("</global>", wl_fragment + "</global>", 1), True
    return text, False


def validate_xml_fragment_in_context(new_conf_text: str) -> bool:
    try:
        ET.fromstring(f"<root>{new_conf_text}</root>")
        return True
    except ET.ParseError as e:
        err(f"Generated configuration failed XML validation: {e}")
        return False


def configure_active_response(enable: bool, whitelist: Optional[str] = None,
                              timeout_s: int = AR_DEFAULT_TIMEOUT_SECONDS, dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce(f"{'enable' if enable else 'disable'} Active Response block in "
                          f"{OSSEC_CONF}, reload wazuh-manager")
        return True
    if not OSSEC_CONF.exists():
        err(f"{OSSEC_CONF} not found - is Wazuh manager installed?")
        return False

    original_text = OSSEC_CONF.read_text()
    backup_path = backup_ossec_conf()

    # Strip any previously-added fragments first (idempotent toggle). The
    # active-response block and the whitelist line now live in two
    # different places in the file, so each gets stripped by its own
    # marker pair.
    ar_pattern = re.compile(re.escape(AR_START_MARKER) + r".*?" + re.escape(AR_END_MARKER), re.DOTALL)
    wl_pattern = re.compile(re.escape(WL_START_MARKER) + r".*?" + re.escape(WL_END_MARKER), re.DOTALL)
    stripped_text = ar_pattern.sub("", original_text)
    stripped_text = wl_pattern.sub("", stripped_text).rstrip() + "\n"

    if enable:
        rule_id = discover_sshd_bruteforce_rule_id()
        block = build_active_response_block(rule_id, timeout_s)
        # ossec.conf is NOT one <ossec_config> block - Wazuh's default file
        # is several separate sibling <ossec_config>...</ossec_config>
        # stanzas concatenated together (one for <global>, one for
        # <remote>, one for <ruleset>, etc). str.replace() with no count
        # replaces EVERY "</ossec_config>", which duplicated this same
        # active-response block into every stanza in the file - the
        # manager then refuses to start because the same rule has the
        # active response defined multiple times. Insert it exactly once,
        # into the first (outermost/global) stanza.
        new_text = (stripped_text.replace("</ossec_config>", block + "\n</ossec_config>", 1)
                    if "</ossec_config>" in stripped_text else stripped_text + "\n" + block + "\n")
        if whitelist:
            new_text, inserted = insert_whitelist_into_global(new_text, whitelist)
            if not inserted:
                warn(f"No <global> section found in {OSSEC_CONF} to place the whitelist in - "
                     f"Active Response will still be enabled, but {whitelist} will NOT be "
                     f"excluded from blocking. Add <white_list>{whitelist}</white_list> inside "
                     f"<global> manually if you need this.")
    else:
        new_text = stripped_text

    fragment_ok = validate_xml_fragment_in_context(block) if enable else True
    whole_ok = validate_xml_fragment_in_context(new_text)
    if not (fragment_ok and whole_ok):
        err("Validation failed - restoring previous configuration, no change applied.")
        if backup_path:
            restore_latest_backup()
        return False

    OSSEC_CONF.write_text(new_text)

    r = run(["systemctl", "reload", "wazuh-manager"], timeout=60)
    if not r.ok:
        r2 = run(["systemctl", "restart", "wazuh-manager"], timeout=60)
        if not r2.ok:
            err(f"Failed to reload/restart wazuh-manager after config change: "
                f"{r2.stderr.strip()}. Restoring previous backup.")
            if backup_path:
                OSSEC_CONF.write_text(original_text)
                restore_latest_backup()
                run(["systemctl", "restart", "wazuh-manager"], timeout=60)
            return False

    state = load_state()
    state["response_enabled"] = enable
    if whitelist:
        state["whitelist"] = whitelist
    save_state(state)

    if enable:
        out(green(bold("PROTECTION ON: matched brute-force attempts are now auto-blocked.")))
    else:
        out(yellow(bold("PROTECTION OFF: attacks are only logged.")))
    return True


def print_handoff_command() -> None:
    state = load_state()
    ip = state.get("server_ip") or guess_default_ip()
    cmd = f"sudo python3 wazuh_victim_setup.py --server {ip} --version {WAZUH_VERSION} --yes"
    out()
    out(bold(cyan("Copy/paste this on the Victim Server to enroll its agent:")))
    out()
    out("  " + green(cmd))
    out()


# --------------------------------------------------------------------------- #
# menu actions  (each takes `args`; exceptions are caught by run_item())
# --------------------------------------------------------------------------- #
def action_setup(args: argparse.Namespace) -> None:
    do_setup(dry_run=args.dry_run, accept_risk=args.accept_risk, whitelist=args.whitelist,
             non_interactive=args.yes)


def action_response_on(args: argparse.Namespace) -> None:
    state = load_state()
    configure_active_response(True, whitelist=state.get("whitelist"), dry_run=args.dry_run)


def action_response_off(args: argparse.Namespace) -> None:
    state = load_state()
    configure_active_response(False, whitelist=state.get("whitelist"), dry_run=args.dry_run)


def classify_alert_line(alert: dict) -> Tuple[bool, Optional[str]]:
    desc = ((alert.get("rule", {}) or {}).get("description", "") or "").lower()
    if "active response" in desc and ("firewall-drop" in desc or "added" in desc):
        return True, "BLOCK"
    if "active response" in desc and ("removed" in desc or "deleted" in desc):
        return True, "UNBLOCK"
    return False, None


def action_live_view(args: argparse.Namespace) -> None:
    if not ALERTS_JSON.exists():
        err(f"{ALERTS_JSON} not found - has the manager generated any alerts yet?")
        return
    mode = "PROTECTION ON" if load_state()["response_enabled"] else "PROTECTION OFF (log only)"
    info(f"Mode: {bold(mode)}   |   Watching alerts live - press Ctrl+C to stop.")
    out(dim(f"{'TIME':<9} {'AGENT':<18} {'SRC IP':<15} {'RULE':<7} {'LVL':<4} DESCRIPTION"))
    out(dim(("─" if UTF8 else "-") * CONTENT_WIDTH))
    try:
        with open(ALERTS_JSON) as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = alert.get("timestamp", "")[:19]
                agent = (alert.get("agent", {}) or {}).get("name", "?")
                src_ip = (alert.get("data", {}) or {}).get("srcip", "-")
                rule = alert.get("rule", {}) or {}
                rule_id, level, desc = rule.get("id", "?"), rule.get("level", "?"), rule.get("description", "")
                is_fw, kind = classify_alert_line(alert)
                tag = _c("1;35", f" [{kind}]") if is_fw else ""
                level_color = "1;31" if isinstance(level, int) and level >= 10 else "1;33"
                out(f"{dim(ts):<9} {cyan(agent):<18} {src_ip:<15} {rule_id:<7} "
                    f"{_c(level_color, str(level)):<4} {desc}{tag}")
    except KeyboardInterrupt:
        print()
        info("Returning to menu.")


def action_summary(args: argparse.Namespace) -> None:
    if not ALERTS_JSON.exists():
        err(f"{ALERTS_JSON} not found.")
        return
    by_rule: Dict[str, int] = {}
    by_src: Dict[str, int] = {}
    blocks = unblocks = total = 0
    with open(ALERTS_JSON) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            rule = alert.get("rule", {}) or {}
            desc = rule.get("description", "unknown")
            by_rule[desc] = by_rule.get(desc, 0) + 1
            src_ip = (alert.get("data", {}) or {}).get("srcip")
            if src_ip:
                by_src[src_ip] = by_src.get(src_ip, 0) + 1
            is_fw, kind = classify_alert_line(alert)
            if is_fw:
                blocks += kind == "BLOCK"
                unblocks += kind == "UNBLOCK"

    out(bold(f"Total alerts read: {total}"))
    out()
    out(bold("Top rule categories:"))
    for desc, count in sorted(by_rule.items(), key=lambda x: -x[1])[:10]:
        out(f"  {count:>5}  {desc}")
    out()
    out(bold("Top source IPs:"))
    for ip, count in sorted(by_src.items(), key=lambda x: -x[1])[:10]:
        out(f"  {count:>5}  {ip}")
    out()
    out(bold("Active Response events:") + f"  blocks={blocks}  unblocks={unblocks}")


def action_health_check(args: argparse.Namespace) -> None:
    all_ok = True
    for svc in ("wazuh-manager", "wazuh-indexer", "wazuh-dashboard"):
        status = run(["systemctl", "is-active", svc]).stdout.strip()
        if status == "active":
            ok(f"{svc}: active")
        else:
            err(f"{svc}: {status or 'not found'}")
            all_ok = False

    state = load_state()
    r = run(["/var/ossec/bin/agent_control", "-l"], timeout=15)
    if r.ok:
        (ok if "Active" in r.stdout else warn)(
            f"Victim agent: {'Active' if 'Active' in r.stdout else 'not showing Active'}")
    else:
        warn("Could not query agent_control -l (manager tools not on PATH?).")

    ar_present = OSSEC_CONF.exists() and AR_START_MARKER in OSSEC_CONF.read_text()
    info(f"Active Response block {'present' if ar_present else 'not present'} in config "
         f"(state says {'ON' if state['response_enabled'] else 'OFF'}).")

    free_gb = shutil.disk_usage("/").free / (1024 ** 3)
    (ok if free_gb >= 10 else warn)(f"Free disk: {free_gb:.1f} GB" + ("" if free_gb >= 10 else " (getting low)"))

    if not poll_dashboard(timeout_s=10):
        err("Dashboard did not respond on :443.")
        all_ok = False
        if not args.dry_run:
            try:
                answer = input(margin() + "Run one-keypress automatic repair now? [Y/n]: ").strip().lower()
            except EOFError:
                answer = "y"
            if answer in ("", "y", "yes"):
                ordered_restart_repair(args.dry_run)
    else:
        ok("Dashboard: responding on :443")

    out()
    out(green(bold("Overall: HEALTHY")) if all_ok else red(bold("Overall: ISSUES DETECTED (see above)")))


def action_cheat_sheet(args: argparse.Namespace) -> None:
    state = load_state()
    victim_ip = state.get("victim_ip")
    if not victim_ip:
        victim_ip = input(margin() + "Victim IP not yet known - enter it now "
                                     "(blank for a placeholder): ").strip()
        if victim_ip:
            state["victim_ip"] = victim_ip
            save_state(state)
    target = victim_ip or "<VICTIM_IP>"

    out(dim("Copy these into a terminal on the ATTACKER machine (Kali), NOT this server.\n"))
    items = [
        ("SSH brute force (hydra)", f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{target}"),
        ("Web recon (nikto)", f"nikto -h http://{target}/dvwa/"),
        ("SQL injection (sqlmap, DVWA login form)",
         f"sqlmap -u 'http://{target}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit' "
         f"--cookie='PHPSESSID=<your-session>; security=low' --batch"),
        ("Basic connectivity check (curl)", f"curl -I http://{target}/dvwa/"),
    ]
    for label, cmd in items:
        out(bold(label))
        out("  " + green(cmd))
        out()


def action_tools(args: argparse.Namespace) -> None:
    out("  1) Clear alerts (fresh start for a demo run)")
    out("  2) Show current ossec.conf")
    out("  3) Reset / uninstall (only what this script configured)")
    out("  4) Re-display dashboard URL and admin credentials")
    out("  0) Back")
    out()
    try:
        choice = input(margin() + "Select: ").strip()
    except EOFError:
        choice = "0"

    if choice == "1":
        if args.dry_run:
            dry_run_announce(f"truncate {ALERTS_JSON} and related logs")
        elif ALERTS_JSON.exists():
            ALERTS_JSON.write_text("")
            ok("Alerts log cleared.")
        else:
            warn("Alerts log not found.")
    elif choice == "2":
        out(OSSEC_CONF.read_text() if OSSEC_CONF.exists() else "")
        if not OSSEC_CONF.exists():
            err(f"{OSSEC_CONF} not found.")
    elif choice == "3":
        confirm = input(margin() + "This removes the Active Response block this script added "
                                   "and clears local state (Wazuh packages are NOT removed). "
                                   "Type 'RESET' to confirm: ").strip()
        if confirm == "RESET":
            if not args.dry_run:
                configure_active_response(False)
                if STATE_FILE.exists():
                    STATE_FILE.unlink()
                ok("Local script state reset. Wazuh packages left in place - uninstall those "
                   "manually with your package manager if desired.")
            else:
                dry_run_announce("disable Active Response + remove local state file")
        else:
            info("Reset cancelled.")
    elif choice == "4":
        state = load_state()
        out(f"Dashboard: https://{state.get('server_ip', '<this-vm-ip>')}/")
        (out if CREDS_FILE.exists() else warn)(
            f"Credentials file: {CREDS_FILE}" if CREDS_FILE.exists()
            else "Credentials file not found - was Setup completed?")


# --------------------------------------------------------------------------- #
# menu
# --------------------------------------------------------------------------- #
MenuItem = Tuple[str, str, Callable[[argparse.Namespace], None]]   # (label, description, action)

MAIN_MENU: List[MenuItem] = [
    ("Setup / repair", "install the full Wazuh stack automatically", action_setup),
    ("Response ON", "enable live Active Response blocking", action_response_on),
    ("Response OFF", "disable blocking, keep logging only", action_response_off),
    ("Live alert view", "attacker IP, rule, severity, block events", action_live_view),
    ("Summary", "totals by category, top source IPs", action_summary),
    ("Health check", "services, agent, dashboard, auto-repair", action_health_check),
    ("Attacker cheat-sheet", "ready-to-copy hydra/nikto/sqlmap commands", action_cheat_sheet),
    ("Tools", "clear alerts, show config, reset, creds", action_tools),
]

RUN_ACTION_MAP: Dict[str, Callable[[argparse.Namespace], None]] = {
    "setup": action_setup, "response-on": action_response_on, "response-off": action_response_off,
    "summary": action_summary, "health": action_health_check, "cheat-sheet": action_cheat_sheet,
}


def status_line() -> str:
    state = load_state()
    dot = "●" if UTF8 else "*"
    installed = (green(dot) + " installed") if state["installed"] else (red(dot) + " NOT installed")
    resp = (green(dot) + " Active Response ON") if state["response_enabled"] else \
           (yellow(dot) + " Active Response OFF")
    wl = state.get("whitelist") or "none"
    return f"{installed}    {resp}    {dim('whitelist: ' + wl)}"


def run_item(args: argparse.Namespace, label: str, fn: Callable[[argparse.Namespace], None]) -> None:
    print_screen_top(compact=True)
    header(label)
    try:
        fn(args)
    except KeyboardInterrupt:
        print()
        warn("Interrupted - returning to menu.")
    except Exception as e:
        err(f"Unexpected error: {e}")
        log_error_full(fn.__name__, e)
        out(dim(f"    (full details logged to {ERROR_LOG})"))
    pause()


def draw_menu(args: argparse.Namespace) -> int:
    rows = []
    width = max(len(label) for label, _, _ in MAIN_MENU)
    for i, (label, desc, _) in enumerate(MAIN_MENU, 1):
        rows.append(f"{yellow(f'[{i}]')}  {bold(label.ljust(width))}   {dim(desc)}")
    rows.append(f"{red('[0]')}  {bold('Exit')}")
    block, pad = center_block(box(rows, "MAIN MENU"))
    extra = [center_line(status_line())]
    if args.dry_run:
        extra.append(center_line(magenta("[ DRY RUN MODE - no changes will be made ]")))
    extra.append("")
    print_screen_top(compact=False, extra=extra, vcenter_height=len(block) + 2)
    for l in block:
        print(l)
    print()
    return pad


def main_menu(args: argparse.Namespace) -> None:
    while True:
        pad = draw_menu(args)
        try:
            raw = input(" " * pad + cyan("Select ▸ " if UTF8 else "Select > ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if raw == "0":
            return
        if not raw.isdigit() or not (1 <= int(raw) <= len(MAIN_MENU)):
            continue
        label, _, fn = MAIN_MENU[int(raw) - 1]
        run_item(args, label, fn)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=f"Wazuh SOC demo lab manager (runs on the Wazuh "
                                            f"Server). Author: {AUTHOR}")
    p.add_argument("--install", action="store_true", help="run Setup non-interactively, then exit")
    p.add_argument("--run", metavar="ACTION", help="run one action and exit: " + ", ".join(RUN_ACTION_MAP))
    p.add_argument("--yes", "-y", action="store_true", help="accept every prompt's default")
    p.add_argument("--accept-risk", action="store_true", help="skip the interactive risk prompt")
    p.add_argument("--whitelist", metavar="IP", help="presenter/management IP or CIDR to whitelist")
    p.add_argument("--dry-run", action="store_true", help="print actions without changing anything")
    p.add_argument("--version", action="version", version=f"{VERSION} ({AUTHOR})")
    return p


def main() -> int:
    ensure_state_dir()
    args = build_arg_parser().parse_args()

    if args.install:
        ensure_root()
        return 0 if do_setup(dry_run=args.dry_run, accept_risk=True, whitelist=args.whitelist,
                             non_interactive=True) else 1

    if args.run:
        fn = RUN_ACTION_MAP.get(args.run)
        if not fn:
            err(f"Unknown --run action '{args.run}'. Valid: {', '.join(RUN_ACTION_MAP)}")
            return 2
        ensure_root()
        fn(args)
        return 0

    ensure_root()
    try:
        main_menu(args)
    except KeyboardInterrupt:
        print()
    clear_screen()
    print("\n" + center_line(green("Goodbye!  ") + dim("Stop lab services you are not using "
                                                        "(Tools > Reset / uninstall).")) + "\n")
    print(center_line(yellow(AUTHOR)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
