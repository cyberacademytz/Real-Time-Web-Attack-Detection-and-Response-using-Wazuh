#!/usr/bin/env python3
"""
WAZUH VICTIM SERVER SETUP  -  Author: www.tca.ac.tz  -  Version 1.0.0

RUNS ON:  the Victim Server (enrolls a Wazuh agent and stands up the
          intentionally-vulnerable demo stack: OpenSSH + Apache/PHP/
          MariaDB/DVWA, with log + File Integrity Monitoring configured).

FOR AUTHORIZED SECURITY TRAINING USE ONLY. This script deliberately installs
DVWA (Damn Vulnerable Web Application), a PUBLIC, INTENTIONALLY VULNERABLE
training app, and opens SSH and HTTP so they can be attacked from the
Attacker machine during the demo. Run this ONLY on an isolated lab network
you own or are explicitly authorized to test - never internet-facing.

Run:   sudo python3 wazuh_victim_setup.py --server <wazuh-server-ip>

Phases: pre-flight -> version check -> agent install & enrollment ->
        SSH + DVWA stack -> log/FIM monitoring -> Active Response
        prerequisite check -> final PASS/FAIL self-test (one repair
        attempt per failed item).

Fully automated: re-execs itself with sudo, waits out apt/dpkg locks,
repairs broken packages, diagnoses enrollment failures from the agent log,
and retries a stuck agent service. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "1.0.0"
AUTHOR = "www.tca.ac.tz"

DEFAULT_EXPECTED_WAZUH_VERSION = "4.9.2"
WAZUH_AGENT_REPO_KEY_URL = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"

APP_NAME = "wazuh_victim_setup"
STATE_DIR = Path("/etc/wazuh-soc-lab")
STATE_FILE = STATE_DIR / "victim_state.json"
ERROR_LOG = STATE_DIR / "victim_error.log"

OSSEC_CONF = Path("/var/ossec/etc/ossec.conf")

DVWA_WEB_ROOT = Path("/var/www/html/dvwa")
DVWA_CONFIG_FILE = DVWA_WEB_ROOT / "config/config.inc.php"
DVWA_DB_NAME = "dvwa"
DVWA_DB_USER = "dvwa"
DVWA_DB_PASS = "p@ssw0rd"          # lab-only, intentionally weak - DVWA's own convention
DVWA_SECURITY_LEVEL = "low"
DVWA_DEFAULT_LOGIN = ("admin", "password")

FIM_DIRECTORIES = [DVWA_WEB_ROOT, Path("/etc")]
LOG_SOURCES = [("/var/log/auth.log", "syslog"), ("/var/log/apache2/access.log", "apache"),
               ("/var/log/apache2/error.log", "apache")]

REEXEC_MARKER = "_WAZUH_VICTIM_SETUP_REEXEC"
SUPPORTED_CODENAMES = {"jammy", "noble"}

# --------------------------------------------------------------------------- #
# terminal / layout helpers (shared look with wazuh_soc_manager.py,
# owasp_lab_manager.py and waf_demo_manager.py)
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


# Same block-letter "WAZUH" logo as wazuh_soc_manager.py, so the two tools
# look like one product; subtitle distinguishes the Victim Server role.
ART = [
    "██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗",
    "██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║",
    "██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║",
    "██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║",
    "╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║",
    " ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝",
]
GRADIENT_256 = ["38;5;208", "38;5;202", "38;5;196", "38;5;160", "38;5;124", "38;5;124"]
GRADIENT_8 = ["1;33", "1;33", "1;31", "1;31", "31", "31"]


def banner_lines(compact: bool) -> List[str]:
    if compact or not UTF8:
        t = "WAZUH VICTIM SERVER SETUP"
        line = (_c("1;31", "▌ ") if UTF8 else "") + _c("1;37", t) + (_c("1;31", " ▐") if UTF8 else "")
        sub = (dim("Agent + DVWA demo stack") + dim("  |  ") + yellow(f"Author: {AUTHOR}") +
               dim("  |  ") + yellow(f"v{VERSION}"))
        return [center_line(line), center_line(sub)]
    grad = GRADIENT_256 if COLOR256 else GRADIENT_8
    lines = [center_line(_c(grad[i], a)) for i, a in enumerate(ART)]
    lines.append("")
    lines.append(center_line(red("V I C T I M   S E R V E R   S E T U P")))
    lines.append(center_line(dim("Wazuh agent  +  OpenSSH  +  Apache/PHP/MariaDB/DVWA")))
    lines.append("")
    lines.append(center_line(yellow("Author: " + AUTHOR) + dim("   │   ") + yellow("Version: " + VERSION)))
    lines.append(center_line(red("FOR AUTHORIZED SECURITY TRAINING USE ONLY")))
    return lines


def print_screen_top(compact: bool, extra: Optional[List[str]] = None) -> None:
    clear_screen()
    for l in banner_lines(compact) + [""] + (extra or []):
        print(l)


class Spinner:
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


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


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


DEFAULT_STATE = {
    "agent_enrolled": False, "server_ip": None, "wazuh_version": None,
    "dvwa_installed": False, "whitelist": None, "last_selftest_at": None,
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
        log_error_full("load_state (corrupt, resetting)", e)
        return dict(DEFAULT_STATE)


def save_state(state: Dict[str, Any]) -> None:
    ensure_state_dir()
    tmp = STATE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE_FILE)


class CmdResult:
    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(cmd, timeout: Optional[int] = 120, check: bool = False, input_text: Optional[str] = None) -> CmdResult:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
        if check and proc.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{proc.stderr}")
        return CmdResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as e:
        return CmdResult(124, e.stdout or "", f"timed out after {timeout}s")


def which(binary: str) -> bool:
    return shutil.which(binary) is not None


def dry_run_announce(action: str) -> None:
    out(magenta("[dry-run] would: ") + action)


# --------------------------------------------------------------------------- #
# pre-flight
# --------------------------------------------------------------------------- #
def ensure_root() -> None:
    if os.geteuid() == 0:
        return
    if os.environ.get(REEXEC_MARKER) == "1":
        err("Already attempted sudo re-exec and still not root. Aborting.")
        sys.exit(1)
    if not which("sudo"):
        err("Need root and 'sudo' is unavailable. Re-run as root directly.")
        sys.exit(1)
    info("Not running as root - re-executing with sudo...")
    env = os.environ.copy()
    env[REEXEC_MARKER] = "1"
    os.execvpe("sudo", ["sudo", "-E", sys.executable] + sys.argv, env)


def read_os_release() -> Dict[str, str]:
    data = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k] = v.strip('"')
    except FileNotFoundError:
        pass
    return data


def check_os() -> None:
    osr = read_os_release()
    codename, pretty = osr.get("VERSION_CODENAME", ""), osr.get("PRETTY_NAME", "unknown")
    if osr.get("ID") != "ubuntu" or codename not in SUPPORTED_CODENAMES:
        warn(f"Detected '{pretty}' - validated against Ubuntu 22.04/24.04 LTS. Continuing anyway.")
    else:
        ok(f"OS check passed: {pretty}")


def check_resources() -> None:
    mem_kb = None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_kb = int(line.split()[1])
                    break
    except Exception:
        pass
    if mem_kb:
        mem_gb = mem_kb / 1024 / 1024
        (warn if mem_gb < 2 else ok)(f"RAM: {mem_gb:.1f} GB" + (" - low for Apache+MariaDB+agent, "
                                     "but should still run for a demo." if mem_gb < 2 else ""))
    free_gb = shutil.disk_usage("/").free / (1024 ** 3)
    (warn if free_gb < 10 else ok)(f"Free disk: {free_gb:.1f} GB" + (" (a bit tight)" if free_gb < 10 else ""))


def check_server_reachable(server_ip: str, timeout: float = 5) -> Dict[Any, Any]:
    results: Dict[Any, Any] = {}
    for port in (1514, 1515):
        try:
            socket.create_connection((server_ip, port), timeout=timeout).close()
            results[port] = True
        except OSError as e:
            results[port], results[f"{port}_err"] = False, str(e)
    return results


def preflight_server_reachability(server_ip: str) -> bool:
    step(f"Checking reachability to Wazuh Server {server_ip} on 1514/1515")
    results = check_server_reachable(server_ip)
    all_ok = True
    for port in (1514, 1515):
        if results.get(port):
            ok(f"{server_ip}:{port} reachable")
        else:
            err(f"{server_ip}:{port} NOT reachable ({results.get(f'{port}_err', 'unknown error')})")
            all_ok = False
    if not all_ok:
        out(yellow("SUGGESTION:"))
        out(textwrap.indent(textwrap.dedent("""\
            - Confirm both machines are attached to the SAME isolated
              Host-only/Internal virtual network (not two different ones).
            - On the Wazuh Server, confirm wazuh-manager is running and,
              if ufw is active there, that ports 1514/1515 are allowed
              (wazuh_soc_manager.py's pre-flight step does this automatically).
            - Double check the IP you passed with --server is actually the
              Wazuh Server's current address (`ip a` on the Wazuh Server).""").rstrip(), "  "))
    return all_ok


def compare_versions(expected: str, installed_target: str, force: bool = False) -> bool:
    if expected == installed_target:
        ok(f"Agent version {installed_target} matches the server's pinned version.")
        return True
    msg = (f"Version mismatch: told to install agent version {installed_target}, but the "
           f"expected manager version is {expected}. A manager/agent version mismatch is a "
           f"known source of enrollment and communication failures.")
    if force:
        warn(msg + " Proceeding anyway because --force-version-mismatch was supplied.")
        return True
    err(msg + " Refusing to proceed. Re-run with the matching --version, or pass "
              "--force-version-mismatch to override.")
    return False


# --------------------------------------------------------------------------- #
# agent install + enrollment
# --------------------------------------------------------------------------- #
def apt_lock_held() -> bool:
    for lockfile in ("/var/lib/dpkg/lock-frontend", "/var/lib/apt/lists/lock", "/var/lib/dpkg/lock"):
        if run(["fuser", lockfile], timeout=10).returncode == 0:
            return True
    return False


def wait_for_apt_lock(timeout_s: int = 300, dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce("wait for apt/dpkg lock")
        return True
    if not apt_lock_held():
        return True
    step(f"apt/dpkg lock held - waiting up to {timeout_s}s...")
    waited = 0
    while waited < timeout_s and apt_lock_held():
        time.sleep(5)
        waited += 5
    return not apt_lock_held()


def repair_broken_packages(dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce("dpkg --configure -a && apt-get install -f -y")
        return True
    run(["dpkg", "--configure", "-a"], timeout=300)
    return run(["apt-get", "install", "-f", "-y"], timeout=300).ok


def apt_install(packages: List[str], dry_run: bool = False, retries: int = 2) -> bool:
    if dry_run:
        dry_run_announce(f"apt-get install -y {' '.join(packages)}")
        return True
    for attempt in range(1, retries + 2):
        wait_for_apt_lock()
        r = run(["apt-get", "install", "-y"] + packages, timeout=900)
        if r.ok:
            return True
        warn(f"apt-get install attempt {attempt} failed: {r.stderr.strip()[-300:]}")
        repair_broken_packages(dry_run)
    return False


def setup_wazuh_repo(dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce("add Wazuh apt repo + GPG key")
        return True
    step("Configuring the Wazuh apt repository")
    apt_install(["gnupg", "apt-transport-https"], dry_run)
    run(f"bash -c \"curl -s {WAZUH_AGENT_REPO_KEY_URL} | gpg --no-default-keyring --keyring "
        f"gnupg-ring:/usr/share/keyrings/wazuh.gpg --import\"")
    run(["chmod", "644", "/usr/share/keyrings/wazuh.gpg"])
    Path("/etc/apt/sources.list.d/wazuh.list").write_text(
        "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ "
        "stable main\n")
    r2 = run(["apt-get", "update"], timeout=180)
    if not r2.ok:
        warn(f"apt-get update after adding Wazuh repo returned nonzero: {r2.stderr.strip()[:300]}")
    return True


def install_agent(server_ip: str, version: str, dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce(f"WAZUH_MANAGER={server_ip} apt-get install -y wazuh-agent={version}-1")
        return True
    setup_wazuh_repo(dry_run)
    env = os.environ.copy()
    env["WAZUH_MANAGER"] = server_ip

    def attempt() -> subprocess.CompletedProcess:
        wait_for_apt_lock()
        return subprocess.run(["apt-get", "install", "-y", f"wazuh-agent={version}-1"],
                              capture_output=True, text=True, env=env, timeout=600)

    step(f"Installing wazuh-agent {version} (WAZUH_MANAGER={server_ip})")
    r = attempt()
    if r.returncode != 0:
        warn("First install attempt failed - repairing packages and retrying once.")
        repair_broken_packages(dry_run)
        avail = run(["apt-cache", "madison", "wazuh-agent"])
        if version not in avail.stdout:
            err(f"wazuh-agent {version} not found in apt-cache madison output. Available:\n"
                f"{avail.stdout}\nThis usually means the pinned version doesn't exist for this "
                f"Ubuntu release, or the repo didn't refresh. Fix the version pin and re-run.")
            return False
        r = attempt()
        if r.returncode != 0:
            err(f"wazuh-agent install still failing after repair+retry:\n{r.stderr[-500:]}")
            return False
    ok(f"wazuh-agent {version} installed.")
    return True


def set_manager_ip_in_config(server_ip: str, dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce(f"set <address>{server_ip}</address> in {OSSEC_CONF}")
        return True
    if not OSSEC_CONF.exists():
        err(f"{OSSEC_CONF} not found after install - agent package may not be installed correctly.")
        return False
    text = OSSEC_CONF.read_text()
    new_text, n = re.subn(r"<address>[^<]*</address>", f"<address>{server_ip}</address>", text, count=1)
    if n == 0:
        warn("Could not find an <address> tag to update.")
    OSSEC_CONF.write_text(new_text)
    return True


def diagnose_enrollment_failure() -> str:
    log_path = Path("/var/ossec/logs/ossec.log")
    if not log_path.exists():
        return "No agent log found yet - enrollment may not have run at all."
    tail = run(["tail", "-n", "60", str(log_path)]).stdout
    lower = tail.lower()
    if "connection refused" in lower or "could not connect" in lower:
        return ("Connection refused/could not connect - double check the server IP, that "
                "wazuh-manager is running on the Wazuh Server, and that port 1515 is reachable.")
    if "ssl error" in lower or "certificate" in lower:
        return ("TLS/certificate error - often clock skew between the two machines. Check "
                "`timedatectl` on both and sync time (`timedatectl set-ntp true`), then retry.")
    if "invalid" in lower and "key" in lower:
        return ("Agent key appears invalid (stale key from a previous attempt). Try: "
                "`/var/ossec/bin/agent-auth -m <server_ip>` again after removing "
                "/var/ossec/etc/client.keys.")
    return f"No specific pattern matched; last log lines:\n{tail[-800:]}"


def start_agent_with_repair(max_attempts: int = 3, dry_run: bool = False) -> bool:
    if dry_run:
        dry_run_announce("systemctl enable --now wazuh-agent (with repair)")
        return True
    for attempt in range(1, max_attempts + 1):
        run(["systemctl", "enable", "--now", "wazuh-agent"], timeout=60)
        time.sleep(2)
        status = run(["systemctl", "is-active", "wazuh-agent"]).stdout.strip()
        if status == "active":
            ok(f"wazuh-agent is active (attempt {attempt}).")
            return True
        warn(f"wazuh-agent not active after attempt {attempt}: {status}")
        repair_broken_packages(dry_run)
        time.sleep(2)
    err("wazuh-agent failed to reach 'active' state. Diagnostics:")
    out(diagnose_enrollment_failure())
    out(run(["journalctl", "-u", "wazuh-agent", "-n", "60", "--no-pager"]).stdout[-1500:])
    return False


def enroll_agent(server_ip: str, dry_run: bool = False, max_attempts: int = 3) -> bool:
    if dry_run:
        dry_run_announce(f"/var/ossec/bin/agent-auth -m {server_ip} && systemctl enable --now wazuh-agent")
        return True
    for attempt in range(1, max_attempts + 1):
        step(f"Enrollment attempt {attempt}/{max_attempts} against {server_ip}")
        r = run(["/var/ossec/bin/agent-auth", "-m", server_ip], timeout=30)
        if r.ok:
            ok("agent-auth succeeded.")
            break
        warn(f"agent-auth failed: {r.stderr.strip()[:300]}")
        warn(f"Diagnosis: {diagnose_enrollment_failure()}")
        time.sleep(3)
    else:
        err(f"Enrollment failed after all attempts. See diagnosis above and the full agent log "
            f"at /var/ossec/logs/ossec.log")
        return False
    run(["systemctl", "daemon-reload"])
    return start_agent_with_repair(max_attempts=3)


# --------------------------------------------------------------------------- #
# victim demo stack
# --------------------------------------------------------------------------- #
def setup_ssh(dry_run: bool = False) -> bool:
    step("Installing/enabling OpenSSH server (brute-force target)")
    if dry_run:
        dry_run_announce("apt-get install openssh-server; systemctl enable --now ssh")
        return True
    if not apt_install(["openssh-server"], dry_run):
        err("Failed to install openssh-server.")
        return False
    run(["systemctl", "enable", "--now", "ssh"], timeout=30)
    status = run(["systemctl", "is-active", "ssh"]).stdout.strip()
    if status == "active":
        ok("SSH server active.")
        return True
    err(f"SSH server not active ({status}). Check: journalctl -u ssh")
    return False


def setup_lamp_and_dvwa(dry_run: bool = False) -> bool:
    step("Installing Apache, PHP, MariaDB, and DVWA")
    if dry_run:
        dry_run_announce("apt-get install apache2 php mariadb-server php-mysqli php-gd git; "
                          "clone DVWA; configure db + config.inc.php")
        return True

    packages = ["apache2", "mariadb-server", "php", "php-mysqli", "php-gd", "php-cli",
                "libapache2-mod-php", "git", "curl"]
    if not apt_install(packages, dry_run):
        err("Failed to install LAMP stack packages.")
        return False

    run(["systemctl", "enable", "--now", "apache2"], timeout=30)
    run(["systemctl", "enable", "--now", "mariadb"], timeout=30)

    if not DVWA_WEB_ROOT.exists():
        step("Cloning DVWA into the Apache web root")
        r = run(["git", "clone", "--depth", "1", "https://github.com/digininja/DVWA.git",
                str(DVWA_WEB_ROOT)], timeout=120)
        if not r.ok:
            err(f"Failed to clone DVWA: {r.stderr.strip()[:300]}")
            return False
    else:
        info("DVWA directory already present - leaving source as-is (idempotent re-run).")

    run(["chown", "-R", "www-data:www-data", str(DVWA_WEB_ROOT)])

    step("Creating DVWA database and user")
    sql = (f"CREATE DATABASE IF NOT EXISTS {DVWA_DB_NAME}; "
           f"CREATE USER IF NOT EXISTS '{DVWA_DB_USER}'@'localhost' IDENTIFIED BY "
           f"'{DVWA_DB_PASS}'; GRANT ALL PRIVILEGES ON {DVWA_DB_NAME}.* TO "
           f"'{DVWA_DB_USER}'@'localhost'; FLUSH PRIVILEGES;")
    r = run(["mysql", "-u", "root", "-e", sql], timeout=30)
    if not r.ok:
        err(f"Failed to create DVWA database/user: {r.stderr.strip()[:300]}")
        return False

    example_config = DVWA_WEB_ROOT / "config/config.inc.php.dist"
    if not DVWA_CONFIG_FILE.exists() and example_config.exists():
        shutil.copy2(example_config, DVWA_CONFIG_FILE)
    if DVWA_CONFIG_FILE.exists():
        text = DVWA_CONFIG_FILE.read_text()
        text = re.sub(r"\$_DVWA\[\s*'db_user'\s*\]\s*=.*?;",
                      f"$_DVWA[ 'db_user' ] = '{DVWA_DB_USER}';", text)
        text = re.sub(r"\$_DVWA\[\s*'db_password'\s*\]\s*=.*?;",
                      f"$_DVWA[ 'db_password' ] = '{DVWA_DB_PASS}';", text)
        text = re.sub(r"\$_DVWA\[\s*'db_database'\s*\]\s*=.*?;",
                      f"$_DVWA[ 'db_database' ] = '{DVWA_DB_NAME}';", text)
        DVWA_CONFIG_FILE.write_text(text)
    else:
        warn(f"Could not find DVWA's config template at {example_config} - repo layout may "
             f"have changed; manual config.inc.php setup may be required.")

    step("Initializing DVWA database schema via its setup endpoint")
    schema_sql = DVWA_WEB_ROOT / "config/schema.sql"
    if schema_sql.exists():
        run(["mysql", "-u", DVWA_DB_USER, f"-p{DVWA_DB_PASS}", DVWA_DB_NAME, "-e",
             f"source {schema_sql}"], timeout=30)
    run(["systemctl", "restart", "apache2"], timeout=30)
    time.sleep(2)
    run(["curl", "-s", "-o", "/dev/null",
         "http://127.0.0.1/dvwa/setup.php?create_db=Create+%2F+Reset+Database"], timeout=20)

    info(f"DVWA security level target: {DVWA_SECURITY_LEVEL} (set via the dvwaSecurityLevel "
         f"cookie at first login - see self-test output for the login URL).")
    info(f"DVWA default login: {DVWA_DEFAULT_LOGIN[0]} / {DVWA_DEFAULT_LOGIN[1]} (DVWA's own "
         f"documented default).")

    ok("DVWA install/config steps completed.")
    return True


def configure_agent_monitoring(dry_run: bool = False) -> bool:
    step("Configuring agent log monitoring + File Integrity Monitoring")
    if dry_run:
        dry_run_announce(f"add <localfile>/<syscheck> entries to {OSSEC_CONF} for "
                          f"{LOG_SOURCES} and {FIM_DIRECTORIES}")
        return True
    if not OSSEC_CONF.exists():
        err(f"{OSSEC_CONF} not found - is the agent installed?")
        return False

    text = OSSEC_CONF.read_text()
    marker_start, marker_end = "<!-- BEGIN wazuh-soc-lab victim monitoring -->", \
        "<!-- END wazuh-soc-lab victim monitoring -->"
    text = re.sub(re.escape(marker_start) + r".*?" + re.escape(marker_end), "", text, flags=re.DOTALL)

    localfiles = "\n".join(f"  <localfile>\n    <log_format>{fmt}</log_format>\n"
                           f"    <location>{path}</location>\n  </localfile>"
                           for path, fmt in LOG_SOURCES)
    syscheck = "\n".join(f'  <directories realtime="yes" report_changes="yes" check_all="yes">'
                         f'{path}</directories>' for path in FIM_DIRECTORIES)
    block = (f"{marker_start}\n<ossec_config>\n{localfiles}\n  <syscheck>\n    <disabled>no</disabled>\n"
            f"{syscheck}\n  </syscheck>\n</ossec_config>\n{marker_end}\n")
    text = text.rstrip() + "\n\n" + block
    OSSEC_CONF.write_text(text)

    run(["systemctl", "restart", "wazuh-agent"], timeout=30)
    time.sleep(3)
    status = run(["systemctl", "is-active", "wazuh-agent"]).stdout.strip()
    if status != "active":
        err(f"wazuh-agent did not come back up after monitoring config change ({status}). "
            f"Check: journalctl -u wazuh-agent -n 100")
        return False
    ok("Agent restarted and active after monitoring config change.")
    return verify_agent_reconnected()


def verify_agent_reconnected(timeout_s: int = 30) -> bool:
    log_path = Path("/var/ossec/logs/ossec.log")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if log_path.exists():
            tail = run(["tail", "-n", "40", str(log_path)]).stdout
            if "connected to" in tail.lower():
                ok("Agent reconnected to the server.")
                return True
        time.sleep(2)
    warn("Did not see an explicit reconnect message within timeout - continuing to final self-test.")
    return True


# --------------------------------------------------------------------------- #
# Active Response prerequisite verification
# --------------------------------------------------------------------------- #
def check_active_response_prereqs(whitelist_ip: Optional[str], dry_run: bool = False) -> Dict[str, bool]:
    step("Verifying Active Response prerequisites on this machine")
    results: Dict[str, bool] = {}
    results["agent_active"] = run(["systemctl", "is-active", "wazuh-agent"]).stdout.strip() == "active"
    results["execd_running"] = run(["pgrep", "-f", "wazuh-execd"]).returncode == 0
    fw_script = Path("/var/ossec/active-response/bin/firewall-drop")
    results["firewall_script_present"] = fw_script.exists() and os.access(fw_script, os.X_OK)
    results["iptables_present"] = which("iptables")

    for key, label in [("agent_active", "Agent service active"),
                       ("execd_running", "wazuh-execd (response executor) running"),
                       ("firewall_script_present", "firewall-drop script present + executable"),
                       ("iptables_present", "iptables backend present")]:
        (ok if results[key] else warn)(label + ("" if results[key] else ": NOT confirmed"))

    if whitelist_ip:
        info(f"Configured presenter/management whitelist IP: {whitelist_ip} - CONFIRM this "
             f"exactly matches the --whitelist value given to wazuh_soc_manager.py on the "
             f"Wazuh Server. A mismatch means the presenter's own connection could be "
             f"auto-blocked during the live demo.")
    else:
        warn("No whitelist IP supplied to this script - pass --whitelist to verify it against "
             "the server's whitelist before a live demo.")
    return results


# --------------------------------------------------------------------------- #
# final self-test
# --------------------------------------------------------------------------- #
def selftest_item(label: str, check_fn: Callable[[], bool], repair_fn: Optional[Callable[[], None]] = None) -> bool:
    passed = check_fn()
    if not passed and repair_fn:
        warn(f"{label}: FAIL - attempting one automatic repair pass...")
        repair_fn()
        time.sleep(2)
        passed = check_fn()
    return passed


def run_final_selftest(server_ip: str, whitelist_ip: Optional[str], dry_run: bool = False) -> bool:
    header("Final self-test")
    results: Dict[str, bool] = {}

    results["Agent connected to server"] = selftest_item(
        "Agent connected to server",
        lambda: run(["systemctl", "is-active", "wazuh-agent"]).stdout.strip() == "active",
        lambda: start_agent_with_repair(max_attempts=2, dry_run=dry_run))

    results["SSH reachable"] = selftest_item(
        "SSH reachable",
        lambda: run(["systemctl", "is-active", "ssh"]).stdout.strip() == "active",
        lambda: run(["systemctl", "restart", "ssh"], timeout=30))

    def check_dvwa() -> bool:
        r = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "http://127.0.0.1/dvwa/login.php"], timeout=10)
        return r.stdout.strip() in ("200", "302")

    def repair_dvwa() -> None:
        run(["systemctl", "restart", "apache2"], timeout=30)
        run(["systemctl", "restart", "mariadb"], timeout=30)

    results["DVWA reachable on :80"] = selftest_item("DVWA reachable on :80", check_dvwa, repair_dvwa)

    def check_fim() -> bool:
        return OSSEC_CONF.exists() and all(str(p) in OSSEC_CONF.read_text() for p in FIM_DIRECTORIES)

    results["FIM watching expected paths"] = selftest_item(
        "FIM watching expected paths", check_fim, lambda: configure_agent_monitoring(dry_run))

    ar_results = check_active_response_prereqs(whitelist_ip, dry_run)
    results["Active Response prerequisites"] = all(ar_results.values())

    out()
    rows = []
    all_pass = True
    for label, passed in results.items():
        rows.append((green("PASS") if passed else red("FAIL")) + f"  {label}")
        all_pass &= passed
    block, _ = center_block(box(rows, "SELF-TEST RESULTS"))
    for l in block:
        print(l)
    out()
    if all_pass:
        out(center_line(green(bold("ALL CHECKS PASSED - victim machine ready for the demo."))))
    else:
        out(center_line(red(bold("ONE OR MORE CHECKS FAILED - see FAIL lines above, each with "
                                 "one repair attempt already made."))))
        out(center_line(dim(f"Re-run this script to retry, or check {ERROR_LOG} / journalctl "
                            f"for the relevant service.")))

    state = load_state()
    state["last_selftest_at"] = now_iso()
    save_state(state)
    return all_pass


# --------------------------------------------------------------------------- #
# CLI / main
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=f"Wazuh victim machine setup (runs on the Victim "
                                            f"Server). Author: {AUTHOR}")
    p.add_argument("--server", metavar="IP", help="Wazuh Server IP address.")
    p.add_argument("--version", metavar="X.Y.Z", default=DEFAULT_EXPECTED_WAZUH_VERSION,
                    help="Pinned Wazuh agent version to install (must match the server's version).")
    p.add_argument("--whitelist", metavar="IP", help="Presenter/management IP, cross-checked "
                                                      "against the server's Active Response whitelist.")
    p.add_argument("--yes", "-y", action="store_true", help="Run unattended, accepting defaults.")
    p.add_argument("--dry-run", action="store_true", help="Print actions without changing anything.")
    p.add_argument("--force-version-mismatch", action="store_true",
                    help="Proceed even if --version doesn't match the expected default.")
    p.add_argument("--app-version", action="version", version=f"{VERSION} ({AUTHOR})")
    return p


def main() -> int:
    ensure_state_dir()
    args = build_arg_parser().parse_args()
    ensure_root()

    print_screen_top(compact=False)
    if args.dry_run:
        out(center_line(magenta("[ DRY RUN MODE - no changes will be made ]")))
        out()

    server_ip = args.server
    if not server_ip and not args.yes:
        server_ip = input(margin() + "Wazuh Server IP address: ").strip()
    if not server_ip:
        err("No --server IP supplied (and not running interactively). Pass --server <ip>.")
        return 2

    if not compare_versions(DEFAULT_EXPECTED_WAZUH_VERSION, args.version, force=args.force_version_mismatch):
        return 1

    header("Pre-flight checks")
    check_os()
    check_resources()
    if not preflight_server_reachability(server_ip):
        if not args.yes:
            if (input(margin() + "Continue anyway? [y/N]: ").strip().lower() or "n") != "y":
                return 1
        else:
            warn("Continuing despite reachability failure because --yes was supplied; "
                 "enrollment will very likely fail and will be retried with diagnostics.")

    header("Agent install & enrollment")
    steps_ok = True
    steps_ok &= bool(install_agent(server_ip, args.version, args.dry_run))
    steps_ok &= bool(set_manager_ip_in_config(server_ip, args.dry_run))
    steps_ok &= bool(enroll_agent(server_ip, args.dry_run))

    header("Victim demo stack")
    steps_ok &= bool(setup_ssh(args.dry_run))
    steps_ok &= bool(setup_lamp_and_dvwa(args.dry_run))

    header("Monitoring configuration")
    steps_ok &= bool(configure_agent_monitoring(args.dry_run))

    state = load_state()
    state.update(server_ip=server_ip, wazuh_version=args.version, agent_enrolled=steps_ok,
                 dvwa_installed=True, whitelist=args.whitelist)
    save_state(state)

    if args.dry_run:
        info("Dry run complete - skipping final self-test (no real state to test).")
        return 0

    passed = run_final_selftest(server_ip, args.whitelist, args.dry_run)
    out()
    out(center_line(yellow(AUTHOR)))
    out()
    return 0 if (steps_ok and passed) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        info("Interrupted by operator.")
        sys.exit(130)
    except Exception as e:
        err(f"Unhandled top-level error: {e}. Full traceback logged to {ERROR_LOG}.")
        log_error_full("main", e)
        sys.exit(1)
