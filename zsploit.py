#!/usr/bin/env python3
"""
Z-Sploit — Security Assessment & Audit Toolkit
================================================
A guided, menu-driven wrapper around standard security-scanning tools
(Nmap, Nikto, Lynis, WhatWeb, Wget, Metasploit, Tor). It automates running
and logging these tools and explains results in plain language — it does
not implement any custom exploit or attack code of its own.

Covers: network vulnerability scanning, web vulnerability scanning, local
system auditing, IP/hosting reconnaissance, website mirroring, and scan
history/logging — all from a single interactive menu.

Author:     Zeeshan Ali
Compatible: Termux (Android) | Kali Linux / Debian-based distros

IMPORTANT: Only use this tool against systems you own or have explicit,
written authorization to test. Unauthorized scanning is illegal in most
jurisdictions.
"""

ZSPLOIT_VERSION = "2.0.0"

import os
import sys
import shutil
import subprocess
import time
import random
import json
import re
import urllib.request
import urllib.error

# ─────────────────────────────────────────────
#  Config + Logging / Scan-History paths
# ─────────────────────────────────────────────
CONFIG_PATH  = os.path.expanduser("~/.zsploit_config.json")
LOG_DIR      = os.path.expanduser("~/zsploit_logs")
HISTORY_PATH = os.path.join(LOG_DIR, "history.json")

DEFAULT_CONFIG = {
    "nmap_timing": "T4",        # T1 (slow/stealthy) .. T5 (fastest)
    "auto_save_logs": True,     # save every scan's output + a history entry
    "last_target": "",          # convenience: reused as the input default
    "theme": "classic",         # classic | matrix | crimson | mono
    "display_mode": "professional",  # professional | classic (ASCII-art banners)
    "explain_mode": True,       # show plain-language summaries after scans
}


def load_config() -> dict:
    """Load ~/.zsploit_config.json, creating it with defaults if missing/corrupt."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                cfg = json.load(f)
            merged = dict(DEFAULT_CONFIG)
            merged.update(cfg)
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    cfg = dict(DEFAULT_CONFIG)
    save_config(cfg)
    return cfg


def save_config(cfg: dict):
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except OSError as e:
        print(f"[!] Could not save config: {e}")


def run_cmd(cmd: str, buffer: list = None) -> int:
    """
    Run an external command, printing its output live (same visible
    behavior as os.system) while also capturing every line into
    `buffer` (if given) so it can be written to a scan log afterward.
    Returns the process's exit code.
    """
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            print(line, end="")
            if buffer is not None:
                buffer.append(line)
        proc.wait()
        return proc.returncode
    except Exception as e:
        msg = f"[!] Command failed to run: {e}\n"
        print(msg, end="")
        if buffer is not None:
            buffer.append(msg)
        return 1


def log_scan(action: str, target: str, buffer: list, summary: str = ""):
    """
    Write a scan's full captured output to its own log file under
    ~/zsploit_logs/, and append a short record to history.json so past
    scans can be listed/reviewed later (Option: Scan History).
    """
    cfg = load_config()
    if not cfg.get("auto_save_logs", True):
        return None

    os.makedirs(LOG_DIR, exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target or "local")
    safe_action = re.sub(r"[^a-zA-Z0-9._-]", "_", action)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(LOG_DIR, f"{safe_action}_{safe_target}_{timestamp}.log")

    try:
        with open(log_file, "w") as f:
            f.write("".join(buffer))
    except OSError as e:
        print(f"[!] Could not write log file: {e}")
        return None

    history = []
    if os.path.exists(HISTORY_PATH):
        try:
            with open(HISTORY_PATH, "r") as f:
                history = json.load(f)
        except (json.JSONDecodeError, OSError):
            history = []

    history.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "target": target or "(local host)",
        "log_file": log_file,
        "summary": summary,
    })
    try:
        with open(HISTORY_PATH, "w") as f:
            json.dump(history, f, indent=2)
    except OSError as e:
        print(f"[!] Could not update scan history: {e}")

    return log_file

# ─────────────────────────────────────────────
#  ANSI Color Helpers + Themes
# ─────────────────────────────────────────────
RESET = "\033[0m"

THEMES = {
    # Original Zsploit look — cyan/green accents, standard bold colors.
    "classic": {
        "RED": "\033[1;31m", "GREEN": "\033[1;32m", "YELLOW": "\033[1;33m",
        "CYAN": "\033[1;36m", "WHITE": "\033[1;37m", "MAGENTA": "\033[1;35m",
        "BOLD": "\033[1m",
    },
    # All-green "hacker movie" look. Errors stay true red so they're
    # never lost in the green-on-green.
    "matrix": {
        "RED": "\033[1;31m", "GREEN": "\033[1;32m", "YELLOW": "\033[0;32m",
        "CYAN": "\033[1;32m", "WHITE": "\033[0;32m", "MAGENTA": "\033[1;32m",
        "BOLD": "\033[1;32m",
    },
    # Red/dark-red dominant — matches the skull/"dangerous" banners.
    "crimson": {
        "RED": "\033[1;31m", "GREEN": "\033[0;31m", "YELLOW": "\033[1;33m",
        "CYAN": "\033[1;31m", "WHITE": "\033[1;37m", "MAGENTA": "\033[1;31m",
        "BOLD": "\033[1;31m",
    },
    # No color at all — just bold/dim white. For terminals that mangle
    # ANSI colors, screen readers, or anyone who prefers plain text.
    "mono": {
        "RED": "\033[1;37m", "GREEN": "\033[0;37m", "YELLOW": "\033[1;37m",
        "CYAN": "\033[0;37m", "WHITE": "\033[1;37m", "MAGENTA": "\033[0;37m",
        "BOLD": "\033[1m",
    },
}

# Populated by apply_theme() below; classic is the default until config loads.
RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = BOLD = ""


def apply_theme(name: str):
    """Switch the active color theme by reassigning the globals the
    red()/green()/etc. helpers read from — takes effect immediately
    for every print() call made after this, no restart needed."""
    global RED, GREEN, YELLOW, CYAN, WHITE, MAGENTA, BOLD
    theme = THEMES.get(name, THEMES["classic"])
    RED, GREEN, YELLOW = theme["RED"], theme["GREEN"], theme["YELLOW"]
    CYAN, WHITE, MAGENTA, BOLD = theme["CYAN"], theme["WHITE"], theme["MAGENTA"], theme["BOLD"]


apply_theme("classic")


def red(t):    return f"{RED}{t}{RESET}"
def green(t):  return f"{GREEN}{t}{RESET}"
def yellow(t): return f"{YELLOW}{t}{RESET}"
def cyan(t):   return f"{CYAN}{t}{RESET}"
def white(t):  return f"{WHITE}{t}{RESET}"
def magenta(t): return f"{MAGENTA}{t}{RESET}"
def bold(t):   return f"{BOLD}{t}{RESET}"

def clear():
    os.system("clear")

def pause(secs=0.6):
    time.sleep(secs)

# ─────────────────────────────────────────────
#  Environment Detection
# ─────────────────────────────────────────────
def detect_env():
    """Return 'termux', 'kali', or 'unknown'."""
    if os.path.isdir("/data/data/com.termux"):
        return "termux"
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
        if "kali" in content:
            return "kali"
    except FileNotFoundError:
        pass
    return "unknown"

ENV = detect_env()

def pkg_install(package):
    """Install a package using the right package manager."""
    if ENV == "termux":
        return os.system(f"pkg install -y {package}")
    else:
        return os.system(f"sudo apt-get install -y {package}")

# ─────────────────────────────────────────────
#  Tool Check & Install
# ─────────────────────────────────────────────
def check_tool(display_name, binary, install_fn):
    """
    Check if `binary` is on PATH.
    If found  → print confirmation and return True.
    If absent → install via install_fn, then MANDATORY re-check that the
    binary actually ended up on PATH afterward — the installer's exit
    code alone isn't trusted (it can report success even when the
    binary didn't land somewhere PATH can see, e.g. wrong repo, partial
    install, or a quirky package). Only a real post-install
    shutil.which() hit counts as success.
    """
    print(f"\n{cyan('▶')} Checking {bold(display_name)} ...", end=" ", flush=True)
    pause(0.3)

    if shutil.which(binary):
        print(green("✔  Already installed — OK"))
        return True

    print(yellow("✘  Not found — installing ..."))
    ret = install_fn()

    # Mandatory re-check: don't trust the installer's exit code alone.
    print(f"   {cyan('▶')} Re-checking {display_name} after install ...", end=" ", flush=True)
    pause(0.3)
    if ret == 0 and shutil.which(binary):
        print(green(f"✔  {display_name} confirmed installed and on PATH."))
        return True

    print(red(f"✘  {display_name} still not found after install attempt."))
    if ret != 0:
        print(red(f"   (installer reported an error — exit status {ret})"))
    else:
        print(red("   (installer reported success, but the binary isn't on PATH — "
                   "may need a fresh shell/PATH refresh, or the package name is wrong)"))
    print(red(f"   ✘  Failed to install {display_name}. Check your connection/permissions."))
    return False

# ── Individual install functions ───────────────

def install_tor():
    if ENV == "termux":
        return os.system("pkg install -y tor")
    return os.system("sudo apt-get install -y tor")

def install_metasploit():
    if ENV == "termux":
        return os.system("pkg install -y unstable-repo && pkg install -y metasploit")
    return os.system("sudo apt-get install -y metasploit-framework")

def install_nmap():
    return pkg_install("nmap")

def install_nikto():
    return pkg_install("nikto")

def install_lynis():
    """Lynis = local system/host vulnerability & hardening auditor."""
    return pkg_install("lynis")

def install_whatweb():
    return pkg_install("whatweb")

def install_wget():
    return pkg_install("wget")


def ensure_tool(binary: str, display_name: str, install_fn) -> bool:
    """
    Pre-flight check run right before a scan uses a tool — not just at
    startup bootstrap. If missing, offers to install it on the spot.
    Returns True if the tool is available to use, False otherwise.
    """
    if shutil.which(binary):
        print(green(f"[✔] {display_name} — installed."))
        return True

    print(yellow(f"[!] {display_name} is not installed."))
    ans = input(bold(f"    Install {display_name} now? (yes/no): ")).strip().lower()
    if ans not in ("yes", "y"):
        print(red(f"    Skipping — {display_name} is required for this step."))
        return False

    print(yellow(f"    Installing {display_name} ..."))
    ret = install_fn()
    if ret == 0 and shutil.which(binary):
        print(green(f"[✔] {display_name} installed successfully."))
        return True
    print(red(f"[!] Failed to install {display_name}. Check your connection/permissions."))
    return False


def _target_reachable(ip: str) -> bool:
    """
    Quick reachability pre-check (ICMP ping, 1 packet, 2s timeout).
    Used only to give a clear, friendly warning before Nmap — some
    targets block ICMP but are still scannable, so this never blocks
    the scan, it just explains likely 'no route' failures in advance.
    """
    flag = "-n" if ENV == "unknown" and os.name == "nt" else "-c"
    try:
        result = subprocess.run(
            ["ping", flag, "1", "-W", "2", ip],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return True  # unknown — don't block the scan on a ping-tool issue


def install_zsploit_deps():
    """Z-Sploit itself is this script; we just ensure Python deps."""
    try:
        import socket      # stdlib – always present; this import IS the check
        _ = socket.AF_INET
        return 0
    except ImportError:
        return 1

# ─────────────────────────────────────────────
#  Dependency Bootstrap
# ─────────────────────────────────────────────
def bootstrap():
    clear()
    print(bold(cyan("=" * 55)))
    print(bold(cyan("   Z-Sploit  ·  Dependency Check & Setup")))
    print(bold(cyan("=" * 55)))

    results = {
        "Tor"         : check_tool("Tor",         "tor",    install_tor),
        "Metasploit"  : check_tool("Metasploit",  "msfconsole", install_metasploit),
        "Nmap"        : check_tool("Nmap",         "nmap",   install_nmap),
        "Nikto"       : check_tool("Nikto",        "nikto",  install_nikto),
        "Lynis"       : check_tool("Lynis",        "lynis",  install_lynis),
        "WhatWeb"     : check_tool("WhatWeb",      "whatweb", install_whatweb),
        "Wget"        : check_tool("Wget",         "wget",   install_wget),
        "Z-Sploit"    : check_tool("Z-Sploit Core","python3", install_zsploit_deps),
    }

    print()
    failed = [name for name, ok in results.items() if not ok]
    if failed:
        print(yellow(f"⚠  Some tools could not be installed: {', '.join(failed)}"))
        print(yellow("   Proceeding with available tools.\n"))
    else:
        print(green("✔  All tools verified.\n"))

    pause(1.0)

# ─────────────────────────────────────────────
#  Banners
# ─────────────────────────────────────────────

# Clean, professional banner — the default look. The old ASCII-art/skull
# banners below are kept and still available via Settings → Display mode
# → "classic", for anyone who liked the original rotating-banner look.
def _banner_professional() -> str:
    """
    Built as a function (not a static string) so it can show the
    current ZSPLOIT_VERSION without the two ever drifting out of sync.
    The border width is computed FROM the content width rather than
    hand-typed, which previously caused a real bug: a manually-typed
    Unicode border was 2 characters narrower than the content lines,
    making the box visibly misaligned. Computing it guarantees they
    can never mismatch again, however the content lines change.
    """
    inner_width = 56
    lines = [
        "",
        "Z - S P L O I T".center(inner_width),
        "Security Assessment & Audit Toolkit".center(inner_width),
        f"v{ZSPLOIT_VERSION}".center(inner_width),
        "",
    ]
    border = "═" * inner_width
    rows = [f"╔{border}╗"]
    rows += [f"║{line.ljust(inner_width)}║" for line in lines]
    rows.append(f"╚{border}╝")
    return "\n".join(rows) + "\n"

BANNER_1 = r"""
 ______     _____       _       _ _
|___  /    / ____|     | |     (_) |
   / / ___| (___  _ __ | | ___  _| |_
  / / / __|\___ \| '_ \| |/ _ \| | __|
 / /__\__ \____) | |_) | | (_) | | |_
/_____|___/_____/| .__/|_|\___/|_|\__|
                 | |
                 |_|
"""

BANNER_2 = r"""
 ▒███████▒      ░██████  ██▓███   ██▓     ▒█████   ██▓▄▄▄█████▓
 ▒ ▒ ▒ ▄▀░    ▒██    ▒ ▓██░  ██▒▓██▒    ▒██▒  ██▒▓██▒▓  ██▒ ▓▒
 ░ ▒ ▄▀▒░     ░ ▓██▄   ▓██░ ██▓▒▒██░    ▒██░  ██▒▒██▒▒ ▓██░ ▒░
   ▄▀▒   ░      ▒   ██▒▒██▄█▓▒ ▒▒██░    ▒██   ██░░██░░ ▓██▓ ░
 ▒███████▒    ▒██████▒▒▒██▒ ░  ░░██████▒░ ████▓▒░░██░  ▒██▒ ░
 ░▒▒ ▓░▒░▒    ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░ ░▓    ▒ ░░
"""

BANNER_3 = r"""
        .-'''-.
       /  .-. .-\
      |  (o ) (o )|
       \   .---.  /
        '-._____.-'
       /   /|_|\   \
      |   [     ]   |

 _____  _____ ____  __    ____  __________
/__  / / ___// __ \/ /   / __ \/  _/_  __/
  / /  \__ \/ /_/ / /   / / / // /  / /
 / /_____/ / ____/ /___/ /_/ // /  / /
/____/____/_/   /_____/\____/___/ /_/

       [ one wrong move and it's game over ]
"""

BANNER_4 = r"""
      ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠

 ______ ___________ _     _____ _____ _____
|___  //  ___| ___ \ |   |  _  |_   _|_   _|
   / / \ `--.| |_/ / |   | | | | | |   | |
  / /   `--. \  __/| |   | | | | | |   | |
./ /___/\__/ / |   | |___\ \_/ /_| |_  | |
\_____/\____/\_|   \_____/\___/ \___/  \_/

        >> framework loaded :: tor + nmap + msf <<
      ☠ ☠ ☠ ☠  NO AUTHORIZATION, NO SCAN  ☠ ☠ ☠ ☠
"""

BANNER_5 = r"""
 _____    ____  ____  _     ___ ___ _____
|__  /   / ___||  _ \| |   / _ \_ _|_   _|
  / /____\___ \| |_) | |  | | | | |  | |
 / /|_____|__) |  __/| |__| |_| | |  | |
/____|   |____/|_|   |_____\___/___| |_|

   (this banner intentionally left mysterious. - Zeeshan Ali)
"""

BANNER_6 = r"""
        ___  ___
       (o o) (o o)
      ,-\__/-\__/-.
     / /          \ \
    | |  ZSPLOIT    | |
     \ \          / /
      '-.______.-'

 ______     ___________ _     _____ _____ _____
|___  /    /  ___| ___ \ |   |  _  |_   _|_   _|
   / /_____\ `--.| |_/ / |   | | | | | |   | |
  / /______|`--. \  __/| |   | | | | | |   | |
./ /___    /\__/ / |   | |___\ \_/ /_| |_  | |
\_____/    \____/\_|   \_____/\___/ \___/  \_/

   !! AUTHORIZED TARGETS ONLY — UNAUTHORIZED USE = CRIME !!
"""

# Heart-shaped banner spelling "ZF" inside it (Metasploit-style novelty banner)
BANNER_HEART = r"""
{heart}    ███████╗      ███████╗{heart}
{heart}    ╚══███╔╝      ██╔════╝{heart}
{heart}      ███╔╝       █████╗  {heart}
{heart}     ███╔╝        ██╔══╝  {heart}
{heart}    ███████╗      ██║     {heart}
{heart}    ╚══════╝      ╚═╝     {heart}

           {heartword} Z-Sploit  ·  by Zeeshan Ali {heartword}
"""

def render_heart_banner():
    """Builds the heart banner using a red ASCII heart glyph, Metasploit-novelty style."""
    heart = red("\u2764")   # ❤ in red
    line = BANNER_HEART.format(heart=heart, heartword=heart)
    return line

BANNERS = [BANNER_1, BANNER_2, BANNER_3, BANNER_4, BANNER_5, BANNER_6]

def random_banner():
    """Pick one of the six banners at random (5 normal + 1 heart), like msfconsole's banner roulette."""
    choice = random.randint(0, len(BANNERS))  # len(BANNERS) index reserved for heart banner
    if choice == len(BANNERS):
        return render_heart_banner()
    return BANNERS[choice]

# ─────────────────────────────────────────────
#  Welcome Screen
# ─────────────────────────────────────────────
def welcome():
    clear()
    width = 58
    cfg = load_config()
    display_mode = cfg.get("display_mode", "professional")

    if display_mode == "classic":
        print(cyan(random_banner()))
        print(bold(white("Z-Sploit".center(width))))
        print(cyan("Zeeshan Ali".center(width)))
    else:
        print(cyan(_banner_professional()))

    print()
    print("─" * width)
    desc = (
        "Z-Sploit scans websites, networks, and this device\n"
        "for common security weaknesses, and explains what it\n"
        "finds in plain language — no security background needed.\n"
        "\n"
        "Only use it on things you own or have permission to test."
    )
    for line in desc.splitlines():
        print(line.center(width))
    print("─" * width)
    print(yellow(f"Type {bold('help')} at any prompt to see usage information."))
    update_status = check_for_updates()
    if update_status is True:
        print(magenta("⚡ A newer version of Z-Sploit is available — choose 'Update' in the menu."))
    print()

# ─────────────────────────────────────────────
#  Self-Update (git pull from Z-Sploit repo)
# ─────────────────────────────────────────────
ZSPLOIT_REPO_URL = "https://github.com/Zeeshan-Ali78/Z-Sploit.git"

def get_script_dir():
    return os.path.dirname(os.path.abspath(__file__))

def check_for_updates():
    """
    Check if the local copy is inside a git repo tied to the Z-Sploit
    GitHub repo. If so, fetch + report whether updates are available.
    Returns True if updates are available, False otherwise (or on error).
    """
    repo_dir = get_script_dir()
    git_dir = os.path.join(repo_dir, ".git")

    if not os.path.isdir(git_dir):
        return None  # not a git checkout

    try:
        subprocess.run(
            ["git", "-C", repo_dir, "fetch", "origin"],
            check=True, capture_output=True, text=True, timeout=30
        )
        local = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "@"],
            check=True, capture_output=True, text=True
        ).stdout.strip()
        remote = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "@{u}"],
            check=True, capture_output=True, text=True
        ).stdout.strip()
        return local != remote
    except Exception:
        return None


def show_scan_history():
    """List past scans from ~/zsploit_logs/history.json, newest first."""
    print(bold(cyan("\n[*] Scan History")))
    print("─" * 50)

    if not os.path.exists(HISTORY_PATH):
        print(yellow("    No scans logged yet."))
        return

    try:
        with open(HISTORY_PATH, "r") as f:
            history = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(red(f"    Could not read history: {e}"))
        return

    if not history:
        print(yellow("    No scans logged yet."))
        return

    print(f"    {yellow('#'.ljust(4))}{yellow('DATE/TIME'.ljust(20))}"
          f"{yellow('ACTION'.ljust(16))}{yellow('TARGET'.ljust(20))}{yellow('SUMMARY')}")
    for i, entry in enumerate(reversed(history[-25:]), start=1):
        print(f"    {white(str(i).ljust(4))}{white(entry.get('timestamp','').ljust(20))}"
              f"{white(entry.get('action','').ljust(16))}{white(entry.get('target','').ljust(20))}"
              f"{white(entry.get('summary',''))}")

    print(yellow(f"\n    Showing last {min(25, len(history))} of {len(history)} total scans."))
    print(yellow(f"    Full logs are in: {LOG_DIR}"))


def show_settings():
    """View/edit ~/.zsploit_config.json interactively."""
    cfg = load_config()
    while True:
        print(bold(cyan("\n[*] Settings")))
        print("─" * 50)
        print(f"    {white('1')}  Nmap timing template     : {yellow(cfg.get('nmap_timing','T4'))}  (T1 slow/stealthy .. T5 fastest)")
        print(f"    {white('2')}  Auto-save scan logs      : {yellow(str(cfg.get('auto_save_logs', True)))}")
        print(f"    {white('3')}  Last target (convenience): {yellow(cfg.get('last_target','') or '(none)')}")
        print(f"    {white('4')}  Color theme              : {yellow(cfg.get('theme','classic'))}  "
              f"(options: {', '.join(THEMES.keys())})")
        print(f"    {white('5')}  Display mode             : {yellow(cfg.get('display_mode','professional'))}  "
              f"(professional / classic)")
        print(f"    {white('6')}  Plain-language summaries : {yellow(str(cfg.get('explain_mode', True)))}  "
              f"(explains results in simple terms after each scan)")
        print(f"    {white('7')}  Back to main menu")

        choice = input(bold("\n    Change which setting? [1-7]: ")).strip()

        if choice == "1":
            val = input("    New timing (T1-T5): ").strip().upper()
            if re.fullmatch(r"T[1-5]", val):
                cfg["nmap_timing"] = val
                save_config(cfg)
                print(green(f"    [✔] Nmap timing set to {val}."))
            else:
                print(red("    Invalid — must be T1 to T5."))
        elif choice == "2":
            cfg["auto_save_logs"] = not cfg.get("auto_save_logs", True)
            save_config(cfg)
            print(green(f"    [✔] Auto-save scan logs set to {cfg['auto_save_logs']}."))
        elif choice == "3":
            cfg["last_target"] = ""
            save_config(cfg)
            print(green("    [✔] Last target cleared."))
        elif choice == "4":
            val = input(f"    New theme ({'/'.join(THEMES.keys())}): ").strip().lower()
            if val in THEMES:
                cfg["theme"] = val
                save_config(cfg)
                apply_theme(val)
                print(green(f"    [✔] Theme switched to '{val}' — applied immediately."))
            else:
                print(red(f"    Invalid — choose one of: {', '.join(THEMES.keys())}."))
        elif choice == "5":
            val = input("    New display mode (professional/classic): ").strip().lower()
            if val in ("professional", "classic"):
                cfg["display_mode"] = val
                save_config(cfg)
                print(green(f"    [✔] Display mode set to '{val}'. Takes effect on next screen clear / restart."))
            else:
                print(red("    Invalid — must be 'professional' or 'classic'."))
        elif choice == "6":
            cfg["explain_mode"] = not cfg.get("explain_mode", True)
            save_config(cfg)
            print(green(f"    [✔] Plain-language summaries set to {cfg['explain_mode']}."))
        elif choice == "7":
            return
        else:
            print(red("    Please enter 1, 2, 3, 4, 5, 6, or 7."))


def run_update():
    """
    Update Z-Sploit from its GitHub repo.
      - If the script is running inside a git checkout, do `git pull`.
      - Otherwise, offer to clone the repo fresh into ./Z-Sploit-latest
        next to the current script (since there's nothing to pull into).
    """
    print(bold(cyan("\n[*] Checking for Z-Sploit updates ...")))
    repo_dir = get_script_dir()
    git_dir = os.path.join(repo_dir, ".git")

    if os.path.isdir(git_dir):
        # We're inside a git checkout — do a normal pull
        try:
            result = subprocess.run(
                ["git", "-C", repo_dir, "pull", "--ff-only", "origin"],
                capture_output=True, text=True, timeout=60
            )
            print(result.stdout.strip())
            if result.returncode == 0:
                if "Already up to date" in result.stdout or "Already up-to-date" in result.stdout:
                    print(green("[✔] Z-Sploit is already up to date."))
                else:
                    print(green("[✔] Z-Sploit updated successfully. Restart the script to use the new version."))
            else:
                print(red("[!] Update failed:"))
                print(red(result.stderr.strip()))
                print(yellow("    If you have local changes, commit/stash them first, or re-clone the repo."))
        except FileNotFoundError:
            print(red("[!] 'git' is not installed. Install it first (e.g. 'apt install git' or 'pkg install git')."))
        except subprocess.TimeoutExpired:
            print(red("[!] Update timed out. Check your network connection and try again."))
        except Exception as e:
            print(red(f"[!] Unexpected error during update: {e}"))
    else:
        # Not a git checkout — offer a fresh clone alongside the current script
        print(yellow("[!] This copy of Z-Sploit isn't a git checkout, so there's nothing to 'pull'."))
        dest = os.path.join(repo_dir, "Z-Sploit-latest")
        ans = input(
            bold(f"    Clone the latest version from GitHub into '{dest}'? (yes/no): ")
        ).strip().lower()
        if ans in ("yes", "y"):
            try:
                result = subprocess.run(
                    ["git", "clone", ZSPLOIT_REPO_URL, dest],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0:
                    print(green(f"[✔] Cloned latest Z-Sploit into: {dest}"))
                else:
                    print(red("[!] Clone failed:"))
                    print(red(result.stderr.strip()))
            except FileNotFoundError:
                print(red("[!] 'git' is not installed. Install it first (e.g. 'apt install git' or 'pkg install git')."))
            except subprocess.TimeoutExpired:
                print(red("[!] Clone timed out. Check your network connection and try again."))
            except Exception as e:
                print(red(f"[!] Unexpected error during clone: {e}"))
        else:
            print(cyan("    Skipped. You can grab updates manually from:"))
            print(cyan(f"    {ZSPLOIT_REPO_URL}"))

    input(yellow("\nPress Enter to continue..."))



def show_help():
    clear()
    width = 58
    print(bold(cyan("=" * width)))
    print(bold(white("Z-Sploit — Help / Usage Guide".center(width))))
    print(bold(cyan("=" * width)))
    print(f"""
{bold('OVERVIEW')}
  Z-Sploit is a guided wrapper that chains together
  well-known, legitimate security tools:
    - Tor       (traffic anonymisation)
    - Nmap      (host/service discovery & scanning)
    - Nikto     (web server / web app vulnerability scan)
    - Lynis     (local system hardening / vulnerability audit)
    - Metasploit (exploitation framework console)

{bold('LEGAL / ETHICAL NOTICE')}
  Only run Z-Sploit against systems you own or have
  explicit written authorization to test. Unauthorized
  scanning or exploitation of systems is illegal in most
  jurisdictions. The System Vulnerability Scan only ever
  audits the local machine Z-Sploit runs on — it never
  touches a remote target.

{bold('MAIN MENU OPTIONS')}
  1  Network Vulnerability  Runs Nmap through several
     Scan                   techniques: a combined top-1000
                           port + version (-sV) + default
                           script (-sC) scan, a full port
                           range scan (-p-), a UDP top-ports
                           scan, and OS detection (-O, if
                           capable). On Termux/Android, SYN
                           scan and OS detection are
                           automatically skipped in favor of
                           TCP Connect (-sT) — raw sockets
                           are blocked by the OS there even
                           as root, so this avoids silent
                           failures.
  2  Web Vulnerability      Runs Nikto + Nmap HTTP NSE
     Scan                   scripts against the target's
                           web server(s).
  3  System Vulnerability   Runs Lynis (or fallback checks)
     Scan                   against THIS local host only.
                           No target IP is requested.
  4  IP Trace                Runs Geo-IP lookup (ip-api.com),
                           reverse DNS, WHOIS, and traceroute
                           against the target.
  5  Full Remote Audit      Runs Network + Web scans, IP
                           Trace, then opens msfconsole
                           pre-seeded with the target as
                           RHOSTS.
  6  Website Recon          Resolves hostname → public IP,
                           shows hosting/ASN/datacenter
                           info, fingerprints the tech stack
                           (server, CDN) from HTTP headers,
                           and scans the page body + headers
                           for backend language, CMS, and
                           frontend framework markers (e.g.
                           PHP, ASP.NET, WordPress, React)
                           (+ WhatWeb if installed). This is
                           network-visible fingerprinting,
                           NOT a source-code audit.
  7  Website Copy          Mirrors the full site (pages,
                           CSS, JS, images) via Wget into
                           its own timestamped folder under
                           ~/zsploit_copies/, and writes a
                           basic-info.txt (target, resolved
                           IP, hosting provider, file count,
                           total size). Respects robots.txt.
                           Only static/browser-visible
                           content is copied — no databases,
                           server-side code, or logins.
  8  Scan History          Lists your last 25 scans (date,
                           action, target, summary) from
                           ~/zsploit_logs/history.json. Every
                           scan's full raw output is also
                           saved there as its own .log file.
  9  Settings              View/change Nmap timing template
                           (T1-T5), toggle auto-saving of
                           scan logs, clear the saved
                           last-target, switch the color
                           theme (classic/matrix/crimson/
                           mono), switch between the clean
                           professional look and the classic
                           ASCII-art banners, or turn the
                           plain-language "In Plain English"
                           summary boxes on/off. Stored in
                           ~/.zsploit_config.json.
 10  Help                  Shows this help screen.
 11  Update                Pulls the latest Z-Sploit from
                           GitHub ({ZSPLOIT_REPO_URL}).
 12  Exit                  Quits Z-Sploit.

{bold('TOR CONTROL')}
  Tor is started automatically at launch. You'll be asked
  whether to disconnect it when you finish your session.

{bold('COMMAND LINE')}
  python3 zsploit.py          Launch normally.
  python3 zsploit.py --help   Show this help and exit.
  python3 zsploit.py -h       Same as --help.

{bold('TIPS')}
  - Re-run the dependency check any time by restarting the
    script; missing tools are auto (re)installed where
    possible.
""")
    print(bold(cyan("=" * width)))
    input(yellow("\nPress Enter to return..."))

# ─────────────────────────────────────────────
#  Tor Control
# ─────────────────────────────────────────────
def _tor_port_open() -> bool:
    """Check whether something is already listening on Tor's SOCKS port (9050)."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=1):
            return True
    except OSError:
        return False


def start_tor():
    print(cyan("\n[*] Starting Tor service ..."))

    if _tor_port_open():
        print(green("[✔] Tor is already running on 127.0.0.1:9050 — reusing it."))
        return

    if ENV == "termux":
        os.system("tor &")
    else:
        os.system("sudo service tor start")

    # Give it a moment to bind, then actually verify instead of assuming.
    for _ in range(5):
        pause(1)
        if _tor_port_open():
            print(green("[✔] Tor is running. Traffic routed through onion network."))
            return

    print(red("[!] Could not confirm Tor started (port 9050 not responding)."))
    print(yellow("    Scans will proceed WITHOUT Tor anonymisation."))

def stop_tor():
    print(cyan("\n[*] Stopping Tor service ..."))
    if ENV == "termux":
        os.system("pkill tor")
    else:
        os.system("sudo service tor stop")
    print(green("[✔] Tor disconnected."))

# ─────────────────────────────────────────────
#  Operations
# ─────────────────────────────────────────────

def validate_ip(ip: str) -> bool:
    """Basic IPv4 / hostname validation."""
    import re
    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ipv4.match(ip):
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # Accept hostnames too
    hostname = re.compile(r"^[a-zA-Z0-9._-]+$")
    return bool(hostname.match(ip))


_NMAP_DIAGNOSED = None  # None = not checked yet this session; True/False = cached result


def _get_local_ip() -> str:
    """
    Best-effort local/source IP detection (no real packets sent — this
    just asks the OS which interface/address it WOULD use for an
    outbound connection, via a UDP socket that's never actually
    connected to anything).
    """
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _looks_like_real_local_ip(ip: str) -> bool:
    """
    Sanity-check a detected 'local IP' before trusting it enough to
    pass to nmap -S. If the detection trick couldn't actually reach
    the internet (sandboxed/restricted network), it can silently
    return a bogus/reserved address (TEST-NET ranges, 0.0.0.0, etc.) —
    confirmed in testing that using -S with such a wrong address makes
    nmap scans take 100x longer (or hang) instead of helping. Rejects
    those; accepts normal private ranges and anything else plausible.
    """
    if not ip or ip in ("0.0.0.0", "127.0.0.1"):
        return False
    bad_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.", "169.254.")
    return not any(ip.startswith(p) for p in bad_prefixes)


def nmap_route_workaround_flags() -> str:
    """
    Known Termux/Android fix for Nmap's 'setup_target: failed to
    determine route' error: Nmap always tries to read the kernel
    routing table during target setup (even for -sT), and Android
    blocks that for unprivileged apps regardless of root.

    -Pn (skip host-discovery ping) is always safe and confirmed fast
    in testing. -S (explicit source IP) is only added when the
    detected local IP passes a sanity check — confirmed in testing
    that -S with a WRONG address makes scans ~100x slower instead of
    fixing anything, so it's better to skip it than guess wrong.

    Returns an empty string on non-Termux.
    """
    if ENV != "termux":
        return ""
    local_ip = _get_local_ip()
    if _looks_like_real_local_ip(local_ip):
        return f"-Pn -S {local_ip}"
    return "-Pn"


RISK_COLORS = {"Low": green, "Medium": yellow, "High": red, "Unknown": white}


def _box_row(plain_text: str, width: int, colorize=None) -> str:
    """
    Builds one bordered row: pads to `width` using the PLAIN text's
    length (ANSI color codes are invisible on screen but count toward
    len(), so padding must be computed before colorizing — otherwise
    colored lines end up shorter than they should and the box's right
    border drifts out of alignment).
    """
    padded = plain_text.ljust(width - 2)
    shown = colorize(padded) if colorize else padded
    return cyan("║") + shown + cyan("║")


def print_plain_summary(title: str, risk: str, points: list, next_steps: list = None):
    """
    Prints a boxed, plain-language explanation after a scan — no jargon,
    aimed at someone with no security background. `points` are short
    "what we found" sentences; `next_steps` are optional suggestions.
    Controlled by the 'explain_mode' setting (Settings → option 6).
    """
    cfg = load_config()
    if not cfg.get("explain_mode", True):
        return

    risk_color = RISK_COLORS.get(risk, white)
    width = 58
    print()
    print(cyan("╔" + "═" * (width - 2) + "╗"))
    print(_box_row(f" In Plain English: {title}", width, lambda s: bold(white(s))))
    print(cyan("╠" + "═" * (width - 2) + "╣"))
    print(_box_row(f" Overall risk level: {risk}", width, lambda s: s.replace(risk, risk_color(risk))))
    print(_box_row("", width))
    print(_box_row(" What we found:", width, bold))
    for p in points:
        for line in _wrap_text(p, width - 6):
            print(_box_row(f"   {line}", width))
    if next_steps:
        print(_box_row("", width))
        print(_box_row(" What to do next:", width, bold))
        for s in next_steps:
            for line in _wrap_text(s, width - 6):
                print(_box_row(f"   {line}", width))
    print(cyan("╚" + "═" * (width - 2) + "╝"))


def _wrap_text(text: str, width: int) -> list:
    """Simple word-wrap so long sentences don't break the summary box."""
    words = text.split()
    lines, current = [], ""
    for w in words:
        if len(current) + len(w) + 1 > width:
            lines.append(current)
            current = w
        else:
            current = f"{current} {w}".strip()
    if current:
        lines.append(current)
    return lines or [""]


def diagnose_nmap(force: bool = False) -> bool:
    """
    Pre-flight sanity check, run before any nmap-based scan: confirms
    the binary isn't just *present* on PATH but actually executes and
    scans successfully. Catches cases shutil.which() can't see — a
    broken/partial Termux install, missing shared libraries, a
    network/firewall that silently drops all scan traffic, etc.
    Prints a clear diagnosis instead of letting the real failure
    scroll past unnoticed inside a long scan's output. Cached for the
    session unless force=True, so repeated scans don't re-test every time.
    """
    global _NMAP_DIAGNOSED
    if _NMAP_DIAGNOSED is not None and not force:
        return _NMAP_DIAGNOSED

    print(yellow("\n[Diagnose] Verifying Nmap actually runs ..."))
    buf = []
    ret = run_cmd("nmap --version", buf)
    if ret != 0 or not any("Nmap version" in line for line in buf):
        print(red(
            "[✘] 'nmap --version' failed or gave unexpected output. The "
            "binary is on PATH but something is broken (corrupt install, "
            "missing shared library, wrong architecture package)."
        ))
        print(yellow("    Try: pkg uninstall nmap && pkg install nmap   (Termux)"))
        print(yellow("    Or:  sudo apt-get install --reinstall nmap   (Kali/Debian)"))
        _NMAP_DIAGNOSED = False
        return False

    print(green("[✔] nmap --version OK — binary runs correctly."))

    print(yellow("[Diagnose] Testing real scan capability against a known-good host"))
    print(yellow("           (scanme.nmap.org — provided by the Nmap project for this) ..."))
    route_flags = nmap_route_workaround_flags()
    buf2 = []
    ret2 = run_cmd(f"nmap -sT -p 80 --open -T4 {route_flags} scanme.nmap.org", buf2)
    text2 = "".join(buf2)

    if "failed to determine route" in text2.lower() and route_flags == "":
        # On Termux this almost always means the known routing-table
        # restriction (see nmap_route_workaround_flags) — retry once
        # with the workaround before concluding it's a real failure.
        print(yellow("    [i] Hit the known Termux routing issue — retrying with -Pn -S <local-ip> ..."))
        local_ip = _get_local_ip()
        if local_ip:
            buf2 = []
            ret2 = run_cmd(f"nmap -sT -p 80 --open -T4 -Pn -S {local_ip} scanme.nmap.org", buf2)
            text2 = "".join(buf2)

    if ret2 == 0 and ("80/tcp" in text2 or "Host is up" in text2):
        print(green("[✔] Test scan succeeded — Nmap and this network can reach and scan hosts."))
        _NMAP_DIAGNOSED = True
        return True

    print(red("[✘] Test scan against scanme.nmap.org failed or returned nothing."))
    if "failed to determine route" in text2.lower():
        print(yellow(
            "    This device has NO network path out at all for scanning — "
            "likely mobile data/carrier or a VPN is blocking it, or there's "
            "no internet connection right now."
        ))
    elif "Could not resolve" in text2 or "Failed to resolve" in text2:
        print(yellow(
            "    DNS resolution is failing — check your internet/DNS "
            "settings (try 'ping google.com' outside Zsploit)."
        ))
    else:
        print(yellow("    Raw nmap output from the test:"))
        for line in buf2[-10:]:
            print("    " + line.rstrip())
    print(yellow(
        "    This means the problem is environmental (network/carrier/VPN), "
        "not a bug in Zsploit's code — every scan option will fail the same "
        "way until this is resolved."
    ))
    _NMAP_DIAGNOSED = False
    return False


def run_vulnerability_scan(ip: str):
    """Nmap scan."""
    print(bold(cyan(f"\n[*] Starting Vulnerability Scan on {ip} ...")))
    print("─" * 50)

    if not ensure_tool("nmap", "Nmap", install_nmap):
        print(red("\n[!] Cannot run vulnerability scan without Nmap."))
        return

    if not diagnose_nmap():
        print(yellow(
            "\n[i] The diagnostic above failed (often just because the test "
            "site scanme.nmap.org specifically is blocked/unreachable on "
            "this network — that does NOT mean your actual target will "
            "fail). Proceeding with the real scan anyway ..."
        ))

    if not _target_reachable(ip):
        print(yellow(
            f"\n[!] '{ip}' did not respond to a ping — it may be unreachable "
            f"from this network, blocking ICMP, or the IP/hostname may be "
            f"wrong. Nmap will still be attempted, but if you see "
            f"'failed to determine route' below, it means this device has "
            f"no network path to that address at all (not a Zsploit bug)."
        ))

    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
    # On Termux/Android, raw sockets (needed for -sS SYN scan and -O OS
    # detection) are blocked by the kernel/SELinux policy even when the
    # process reports UID 0 — so checking root alone isn't enough here.
    # This was the actual cause of Option 1 silently failing/erroring
    # on Termux: nmap would try -sS/-O, get "dnet: Failed to open
    # device" or similar, and the scan would look broken.
    has_root = is_root and ENV != "termux"

    if ENV == "termux":
        print(yellow(
            "\n[i] Running on Termux/Android — raw sockets are blocked by the "
            "OS regardless of root, so SYN scan (-sS) and OS detection (-O) "
            "are skipped. Using TCP Connect (-sT) instead, which works "
            "reliably here."
        ))
    elif not has_root:
        print(yellow(
            "\n[i] Not running as root — SYN scan (-sS) and OS detection (-O) "
            "need raw-socket access, so this run will use their unprivileged "
            "equivalents (-sT) instead. Run with 'sudo' for the full set."
        ))

    cfg = load_config()
    timing = cfg.get("nmap_timing", "T4")
    port_scan_flag = "-sS" if has_root else "-sT"
    port_scan_name = "SYN (stealth)" if has_root else "TCP Connect"

    # Known Termux/Android fix for "failed to determine route": Nmap
    # can't read the kernel routing table there (even as root), so we
    # pre-supply the source IP and skip the ping-based route check.
    route_flags = nmap_route_workaround_flags()
    if route_flags:
        print(yellow(
            f"\n[i] Termux detected — applying the routing workaround "
            f"({route_flags}) to avoid 'failed to determine route' errors."
        ))

    # -v + --stats-every: nmap otherwise prints NOTHING while a phase
    # runs (confirmed in testing) — on a very slow connection a silent
    # multi-minute scan looks exactly like it's stuck/broken. These
    # give live "Discovered open port..." / periodic "% done" output.
    # --host-timeout bounds the worst case so a truly unreachable or
    # extremely slow target doesn't hang indefinitely either.
    live_flags = "-v --stats-every 10s --host-timeout 5m"

    phases = [
        # Combined into one nmap run (instead of 3 separate ones) so
        # host discovery only happens once — much faster, same coverage.
        (f"{port_scan_name} scan + version + scripts (top 1000 ports)",
         f"nmap {port_scan_flag} -sV -sC --open -{timing} {live_flags} {route_flags} {ip}"),

        ("Full port range scan (-p-) — catches non-standard ports",
         f"nmap {port_scan_flag} -p- --open -{timing} {live_flags} {route_flags} {ip}"),

        ("UDP scan, top 20 ports (-sU) — slower, often filtered",
         f"nmap -sU --top-ports 20 --open -{timing} {live_flags} {route_flags} {ip}"),
    ]
    if has_root:
        phases.append((
            "OS detection (-O)",
            f"nmap -O {live_flags} {ip}"
        ))
    elif ENV == "termux":
        print(yellow("[!] Skipping OS detection (-O) — blocked on Termux/Android regardless of root."))
    else:
        print(yellow("[!] Skipping OS detection (-O) — requires root."))

    log_buffer = []
    for label, cmd in phases:
        print(yellow(f"\n[Nmap] {label} ..."))
        log_buffer.append(f"\n=== {label} ===\n$ {cmd}\n")
        run_cmd(cmd, log_buffer)

    # ── Parsed summary table: open ports found across all phases ──
    full_text = "".join(log_buffer)
    raw_matches = re.findall(
        r"^(\d+/(?:tcp|udp))[ \t]+open[ \t]+(\S+(?:[ \t]+.*)?)$", full_text, re.MULTILINE
    )
    # The same port can appear in multiple phases with different levels of
    # detail (e.g. "open https" from an early phase vs "open ssl/https
    # github.com" once -sV finishes) — dedupe by port/protocol, keeping
    # whichever line has the most detail (the longest one), rather than by
    # exact line text, which previously let the same port show up twice.
    best_by_port = {}
    for port_proto, rest in raw_matches:
        full_line = f"{port_proto} open  {rest}"
        if port_proto not in best_by_port or len(rest) > len(best_by_port[port_proto][1]):
            best_by_port[port_proto] = (full_line, rest)
    port_lines = sorted((v[0] for v in best_by_port.values()),
                         key=lambda line: int(line.split("/")[0]))
    print(white("\n    ── Open Ports Summary ──"))
    if port_lines:
        print(f"    {yellow('PORT/PROTO'.ljust(14))}{yellow('STATE'.ljust(8))}{yellow('SERVICE / VERSION')}")
        for pl in port_lines:
            parts = pl.split(None, 2)
            port_proto = parts[0] if len(parts) > 0 else ""
            state      = parts[1] if len(parts) > 1 else ""
            rest       = parts[2] if len(parts) > 2 else ""
            print(f"    {white(port_proto.ljust(14))}{green(state.ljust(8))}{white(rest)}")
    else:
        print("    No open ports found across any scan phase.")

        # Explain WHY — nmap's --open flag hides filtered/closed ports
        # entirely, so "nothing shown" is ambiguous on its own: it could
        # mean genuinely nothing is open, OR a CDN/WAF/firewall silently
        # filtered the scan traffic (very common on CDN-fronted sites —
        # this is exactly what a security-focused CDN like Hostinger's
        # is supposed to do to scan-like traffic).
        not_shown = re.findall(
            r"Not shown:\s+(\d+)\s+([\w|]+)\s+(?:tcp|udp)?\s*ports?", full_text
        )
        if not_shown:
            print(yellow("\n    [i] Why nothing shows: nmap's --open flag hides any port that"))
            print(yellow("        isn't open. Here's what it actually found per phase:"))
            for count, state in not_shown:
                print(f"        {white(count)} port(s) reported as {yellow(state)}")
            if any(state == "filtered" for _, state in not_shown):
                print(yellow(
                    "\n        'filtered' means something (commonly a CDN/WAF/firewall — "
                    "Hostinger's edge included) is silently dropping the scan packets "
                    "rather than responding. This is usually intentional anti-scanning "
                    "protection on the hosting/CDN side, not a bug in Zsploit or proof "
                    "the ports are actually closed."
                ))
        else:
            print(yellow(
                "    [i] No 'Not shown' summary line found in the output either — "
                "check the full log for errors (e.g. a timed-out phase)."
            ))

    # ── Plain-language translation of the results ──
    PORT_MEANINGS = {
        21:   ("file transfer (FTP)", "High", "FTP often sends passwords in plain text — avoid exposing it directly to the internet."),
        22:   ("remote login (SSH)", "Medium", "Normal for servers you manage remotely, but make sure it uses a strong password or key, not a weak/default one."),
        23:   ("remote login without encryption (Telnet)", "High", "Telnet is outdated and sends everything — including passwords — unencrypted. Disable it if possible."),
        25:   ("sending email (SMTP)", "Medium", "Make sure this isn't an open mail relay anyone can abuse to send spam."),
        80:   ("regular website traffic (HTTP)", "Low", "Normal for a public website."),
        443:  ("secure website traffic (HTTPS)", "Low", "Normal and expected for a public website."),
        3306: ("a MySQL database", "High", "Databases generally should not be reachable directly from the internet."),
        5432: ("a PostgreSQL database", "High", "Databases generally should not be reachable directly from the internet."),
        6379: ("a Redis database", "High", "Redis is often unauthenticated by default — this is a common and serious misconfiguration."),
        27017:("a MongoDB database", "High", "Databases generally should not be reachable directly from the internet."),
        3389: ("remote desktop access (RDP)", "High", "Exposing remote desktop directly to the internet is a common attack target."),
        8080: ("an alternate web server/admin panel", "Medium", "Worth confirming this is intentional and password-protected."),
    }
    plain_points, plain_steps, risk_levels = [], [], []
    for pl in port_lines:
        try:
            port_num = int(pl.split("/")[0])
        except ValueError:
            continue
        if port_num in PORT_MEANINGS:
            meaning, risk, advice = PORT_MEANINGS[port_num]
            plain_points.append(f"Port {port_num} is open — this is typically used for {meaning}.")
            plain_steps.append(advice)
            risk_levels.append(risk)
        else:
            plain_points.append(f"Port {port_num} is open — this is a less common port, worth checking what's running on it.")
            risk_levels.append("Medium")

    if not port_lines:
        if "filtered" in full_text.lower():
            overall_risk = "Low"
            plain_points = [
                "No open doors (ports) were visible from the outside.",
                "This usually means a firewall or CDN is actively blocking scan attempts — generally a good sign, not a problem.",
            ]
        else:
            overall_risk = "Low"
            plain_points = ["No open doors (ports) were found — nothing appears to be directly exposed."]
        plain_steps = []
    else:
        overall_risk = "High" if "High" in risk_levels else ("Medium" if "Medium" in risk_levels else "Low")

    print_plain_summary("Network Scan", overall_risk, plain_points, plain_steps)

    summary = f"{len(port_lines)} open port(s) found"
    log_file = log_scan("network_scan", ip, log_buffer, summary)
    if log_file:
        print(yellow(f"\n[Log] Full output saved → {log_file}"))

    print(green("\n[✔] Vulnerability scan complete — all techniques attempted."))


def _resolve_target_ip(target: str):
    """Resolve a hostname/domain to its public IP. Returns None on failure."""
    import socket
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def detect_site_languages(html: str, headers: dict) -> dict:
    """
    Best-effort detection of the backend language(s), CMS/platform, and
    frontend framework(s) a website is built with — based on publicly
    visible signals (HTML markers, cookie names, asset paths, headers).
    This is NOT source-code access; it's pattern matching on what the
    server already sends to any visitor's browser.
    """
    body = (html or "").lower()
    hdrs = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
    combined = body + " " + hdrs

    findings = {"Backend / Language": [], "CMS / Platform": [], "Frontend": []}

    backend_signatures = [
        ("PHP",               [".php", "phpsessid", "x-powered-by:php"]),
        ("ASP.NET (.NET/C#)", ["__viewstate", ".aspx", "x-aspnet-version"]),
        ("Java (JSP/Servlet)",["jsessionid", ".jsp", ".do;"]),
        ("Ruby on Rails",     ["csrf-param", "authenticity_token", "_rails_session"]),
        ("Python (Django)",   ["csrfmiddlewaretoken", "django"]),
        ("Node.js / Express", ["x-powered-by:express", "connect.sid"]),
        ("Go",                ["x-powered-by:go"]),
    ]
    for lang, markers in backend_signatures:
        if any(m in combined for m in markers):
            findings["Backend / Language"].append(lang)

    cms_signatures = [
        ("WordPress", ["wp-content", "wp-includes", "wp-json", "wordpress"]),
        ("Drupal",    ["drupal.settings", "/sites/default/files", "x-generator:drupal"]),
        ("Joomla",    ["/media/jui/", "joomla"]),
        ("Magento",   ["mage.cookies", "/skin/frontend/", "x-magento"]),
        ("Shopify",   ["cdn.shopify.com", "shopify.theme", "myshopify.com"]),
        ("Wix",       ["wix.com", "wixstatic.com"]),
        ("Squarespace", ["squarespace"]),
        ("Laravel",   ["laravel_session"]),
    ]
    for cms, markers in cms_signatures:
        if any(m in combined for m in markers):
            findings["CMS / Platform"].append(cms)

    frontend_signatures = [
        ("React",       ["data-reactroot", "react-dom", "__react"]),
        ("Next.js",     ["__next_data__", "/_next/"]),
        ("Vue.js",      ["data-v-", "v-cloak", "__vue__"]),
        ("Nuxt.js",     ["__nuxt__"]),
        ("Angular",     ["ng-version", "ng-app"]),
        ("jQuery",      ["jquery"]),
        ("Bootstrap",   ["bootstrap.min.css", "bootstrap.min.js"]),
        ("Tailwind CSS",["tailwind"]),
    ]
    for fe, markers in frontend_signatures:
        if any(m in combined for m in markers):
            findings["Frontend"].append(fe)

    return findings


def probe_common_paths(target: str) -> list:
    """
    Fallback fingerprinting when headers are stripped by a CDN/proxy
    (common on Hostinger, Cloudflare, etc.): probe a handful of
    well-known paths that only exist for specific platforms. A 200/30x
    response on one of these is a strong signal even with no useful
    headers at all.
    """
    probes = [
        # Only specific filenames/folder structures unique enough to a
        # platform that a real hit is a strong signal. Generic guesses
        # like "/administrator/", "/cgi-bin/", "/user/login" were removed
        # after testing showed real sites (github.com) return 200 for
        # them (likely deceptive/anti-scanning responses, or unrelated
        # legacy routing) despite running none of these technologies —
        # a false-positive risk no amount of baseline-checking fixes if
        # the path itself is too common to begin with.
        ("/wp-login.php",        "WordPress"),
        ("/wp-json/",            "WordPress (REST API exposed)"),
        ("/xmlrpc.php",          "WordPress (XML-RPC exposed)"),
        ("/sites/default/",      "Drupal"),
        ("/_next/static/",       "Next.js (React)"),
    ]
    def _probe_one(base: str, path: str):
        """Returns (status_code, content_length) or (None, None) on error."""
        try:
            req = urllib.request.Request(
                base + path,
                headers={"User-Agent": "Mozilla/5.0 (Zsploit-Recon)"},
                method="HEAD",
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                return resp.status, resp.headers.get("Content-Length")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Length") if e.headers else None
        except Exception:
            return None, None

    found = []
    for scheme in ("https", "http"):
        base = f"{scheme}://{target}"

        # Baseline: a guaranteed-nonexistent path. Many sites (GitHub
        # included) return 200 or a redirect for EVERY path instead of a
        # real 404 ("soft 404s"), which would otherwise false-positive
        # every single probe below. If the site's "nothing here" response
        # looks the same as a real page, we can't trust a bare status code.
        baseline_path = f"/zsploit-recon-check-{random.randint(10**8, 10**9)}"
        baseline_status, baseline_len = _probe_one(base, baseline_path)

        reached = baseline_status is not None
        for path, label in probes:
            status, length = _probe_one(base, path)
            if status is None:
                continue
            reached = True
            if status >= 400:
                continue
            # Only count this as a real signal if it's distinguishable
            # from how the site responds to a path that can't possibly
            # exist — different status code, or (same status) a
            # meaningfully different response size.
            if baseline_status is not None and status == baseline_status:
                if length is not None and baseline_len is not None and length != baseline_len:
                    found.append(label)
                # same status AND same/unknown length → indistinguishable
                # from the baseline, almost certainly a soft-404, skip it
                continue
            found.append(label)
        if reached:
            break
    return sorted(set(found))


def run_website_recon(target: str):
    """
    Website recon / profile:
      - Resolves hostname -> public IP (shows 'local' vs 'hosted' IP distinction)
      - Hosting info: ASN, ISP, datacenter location (reuses Geo-IP lookup)
      - Tech stack fingerprint: server software, CMS, language, framework
        — inferred from HTTP response headers (no source-code access, so
        this is best-effort fingerprinting, not a code audit)
    """
    print(bold(cyan(f"\n[*] Website Recon on {target} ...")))
    print("─" * 50)

    resolved_ip = _resolve_target_ip(target)
    if resolved_ip:
        print(yellow("[Resolve] Hostname → Public/Hosted IP:"))
        print(f"    {white(resolved_ip)}")
    else:
        print(red(f"[!] Could not resolve '{target}' to an IP. Using it as-is."))
        resolved_ip = target

    print(yellow("\n[Note] A 'local IP' (e.g. 192.168.x.x / 127.0.0.1) only exists"))
    print(yellow("        on the machine the site is physically hosted on — it is"))
    print(yellow("        not visible from the outside. What you can see remotely"))
    print(yellow("        is the public/hosted IP above, plus whatever the hosting"))
    print(yellow("        provider/CDN exposes (see hosting info below)."))

    # Hosting / ASN / datacenter info (reuses existing Geo-IP lookup)
    geo_data = run_geolocation(resolved_ip)
    hosting_org = (geo_data or {}).get("isp") or (geo_data or {}).get("org")

    # --- Tech stack fingerprint via HTTP headers + page body ---
    print(yellow("\n[Fingerprint] Fetching page (headers + HTML) ..."))
    headers_found = {}
    html_body = ""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{target}",
                headers={"User-Agent": "Mozilla/5.0 (Zsploit-Recon)"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                headers_found = dict(resp.getheaders())
                # Read up to ~300 KB of body — plenty for fingerprinting,
                # avoids pulling huge pages/media into memory.
                raw = resp.read(300_000)
                charset = resp.headers.get_content_charset() or "utf-8"
                html_body = raw.decode(charset, errors="replace")
                print(f"    {white(f'[{scheme.upper()} reachable]')}")
                break
        except Exception as e:
            print(red(f"    [{scheme.upper()} failed] {e}"))

    guess = []  # defined up front so it's always safe to reference later,
                # even when headers_found ends up empty
    web_server = headers_found.get("Server", "unknown")

    if headers_found:
        interesting = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
                        "X-Drupal-Cache", "X-Varnish", "Via", "CF-RAY", "X-Cache"]
        print(white("\n    ── Raw headers of interest ──"))
        for h in interesting:
            if h in headers_found:
                print(f"    {yellow(h.ljust(18))}{white(headers_found[h])}")

        combined = " ".join(headers_found.values()).lower()
        if "php" in combined: guess.append("PHP")
        if "asp.net" in combined: guess.append("ASP.NET (.NET / C#)")
        if "express" in combined or "node" in combined: guess.append("Node.js / Express")
        if "wordpress" in combined or "wp-" in combined: guess.append("WordPress (CMS)")
        if "drupal" in combined: guess.append("Drupal (CMS)")
        if "joomla" in combined: guess.append("Joomla (CMS)")
        if "nginx" in combined: guess.append("Nginx (web server)")
        if "apache" in combined: guess.append("Apache (web server)")
        header_keys_lower = [h.lower() for h in headers_found]
        if "cloudflare" in combined or "cf-ray" in header_keys_lower:
            guess.append("Cloudflare (CDN/proxy)")

        print(white("\n    ── Likely tech stack (header-based guess) ──"))
        if guess:
            for g in sorted(set(guess)):
                print(f"    - {white(g)}")
        else:
            print("    Could not confidently fingerprint — headers may be stripped/hardened.")
    else:
        print(red("    [!] Could not fetch headers (site unreachable or blocking requests)."))

    # --- Language / CMS / frontend-framework detection (headers + body) ---
    print(white("\n    ── Site languages & frameworks (body + header scan) ──"))
    site_langs = detect_site_languages(html_body, headers_found)

    # Fallback probing: when a CDN/proxy strips headers and the body gave
    # nothing, check a handful of known platform-specific paths directly.
    print(yellow("\n[Probe] Checking known platform paths (fallback signal) ..."))
    probe_hits = probe_common_paths(target)
    if probe_hits:
        site_langs.setdefault("CMS / Platform", [])
        site_langs["CMS / Platform"].extend(probe_hits)

    any_found = False
    for category, items in site_langs.items():
        if items:
            any_found = True
            print(f"    {yellow(category.ljust(22))}{white(', '.join(sorted(set(items))))}")
    if not any_found:
        print("    No confident language/framework markers found")
        print("    (page may be minified, static, or behind a WAF/CDN that strips signals).")

    # Optional deeper fingerprint if WhatWeb is installed (offers install here too)
    if ensure_tool("whatweb", "WhatWeb", install_whatweb):
        print(yellow("\n[WhatWeb] Running deeper fingerprint (CMS, JS libs, analytics) ..."))
        os.system(f"whatweb -a 3 {target}")

    # --- Consolidated Architecture Summary ---
    print(bold(cyan("\n    ══════ Website Architecture Summary ══════")))
    print(f"    {yellow('Target'.ljust(22))}{white(target)}")
    print(f"    {yellow('Hosted IP'.ljust(22))}{white(resolved_ip)}")
    print(f"    {yellow('Hosting provider'.ljust(22))}{white(hosting_org or 'unknown')}")
    print(f"    {yellow('Web server'.ljust(22))}{white(web_server)}")

    backend_list = sorted(set(site_langs.get("Backend / Language", []) + guess))
    cms_list = sorted(set(site_langs.get("CMS / Platform", [])))
    frontend_list = sorted(set(site_langs.get("Frontend", [])))

    print(f"    {yellow('Backend language(s)'.ljust(22))}{white(', '.join(backend_list) or 'not detected')}")
    print(f"    {yellow('CMS / Platform'.ljust(22))}{white(', '.join(cms_list) or 'not detected')}")
    print(f"    {yellow('Frontend tech'.ljust(22))}{white(', '.join(frontend_list) or 'not detected')}")

    if not (backend_list or cms_list or frontend_list):
        print(yellow(
            "\n    [i] Nothing detected confidently — this usually means the\n"
            "        hosting CDN/proxy is stripping identifying headers (very\n"
            "        common, and generally a GOOD security practice, not a bug\n"
            "        in this scan)."
        ))

    recon_points = [f"Your website is hosted by {hosting_org or 'an unidentified provider'}, at address {resolved_ip}."]
    if cms_list:
        recon_points.append(f"It's built on {', '.join(cms_list)} — a popular website platform, which is fine, but keep it updated.")
    if backend_list:
        recon_points.append(f"The site uses {', '.join(backend_list)} behind the scenes.")
    if not (backend_list or cms_list or frontend_list):
        recon_points.append("We couldn't identify the website's technology from the outside — often a sign the hosting provider is actively hiding this information, which is a good thing.")
    print_plain_summary(
        "Website Recon",
        "Low",
        recon_points,
        ["This scan only looks at what's publicly visible — it does not check your website's actual source code."]
    )

    print(bold(red(
        "\n[i] Note: this is network-visible fingerprinting, not a source-code "
        "review. For a real code-level audit you'd need to share/upload the "
        "actual source for static analysis."
    )))
    print(green("\n[✔] Website recon complete."))


def run_website_copy(target: str):
    """
    Full website copy / mirror: downloads the site's pages, assets,
    and structure into its own timestamped folder using Wget's
    --mirror mode (standard, well-known archiving technique — same
    idea as 'Save page as', just for the whole site). Respects the
    site's robots.txt by default (no bypass added). Also writes a
    basic-info.txt with target, resolved IP, hosting org, scan time,
    and a file/size summary of what was copied.
    """
    print(bold(cyan(f"\n[*] Starting Website Copy on {target} ...")))
    print("─" * 50)

    if not ensure_tool("wget", "Wget", install_wget):
        print(red("\n[!] Cannot copy the website without Wget."))
        return

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    base_dir = os.path.expanduser(f"~/zsploit_copies/{safe_name}_{timestamp}")
    os.makedirs(base_dir, exist_ok=True)
    print(yellow(f"\n[Folder] Saving into: {base_dir}"))

    resolved_ip = _resolve_target_ip(target)
    geo_data = run_geolocation(resolved_ip) if resolved_ip else None
    hosting_org = (geo_data or {}).get("isp") or (geo_data or {}).get("org") or "unknown"

    print(yellow("\n[Wget] Mirroring site (pages, CSS, JS, images) ..."))
    log_buffer = [f"=== Website Copy: {target} ===\n"]
    wget_cmd = (
        f"wget --mirror --convert-links --adjust-extension "
        f"--page-requisites --no-parent --tries=2 --timeout=15 "
        f"-e robots=on -P {base_dir} https://{target}"
    )
    ret = run_cmd(wget_cmd, log_buffer)
    if ret != 0:
        print(yellow("[!] HTTPS mirror had issues, retrying with HTTP ..."))
        wget_cmd_http = wget_cmd.replace("https://", "http://")
        run_cmd(wget_cmd_http, log_buffer)

    # ── Summarize what got copied ──────────────────
    file_count = 0
    total_bytes = 0
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f == "basic-info.txt":
                continue
            fp = os.path.join(root, f)
            try:
                total_bytes += os.path.getsize(fp)
                file_count += 1
            except OSError:
                pass

    def human_size(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    info_path = os.path.join(base_dir, "basic-info.txt")
    info_text = (
        f"Z-Sploit Website Copy — Basic Info\n"
        f"{'=' * 40}\n"
        f"Target:            {target}\n"
        f"Resolved IP:       {resolved_ip or 'could not resolve'}\n"
        f"Hosting provider:  {hosting_org}\n"
        f"Copy date:         {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Saved to:          {base_dir}\n"
        f"Files copied:      {file_count}\n"
        f"Total size:        {human_size(total_bytes)}\n"
        f"\n"
        f"Note: this mirror respects the site's robots.txt by default.\n"
        f"Dynamic/server-side functionality (forms, logins, databases)\n"
        f"is NOT copied — only what a normal browser can fetch and see.\n"
    )
    with open(info_path, "w") as f:
        f.write(info_text)

    print(white("\n    ── Copy summary ──"))
    print(f"    {yellow('Files copied'.ljust(18))}{white(str(file_count))}")
    print(f"    {yellow('Total size'.ljust(18))}{white(human_size(total_bytes))}")
    print(f"    {yellow('Saved to'.ljust(18))}{white(base_dir)}")
    print(f"    {yellow('Info file'.ljust(18))}{white(info_path)}")

    log_file = log_scan(
        "website_copy", target, log_buffer,
        f"{file_count} file(s), {human_size(total_bytes)} — saved to {base_dir}"
    )
    if log_file:
        print(yellow(f"[Log] Wget transcript also saved → {log_file}"))

    print(green("\n[✔] Website copy complete."))


def run_web_vuln_scan(ip: str):
    """
    Web application / web server vulnerability scan.
    Uses Nikto (HTTP/HTTPS misconfig, outdated software, dangerous
    files/CGIs) plus Nmap's http-* NSE scripts for a second pass.
    Only scans the target the user explicitly supplied.
    """
    print(bold(cyan(f"\n[*] Starting Web Vulnerability Scan on {ip} ...")))
    print("─" * 50)

    ran_anything = False
    log_buffer = []

    if ensure_tool("nikto", "Nikto", install_nikto):
        print(yellow("\n[Nikto] Scanning HTTP (port 80) ..."))
        log_buffer.append("\n=== Nikto HTTP scan ===\n")
        run_cmd(f"nikto -h http://{ip}", log_buffer)
        print(yellow("\n[Nikto] Scanning HTTPS (port 443) ..."))
        log_buffer.append("\n=== Nikto HTTPS scan ===\n")
        run_cmd(f"nikto -h https://{ip} -ssl", log_buffer)
        ran_anything = True

    if ensure_tool("nmap", "Nmap", install_nmap):
        if not diagnose_nmap():
            print(yellow(
                "[i] Diagnostic test (against scanme.nmap.org) failed — that "
                "doesn't necessarily mean your target will fail too. Trying anyway ..."
            ))
        print(yellow("\n[Nmap] Running HTTP NSE script scan (http-vuln*, http-enum, http-headers) ..."))
        log_buffer.append("\n=== Nmap HTTP NSE scripts ===\n")
        route_flags = nmap_route_workaround_flags()
        run_cmd(
            f"nmap -p80,443,8080,8443 -v --stats-every 10s --host-timeout 5m "
            f"{route_flags} --script "
            f"\"http-vuln*,http-enum,http-headers,http-title,ssl-cert\" {ip}",
            log_buffer
        )
        ran_anything = True

    if not ran_anything:
        print(red("[!] No web-scanning tools available. Install Nikto and/or Nmap first."))
    else:
        finding_count = len(re.findall(r"^\+ ", "".join(log_buffer), re.MULTILINE))
        print(white("\n    ── Findings Summary ──"))
        print(f"    {yellow('Nikto findings'.ljust(18))}{white(str(finding_count))}")

        if finding_count == 0:
            web_risk = "Low"
            web_points = ["No issues were flagged on the website's web server — nothing obvious stands out."]
            web_steps = []
        elif finding_count <= 3:
            web_risk = "Medium"
            web_points = [f"The scan flagged {finding_count} small item(s) — things like missing security headers or minor misconfigurations."]
            web_steps = ["Review the full log for details — these are usually quick, low-risk fixes."]
        else:
            web_risk = "High"
            web_points = [f"The scan flagged {finding_count} items — a higher number worth reviewing properly, as it may include outdated software versions or exposed files."]
            web_steps = [
                "Check the full log (saved below) for the specific issues.",
                "Prioritize anything mentioning an outdated software version or an exposed admin/config file.",
            ]
        print_plain_summary("Website Security Scan", web_risk, web_points, web_steps)

        log_file = log_scan("web_scan", ip, log_buffer, f"{finding_count} Nikto finding(s)")
        if log_file:
            print(yellow(f"\n[Log] Full output saved → {log_file}"))

    print(green("\n[✔] Web vulnerability scan complete."))


def run_system_vuln_scan():
    """
    LOCAL system / host vulnerability & hardening audit — runs against
    the machine Z-Sploit itself is running on (not a remote target),
    using Lynis if available, with basic fallback checks otherwise.
    """
    print(bold(cyan("\n[*] Starting System Vulnerability Scan (local host) ...")))
    print("─" * 50)

    log_buffer = []

    if ensure_tool("lynis", "Lynis", install_lynis):
        print(yellow("\n[Lynis] Running system audit ..."))
        log_buffer.append("\n=== Lynis system audit ===\n")
        if ENV == "termux":
            run_cmd("lynis audit system", log_buffer)
        else:
            run_cmd("sudo lynis audit system", log_buffer)
        print(green("\n[✔] Lynis report saved (see /var/log/lynis-report.dat if available)."))
    else:
        print(yellow("[!] Lynis not available — running basic fallback checks instead."))

        print(yellow("\n[Fallback] Listening ports/services on this host ..."))
        log_buffer.append("\n=== Listening ports/services ===\n")
        if shutil.which("ss"):
            run_cmd("ss -tulnp 2>/dev/null || ss -tuln", log_buffer)
        elif shutil.which("netstat"):
            run_cmd("netstat -tulnp 2>/dev/null || netstat -tuln", log_buffer)
        else:
            print(red("    Neither 'ss' nor 'netstat' found."))

        print(yellow("\n[Fallback] OS / kernel version ..."))
        log_buffer.append("\n=== OS / kernel version ===\n")
        run_cmd("uname -a", log_buffer)

        print(yellow("\n[Fallback] Upgradable packages (patch status) ..."))
        log_buffer.append("\n=== Upgradable packages ===\n")
        if ENV == "termux":
            run_cmd("pkg list-upgradable 2>/dev/null || echo 'Run: pkg update' ", log_buffer)
        elif shutil.which("apt"):
            run_cmd("apt list --upgradable 2>/dev/null", log_buffer)
        else:
            print("    Package manager check not available on this system.")

    log_file = log_scan("system_scan", "(local host)", log_buffer)
    if log_file:
        print(yellow(f"\n[Log] Full output saved → {log_file}"))

    print(green("\n[✔] System vulnerability scan complete."))


def run_geolocation(ip: str):
    """
    IP geolocation lookup — same idea/data as the IP-Tracer project
    (github.com/Zeeshan-78/IP-Tracer), reimplemented natively here in
    Python against the same free public API (ip-api.com), so Zsploit
    doesn't need a PHP dependency or an extra cloned repo.
    """
    print(yellow("\n[Geo-IP] Looking up location via ip-api.com ..."))
    url = f"http://ip-api.com/json/{ip}"
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(red(f"    [!] Lookup failed: {e}"))
        return None
    except json.JSONDecodeError:
        print(red("    [!] Lookup failed: invalid response from API."))
        return None

    if data.get("status") != "success":
        reason = data.get("message", "unknown error")
        print(red(f"    [!] Could not geolocate {ip}: {reason}"))
        return None

    fields = [
        ("IP Address",   data.get("query")),
        ("Country",      f"{data.get('country')} ({data.get('countryCode')})"),
        ("Region",       f"{data.get('regionName')} ({data.get('region')})"),
        ("City",         data.get("city")),
        ("Zip code",     data.get("zip")),
        ("Time zone",    data.get("timezone")),
        ("ISP",          data.get("isp")),
        ("Organization", data.get("org")),
        ("ASN",          data.get("as")),
        ("Latitude",     data.get("lat")),
        ("Longitude",    data.get("lon")),
    ]
    print(white("    ── Geo-IP Information ──"))
    for label, value in fields:
        print(f"    {yellow(label.ljust(14))}{white(str(value))}")

    return data


def run_ip_trace(ip: str):
    """Geo-IP lookup + Traceroute + WHOIS + reverse-DNS lookup."""
    print(bold(cyan(f"\n[*] Starting IP Trace on {ip} ...")))
    print("─" * 50)

    log_buffer = []

    geo_data = run_geolocation(ip)
    if geo_data:
        log_buffer.append(f"\n=== Geo-IP ===\n{json.dumps(geo_data, indent=2)}\n")

    print(yellow("\n[Trace] Reverse DNS lookup ..."))
    log_buffer.append("\n=== Reverse DNS ===\n")
    run_cmd(f"nslookup {ip} 2>/dev/null || host {ip} 2>/dev/null || echo 'nslookup/host not available'", log_buffer)

    if shutil.which("whois"):
        print(yellow("\n[Trace] WHOIS information ..."))
        log_buffer.append("\n=== WHOIS ===\n")
        run_cmd(f"whois {ip}", log_buffer)
    else:
        print(yellow("[!] whois not installed — skipping WHOIS lookup."))

    tracer = "traceroute" if shutil.which("traceroute") else (
             "tracert"   if shutil.which("tracert")    else None)
    if tracer:
        print(yellow(f"\n[Trace] Running {tracer} ..."))
        log_buffer.append(f"\n=== {tracer} ===\n")
        run_cmd(f"{tracer} {ip}", log_buffer)
    else:
        print(yellow("[!] traceroute not found — skipping route trace."))

    log_file = log_scan("ip_trace", ip, log_buffer)
    if log_file:
        print(yellow(f"\n[Log] Full output saved → {log_file}"))

    print(green("\n[✔] IP trace complete."))


def launch_metasploit(ip: str):
    """Open msfconsole pre-seeded with the target host."""
    if not shutil.which("msfconsole"):
        print(red("[!] Metasploit (msfconsole) not found — skipping."))
        return
    print(bold(cyan(f"\n[*] Launching Metasploit against {ip} ...")))

    # Try to get Metasploit's database connected so 'vulns' and other
    # DB-backed features work. Best-effort: if this fails, we still
    # guarantee a real scan below regardless of DB status.
    if shutil.which("msfdb"):
        print(yellow("[*] Initializing Metasploit database (one-time setup if needed) ..."))
        os.system("msfdb init >/dev/null 2>&1")

    print(yellow("    Type 'exit' inside msfconsole to return to Z-Sploit.\n"))
    pause(1)

    # Apply the same Termux/root-awareness used for every other nmap call
    # in this script: -O needs raw sockets (unavailable on Termux even as
    # root), and without the route-workaround flags, this would hit the
    # identical 'failed to determine route' failure fixed elsewhere.
    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
    has_raw_sockets = is_root and ENV != "termux"
    route_flags = nmap_route_workaround_flags()
    nmap_flags = f"-sV -O {route_flags}".strip() if has_raw_sockets else f"-sT -sV {route_flags}".strip()

    rc_script = f"/tmp/zsploit_msf_{ip.replace('.','_')}.rc"
    with open(rc_script, "w") as f:
        f.write(f"setg RHOSTS {ip}\n")
        f.write("db_status\n")
        # IMPORTANT: plain 'nmap', not 'db_nmap'. db_nmap silently does
        # NOTHING if the database isn't connected (just prints
        # "Database not connected" and skips the actual scan) — using
        # plain nmap here means a real scan always happens regardless
        # of whether the DB setup above succeeded.
        f.write(f"nmap {nmap_flags} {ip}\n")
        f.write("vulns\n")
    os.system(f"msfconsole -r {rc_script}")
    try:
        os.remove(rc_script)
    except OSError:
        pass

# ─────────────────────────────────────────────
#  Main Flow
# ─────────────────────────────────────────────
def get_ip() -> str:
    last_target = load_config().get("last_target", "")
    prompt = (
        f"\n[?] Enter target IP address or hostname [{last_target}]: "
        if last_target else
        "\n[?] Enter target IP address or hostname: "
    )
    while True:
        ip = input(bold(prompt)).strip()
        if ip.lower() == "help":
            show_help()
            continue
        if not ip and last_target:
            # Pressing Enter reuses the last target — this is the actual
            # point of saving last_target; previously it was written to
            # config but never read back anywhere, making it pointless.
            return last_target
        if ip and validate_ip(ip):
            return ip
        print(red("    Invalid IP / hostname. Please try again."))


MENU_ITEMS = [
    ("1",  "Network Vulnerability Scan", "Nmap — multi-technique"),
    ("2",  "Web Vulnerability Scan",     "Nikto + Nmap HTTP scripts"),
    ("3",  "System Vulnerability Scan",  "Lynis — local host only"),
    ("4",  "IP Trace",                   "WHOIS + Traceroute + rDNS"),
    ("5",  "Full Remote Audit",          "1 + 2 + 4 + Metasploit"),
    ("6",  "Website Recon",              "Tech stack + Hosting profile"),
    ("7",  "Website Copy",               "Full mirror → own folder + info.txt"),
    ("8",  "Scan History",               "Review past scans & logs"),
    ("9",  "Settings",                   "Nmap timing, auto-logging, theme"),
    ("10", "Help",                       None),
    ("11", "Update",                     "git pull from GitHub"),
    ("12", "Exit",                       None),
]


def print_menu():
    print(bold(cyan("\n[?] Select an action:")))
    num_width = max(len(n) for n, _, _ in MENU_ITEMS)
    label_width = max(len(label) for _, label, _ in MENU_ITEMS) + 2
    for num, label, desc in MENU_ITEMS:
        line = f"    {white(num.rjust(num_width))}  {label}"
        if desc:
            line += " " * (label_width - len(label)) + f"({desc})"
        print(line)


def choose_action() -> str:
    print_menu()
    valid = tuple(num for num, _, _ in MENU_ITEMS)
    while True:
        choice = input(bold("\n    Your choice [1-12]: ")).strip().lower()
        if choice == "help":
            choice = "10"
        if choice == "update":
            choice = "11"
        if choice in valid:
            if choice == "10":
                show_help()
                print_menu()
                continue
            if choice == "11":
                run_update()
                print_menu()
                continue
            return choice
        print(red("    Please enter a number from 1 to 12."))


def ask_disconnect_tor() -> bool:
    ans = input(bold(yellow("\n[?] Disconnect Tor now? (yes/no): "))).strip().lower()
    return ans in ("yes", "y")


def main():
    # Step 0 — apply the saved color theme before anything else prints
    apply_theme(load_config().get("theme", "classic"))

    # --help / -h and --version command line flags
    if len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        show_help()
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-v"):
        print(f"Z-Sploit v{ZSPLOIT_VERSION}")
        sys.exit(0)

    # Step 1 — dependency checks
    bootstrap()

    # Step 2 — welcome screen (random banner each run)
    welcome()

    # Step 3 — start Tor
    start_tor()

    # Step 4 — action loop: keep returning to the menu after each action
    # instead of exiting; only Option 9 (Exit) breaks out, and only then
    # do we ask whether Tor should be stopped.
    while True:
        action = choose_action()

        if action == "12":
            print("\n" + "═" * 55)
            if ask_disconnect_tor():
                stop_tor()
            else:
                print(cyan("[*] Tor remains active."))

            print()
            print(bold(green("╔══════════════════════════════════════╗")))
            print(bold(green("║   Z-Sploit session complete. Stay    ║")))
            print(bold(green("║        Ethical. Zeeshan Ali ©        ║")))
            print(bold(green("╚══════════════════════════════════════╝")))
            print()
            sys.exit(0)

        if action == "8":
            show_scan_history()
            print("\n" + "═" * 55)
            print(cyan("[*] Action complete. Returning to main menu ..."))
            continue

        if action == "9":
            show_settings()
            print("\n" + "═" * 55)
            print(cyan("[*] Action complete. Returning to main menu ..."))
            continue

        # Step 5 — get target IP (not needed for a local-only system scan)
        ip = None
        if action != "3":
            ip = get_ip()
            cfg = load_config()
            cfg["last_target"] = ip
            save_config(cfg)

        print()
        print("═" * 55)

        if action in ("1", "5"):
            run_vulnerability_scan(ip)

        if action in ("2", "5"):
            run_web_vuln_scan(ip)

        if action == "3":
            run_system_vuln_scan()

        if action in ("4", "5"):
            run_ip_trace(ip)

        if action == "5":
            launch_metasploit(ip)

        if action == "6":
            run_website_recon(ip)

        if action == "7":
            run_website_copy(ip)

        print("\n" + "═" * 55)
        print(cyan("[*] Action complete. Returning to main menu ..."))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(red("\n\n[!] Interrupted by user. Exiting cleanly.\n"))
        sys.exit(0)
