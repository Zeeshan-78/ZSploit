# Z-Sploit

**A guided, terminal-based wrapper around Tor, Nmap, Nikto, Lynis, WhatWeb, Wget, and Metasploit for streamlined, non-technical-friendly security assessment workflows.**
<p align="center">
<img src="1.png"/>
</p>
Z-Sploit chains together well-known, legitimate security tools into a single guided session — no manual chaining required. It checks for and installs missing dependencies, anonymises traffic through Tor, runs network/web/system vulnerability scans, fingerprints a website's hosting and tech stack, mirrors a site for archiving, and (optionally) hands the target straight to Metasploit — all from one menu, with results explained in plain language as well as raw technical output.

---

## ⚠️ Legal & Ethical Notice

Z-Sploit is intended **only** for use against systems you own or have explicit, written authorization to test. Unauthorized scanning, probing, or exploitation of systems you do not control is illegal in most jurisdictions and may carry serious civil and criminal penalties.

The author and contributors take no responsibility for misuse of this tool. By using Z-Sploit you agree to use it ethically and legally.

---

## Features

### Core scanning
- **Network Vulnerability Scan** — multi-technique Nmap scan: a combined top-1000-port + service/version (`-sV`) + default-script (`-sC`) pass, a full port-range scan (`-p-`), a UDP top-ports scan, and OS detection (`-O`, when privileges allow). Automatically falls back to TCP Connect (`-sT`) instead of SYN scan on Termux/Android, where raw sockets are kernel-restricted even as root.
- **Web Vulnerability Scan** — Nikto (HTTP + HTTPS) plus Nmap's `http-vuln*`, `http-enum`, `http-headers`, `http-title`, and `ssl-cert` NSE scripts.
- **System Vulnerability Scan** — Lynis audit of the **local** host Z-Sploit runs on (never a remote target), with manual fallback checks (listening ports, kernel version, upgradable packages) if Lynis isn't installed.
- **IP Trace** — Geo-IP lookup (via ip-api.com: country, city, ISP, ASN, coordinates), reverse DNS, WHOIS, and traceroute, all in one step.
- **Full Remote Audit** — runs the network scan, web scan, and IP trace together, then opens `msfconsole` pre-seeded with the target as `RHOSTS`.

### Website intelligence
- **Website Recon** — resolves the hostname to its public IP, shows hosting/ASN/datacenter info, and fingerprints the tech stack from HTTP headers *and* page content: detects backend language (PHP, ASP.NET, Java, Ruby on Rails, Python/Django, Node.js/Express, Go), CMS/platform (WordPress, Drupal, Joomla, Magento, Shopify, Wix, Squarespace, Laravel), and frontend framework (React, Next.js, Vue, Nuxt, Angular, jQuery, Bootstrap, Tailwind). Falls back to probing known platform-specific paths (e.g. `/wp-login.php`, `/cdn-cgi/`) when a CDN strips identifying headers. Finishes with a consolidated **Website Architecture Summary**.
- **Website Copy** — full site mirror via Wget into its own timestamped folder under `~/zsploit_copies/`, with a `basic-info.txt` (target, resolved IP, hosting provider, file count, total size). Respects `robots.txt` by default; copies only static/browser-visible content, no databases or server-side code.

### Diagnostics & reliability
- **Nmap pre-flight diagnostic** — before any Nmap-based scan, verifies the binary actually runs (not just that it's installed) and tests real scan capability against a known-good host, giving a clear ✔/✘ diagnosis instead of a silent or confusing failure. Result is cached per session and never blocks the real scan from being attempted.
- **Termux routing workaround** — automatically applies the known fix (`-Pn` plus a sanity-checked `-S <source-ip>`) for Nmap's `"failed to determine route"` error on Android/Termux, where the kernel blocks the routing-table lookup Nmap normally relies on — even for simple TCP Connect scans.
- **Live scan progress** — Nmap phases run with `-v --stats-every 10s --host-timeout 5m` so long scans show visible progress instead of going silent for minutes on a slow connection, and a genuinely unreachable target times out instead of hanging forever.
- **"Why nothing shows" explanation** — if a scan finds zero open ports, Z-Sploit parses Nmap's own `"Not shown: N <state> ports"` output and explains whether that means nothing is open or a CDN/WAF/firewall is silently filtering scan traffic (very common on CDN-fronted sites), instead of leaving a blank, unexplained result.

### Usability
- **Plain-language summaries** — after Network, Web, and Website Recon scans, an "In Plain English" box explains the findings in non-technical terms (what was found, an overall Low/Medium/High risk level, and suggested next steps) — no security background needed. Toggleable in Settings.
- **Professional display mode** — a clean, boxed default header instead of ASCII art, with the original rotating ASCII-art/skull banners still available as a "classic" display mode.
- **Color themes** — classic, matrix (green-on-green), crimson (red-dominant), and mono (no color), switchable instantly from Settings.
- **Menu loops, doesn't exit** — after any scan completes, Z-Sploit returns to the main menu instead of quitting, so you can run several scans in one session. Only explicitly choosing **Exit** ends the session (and asks whether to stop Tor).
- **Scan History** — lists your last 25 scans (date, action, target, summary); every scan's full raw output is also saved as its own log file.
- **Settings** — change the Nmap timing template (T1–T5), toggle auto-saving of scan logs, clear the saved last-target, switch the color theme or display mode, or toggle plain-language summaries — all stored in `~/.zsploit_config.json`.
- **Per-action dependency checks** — missing tools (Nmap, Nikto, Lynis, WhatWeb, Wget) are checked and offered for installation right before the scan that needs them, not just at startup.

### General
- **Automatic dependency checks** — detects and installs Tor, Nmap, Nikto, Lynis, WhatWeb, Wget, and Metasploit if missing (via `apt` on Kali Linux or `pkg` on Termux).
- **Tor integration** — starts Tor at launch (verifying the SOCKS port actually opened, not just assuming success), reuses an already-running instance, and offers to disconnect it when you're done.
- **Built-in help system** — `help` command from any prompt, or `--help` / `-h` from the command line.
- **Self-updater** — pulls the latest version straight from this GitHub repo.
- **Cross-platform** — works on both Kali Linux and Termux (Android).

---

## Requirements

- Python 3.6+
- One of:
  - **Kali Linux** (or another Debian-based distro with `apt`)
  - **Termux** on Android
- `git` (for the self-update feature)
- Root/sudo access on Linux for installing packages and managing the Tor service

Z-Sploit will attempt to install missing tools automatically, but you can also install them manually beforehand:

```bash
# Kali Linux / Debian-based
sudo apt-get install -y tor nmap nikto lynis whatweb wget metasploit-framework whois traceroute git

# Termux
pkg install -y tor nmap nikto lynis whatweb wget unstable-repo metasploit git
```

---

## Installation

```bash
git clone https://github.com/Zeeshan-78/Z-Sploit.git
cd Z-Sploit
chmod +x zsploit.py
```

---

## Usage

Run the script:

```bash
python3 zsploit.py
```

Show the help guide without launching the full workflow:

```bash
python3 zsploit.py --help
# or
python3 zsploit.py -h
```

### Walkthrough

1. **Dependency check** — Z-Sploit verifies Tor, Nmap, Nikto, Lynis, WhatWeb, Wget, and Metasploit are installed, installing anything missing.
2. **Welcome screen** — a clean professional header by default (or a random ASCII banner in "classic" display mode), along with an update notice if a newer version is available on GitHub.
3. **Tor starts automatically** to anonymise your traffic.
4. **Choose an action** from the menu — a target IP/hostname is requested only for options that need one:

   | Option | Action                     | Description                                                                 |
   |--------|-----------------------------|-------------------------------------------------------------------------------|
   | 1      | Network Vulnerability Scan  | Multi-technique Nmap scan (ports, services, scripts, OS detection).           |
   | 2      | Web Vulnerability Scan      | Nikto + Nmap HTTP NSE scripts.                                                |
   | 3      | System Vulnerability Scan   | Lynis audit of the local host only — no target needed.                        |
   | 4      | IP Trace                    | Geo-IP + reverse DNS + WHOIS + traceroute.                                     |
   | 5      | Full Remote Audit           | Options 1 + 2 + 4, then opens `msfconsole` against the target.                |
   | 6      | Website Recon               | Tech-stack fingerprint + hosting/architecture summary.                        |
   | 7      | Website Copy                | Full site mirror into its own folder + `basic-info.txt`.                      |
   | 8      | Scan History                 | Review past scans and their saved logs.                                       |
   | 9      | Settings                     | Nmap timing, auto-logging, color theme, display mode, plain-language toggle.  |
   | 10     | Help                         | Shows the in-app help guide.                                                   |
   | 11     | Update                       | Pulls the latest Z-Sploit release from GitHub.                                |
   | 12     | Exit                         | Quits Z-Sploit (asks whether to stop Tor first).                              |

5. **Z-Sploit returns to the menu after each action** — run as many scans as you like in one session; it only exits when you choose **Exit**.
6. **Tor disconnect prompt** — on Exit, choose whether to stop Tor.

---

## Updating

If you cloned Z-Sploit with `git`, you can update in two ways:

- From inside the app: choose **11. Update** from the main menu.
- From the command line:

  ```bash
  cd Z-Sploit
  git pull --ff-only origin
  ```

If your local copy isn't a git checkout, the in-app updater will offer to clone a fresh copy into a `Z-Sploit-latest` folder alongside the script.

---

## Configuration & Logs

- **`~/.zsploit_config.json`** — your saved settings (Nmap timing, auto-log toggle, color theme, display mode, plain-language toggle, last target).
- **`~/zsploit_logs/`** — full raw output of every scan, one file per run, plus `history.json` (the index behind the Scan History menu).
- **`~/zsploit_copies/`** — mirrored websites from the Website Copy feature, one timestamped folder per copy.

---

## Project Structure

```
Z-Sploit/
├── zsploit.py     # Main application
└── README.md      # This file
```

---

## Contributing

Issues and pull requests are welcome. Please keep contributions focused on usability, reliability, and ethical-use safeguards (e.g., clearer authorization warnings, better input validation).

---

## Author

**Zeeshan Ali**

---

## License

Specify your preferred license here (e.g., MIT, GPLv3). If you haven't chosen one yet, [choosealicense.com](https://choosealicense.com/) can help you pick.
