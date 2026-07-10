#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Strix Archer
------------
An OSINT automation tool for AUTHORIZED lab targets — built primarily for
CTF challenges and their fictional characters.

It does two things:
  • INFRASTRUCTURE OSINT  — DNS, WHOIS, crt.sh certificate-transparency
    subdomains, reverse-IP, HTTP header / technology fingerprint.
  • IDENTITY OSINT        — username presence across platforms, email
    format + Gravatar checks, and a per-character "dossier" that merges
    every clue into one report.

Design principles (shared with the author's Vantage recon tool):
  • Wraps installed open-source tools when present (sherlock, spiderfoot,
    theHarvester, holehe, maigret), and FALLS BACK to a built-in,
    dependency-free implementation when they are not — so it runs on the
    THM AttackBox and on a bare Python install alike.
  • Low-impact by default: identity checks are rate-limited so this stays
    a learning tool, not a mass-profiling machine.
  • Everything is written to a tidy .txt + .html report you can scan for
    room answers.

LEGAL / ETHICAL SCOPE
  Strix Archer is for targets you own or are explicitly authorized to
  test — CTF challenges and their fictional personas are the intended
  use. A one-time consent gate enforces acknowledgement of this. Do NOT
  use it to profile real people without their consent.

Requires: Python 3.10+  (standard library only for the built-in engine;
optional tools are used automatically if they are on PATH).
Run:  python3 strix_archer.py --help
"""

import argparse
import concurrent.futures as futures
import html
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

VERSION = "1.0"

# ----------------------------------------------------------------------
# Branding / terminal UI  (same family as Vantage)
# ----------------------------------------------------------------------
BANNER = r"""
   ██████╗████████╗██████╗ ██╗██╗  ██╗
   ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
   ╚█████╗    ██║   ██████╔╝██║ ╚███╔╝
    ╚═══██╗   ██║   ██╔══██╗██║ ██╔██╗
   ██████╔╝   ██║   ██║  ██║██║██╔╝ ██╗
   ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
      ┏━┓┏━┓┏━╸╻ ╻┏━╸┏━┓
      ┣━┫┣┳┛┃  ┣━┫┣╸ ┣┳┛
      ╹ ╹╹┗╸┗━╸╹ ╹┗━╸╹┗╸
"""
AIM = "  »»————————►  ◎   lock · aim · gather"
TAGLINE = "  OSINT for authorized lab targets  ·  v%s" % VERSION


class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
    GRAY = "\033[90m"; WHITE = "\033[97m"


USE_COLOR = True
DEBUG = False


def _c(text, color):
    return f"{color}{text}{C.RESET}" if USE_COLOR else text


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def print_banner():
    print(_c(BANNER, C.MAGENTA + C.BOLD))
    # arrow flies to the target ◎ — colored in parts for a bit of flair
    print(_c("  »»————————►", C.YELLOW + C.BOLD) + _c("  ◎", C.GREEN + C.BOLD)
          + _c("   lock · aim · gather", C.GRAY))
    print(_c(TAGLINE, C.CYAN))
    print(_c("  authorized targets only — CTF challenges & fictional personas",
             C.GRAY) + "\n")


def log_phase(msg):
    line = "─" * 60
    print("\n" + _c(line, C.MAGENTA))
    print(_c("  ▶ " + msg, C.MAGENTA + C.BOLD))
    print(_c(line, C.MAGENTA))


def log_step(msg):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("→ ", C.BLUE) + msg)


def log_result(label, detail):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("✔ ", C.GREEN)
          + _c(label, C.BOLD) + _c(" · ", C.GRAY) + _c(str(detail), C.WHITE))


def log_hit(label, detail):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("★ ", C.YELLOW + C.BOLD)
          + _c(label, C.BOLD) + _c(" · ", C.GRAY) + _c(str(detail), C.WHITE))


def log_warn(msg):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("! ", C.YELLOW) + _c(msg, C.YELLOW))


def log_info(msg):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("· ", C.GRAY) + msg)


def log_debug(msg):
    if DEBUG:
        print(_c(f"  [{_ts()}] ", C.GRAY) + _c("dbg ", C.GRAY) + _c(msg, C.GRAY))


class StrixParser(argparse.ArgumentParser):
    def format_help(self):
        return BANNER + AIM + "\n" + TAGLINE + "\n\n" + super().format_help()


# ----------------------------------------------------------------------
# Config / consent
# ----------------------------------------------------------------------
def config_dir() -> str:
    base = (os.environ.get("APPDATA") or
            os.path.join(os.path.expanduser("~"), ".config"))
    d = os.path.join(base, "StrixArcher")
    os.makedirs(d, exist_ok=True)
    return d


CONSENT_FILE = os.path.join(config_dir(), "consent.json")

CONSENT_TEXT = """
  ┌────────────────────────────────────────────────────────────────┐
  │  STRIX ARCHER — AUTHORIZED USE ONLY                             │
  │                                                                │
  │  This tool performs OSINT collection. You confirm that you     │
  │  will use it ONLY against:                                     │
  │     • CTF challenges and their fictional characters, or       │
  │     • targets you own or have WRITTEN authorization to test.   │
  │                                                                │
  │  Using OSINT tooling to profile real individuals without       │
  │  their consent can be harassment or stalking, and may be       │
  │  illegal in your jurisdiction. You accept full responsibility  │
  │  for how you use this tool.                                    │
  └────────────────────────────────────────────────────────────────┘
"""


def check_consent(assume_yes: bool) -> bool:
    if os.path.exists(CONSENT_FILE):
        try:
            with open(CONSENT_FILE, encoding="utf-8") as f:
                if json.load(f).get("accepted") is True:
                    return True
        except Exception:
            pass
    print(_c(CONSENT_TEXT, C.YELLOW))
    if assume_yes:
        log_info("consent auto-accepted via --i-am-authorized flag")
        ok = True
    else:
        try:
            ans = input(_c("  Type 'I AGREE' to continue: ", C.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        ok = ans.upper() in ("I AGREE", "AGREE", "YES")
    if ok:
        try:
            with open(CONSENT_FILE, "w", encoding="utf-8") as f:
                json.dump({"accepted": True,
                           "at": datetime.now().isoformat()}, f)
        except Exception:
            pass
    return ok


# ----------------------------------------------------------------------
# HTTP helper (stdlib only)
# ----------------------------------------------------------------------
UA = "Mozilla/5.0 (compatible; StrixArcher/%s; +authorized-lab-use)" % VERSION


def http_get(url, timeout=10, method="GET", headers=None):
    """Return (status, headers_dict, body_text). status 0 on transport error."""
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, method=method, headers=h)
    ctx = ssl.create_default_context()
    old_to = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)  # guards DNS/connect stalls too
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(2_000_000)
            enc = r.headers.get_content_charset() or "utf-8"
            return (r.status, dict(r.headers),
                    body.decode(enc, errors="replace"))
    except urllib.error.HTTPError as e:
        try:
            body = e.read(500_000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return (e.code, dict(e.headers or {}), body)
    except Exception as e:
        log_debug(f"http_get {url}: {e}")
        return (0, {}, "")
    finally:
        socket.setdefaulttimeout(old_to)


def http_status(url, timeout=8):
    """Lightweight status probe (HEAD, falling back to GET)."""
    st, _, _ = http_get(url, timeout=timeout, method="HEAD")
    if st == 0:
        st, _, _ = http_get(url, timeout=timeout, method="GET")
    return st


# ----------------------------------------------------------------------
# External-tool detection (wrap if available, else built-in fallback)
# ----------------------------------------------------------------------
OPTIONAL_TOOLS = ["sherlock", "spiderfoot", "theHarvester", "holehe",
                  "maigret", "whois", "dig"]

# Safe setup recipes: how to install each optional tool. Strix does NOT run
# these silently — `--setup` shows them, and only runs them (via pipx into an
# isolated environment, never polluting system Python) after you confirm.
SETUP_RECIPES = {
    "sherlock":     ["pipx", "install", "sherlock-project"],
    "maigret":      ["pipx", "install", "maigret"],
    "holehe":       ["pipx", "install", "holehe"],
    "theHarvester": ["pipx", "install", "theHarvester"],
    "spiderfoot":   ["pipx", "install", "spiderfoot"],
}
# whois / dig come from OS packages, not pip — we only advise, never install.
SETUP_ADVISORY = {
    "whois": "install via your OS package manager, e.g. "
             "'sudo apt install whois'  (Windows: comes with Sysinternals "
             "'whois.exe' or use the built-in stdlib fallback)",
    "dig":   "install via your OS package manager, e.g. "
             "'sudo apt install dnsutils'  (optional — stdlib DNS is used "
             "otherwise)",
}


def detect_tools() -> dict:
    found = {}
    for t in OPTIONAL_TOOLS:
        path = shutil.which(t)
        # theHarvester is sometimes 'theHarvester.py' or lowercase
        if not path and t == "theHarvester":
            path = shutil.which("theharvester")
        found[t] = path
    return found


def run_tool(argv, timeout=300):
    """Run an external tool safely (fixed argv, no shell). (rc, out, err)."""
    log_debug("run: " + " ".join(argv))
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def _ensure_pipx(assume_yes: bool) -> bool:
    """Make sure pipx exists. If not, offer to install it the safe way:
    `python3 -m pip install --user pipx` (user-scope, never system-wide),
    then `ensurepath`. Returns True if pipx is usable afterward."""
    if shutil.which("pipx"):
        return True
    log_warn("pipx not found — it keeps each tool in its own isolated venv, "
             "which is the safe way to install these.")
    cmd1 = [sys.executable, "-m", "pip", "install", "--user", "pipx"]
    cmd2 = [sys.executable, "-m", "pipx", "ensurepath"]
    log_info("proposed (user-scope, does NOT touch system Python):")
    print("    " + _c(" ".join(cmd1), C.CYAN))
    print("    " + _c(" ".join(cmd2), C.CYAN))
    if assume_yes:
        proceed = True
    else:
        try:
            proceed = input(_c("  Install pipx now? [y/N]: ",
                               C.BOLD)).strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            print(); proceed = False
    if not proceed:
        log_info("skipped — install pipx manually, then re-run --setup")
        return False
    log_step("installing pipx (user scope)")
    rc, so, se = run_tool(cmd1, timeout=300)
    if rc != 0:
        log_warn(f"pipx install failed: {first_line(se or so)}")
        return False
    run_tool(cmd2, timeout=60)
    # pipx may not be on PATH in THIS session yet; fall back to `python -m pipx`
    if shutil.which("pipx"):
        log_result("pipx", "installed")
        return True
    log_info("pipx installed but not on PATH yet — using 'python -m pipx' "
             "for this run (restart your terminal later to get 'pipx')")
    return True


def _pipx_argv(recipe: list[str]) -> list[str]:
    """Return a runnable argv for a pipx recipe, using the module form if the
    pipx launcher isn't on PATH yet in this session."""
    if shutil.which("pipx"):
        return recipe
    return [sys.executable, "-m"] + recipe  # ['python','-m','pipx','install',...]


def run_setup(assume_yes: bool):
    """Safe, transparent, robust installer for optional tools.

    Every tool lands in its OWN isolated venv via pipx — the system Python is
    never touched. Nothing installs without showing the exact command first;
    each install is verified, and a final re-detect confirms the result.
    """
    log_phase("Setup — optional OSINT tools")
    tools = detect_tools()

    present = [t for t, p in tools.items() if p]
    if present:
        log_result("already installed", ", ".join(present))

    to_install = [t for t in SETUP_RECIPES if not tools.get(t)]
    advisories = [t for t in SETUP_ADVISORY if not tools.get(t)]

    if advisories:
        print()
        log_info("These come from your OS package manager (not installed here):")
        for t in advisories:
            print(f"    {t}: {SETUP_ADVISORY[t]}")

    if not to_install:
        log_result("setup", "all pip-based tools are already installed")
        return

    print()
    log_info("Missing pip-based tools (each installs into its own isolated "
             "venv via pipx):")
    for t in to_install:
        print("    " + _c(" ".join(SETUP_RECIPES[t]), C.CYAN))

    if not _ensure_pipx(assume_yes):
        log_info("copy the commands above to install manually once pipx is ready")
        return

    print()
    if assume_yes:
        proceed = True
        log_info("--i-am-authorized given: running the installs, one by one")
    else:
        try:
            proceed = input(_c("  Run these installs now? [y/N]: ",
                               C.BOLD)).strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            print(); proceed = False
    if not proceed:
        log_info("skipped — copy the commands above to install manually")
        return

    installed, failed = [], []
    for t in to_install:
        log_step(f"installing {t}")
        rc, so, se = run_tool(_pipx_argv(SETUP_RECIPES[t]), timeout=900)
        if rc == 0:
            log_result(t, "installed")
            installed.append(t)
        else:
            log_warn(f"{t} failed (rc={rc}): {first_line(se or so)}")
            failed.append(t)

    # Final verification pass — re-detect from scratch.
    print()
    fresh = detect_tools()
    now_present = [t for t in to_install if fresh.get(t)]
    log_phase("Setup summary")
    if now_present:
        log_result("now available", ", ".join(now_present))
    if failed:
        log_warn("still missing: " + ", ".join(failed)
                 + "  (try the printed command manually to see the full error)")
    log_info("tip: if a tool isn't found on the next run, restart your "
             "terminal so PATH picks up pipx's bin directory")


# ======================================================================
# INFRASTRUCTURE OSINT
# ======================================================================
def normalize_domain(target: str) -> str:
    t = target.strip()
    if "://" in t:
        t = urlparse(t).hostname or t
    return t.strip("/").split("/")[0].lower()


# ---- DNS via DNS-over-HTTPS (Cloudflare + Google), stdlib socket fallback --
_DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]


def _doh_query(domain: str, rtype: str) -> list[str]:
    """Query a record type over DoH (JSON). Tries Cloudflare then Google."""
    for base in _DOH_ENDPOINTS:
        url = f"{base}?name={urllib.parse.quote(domain)}&type={rtype}"
        st, _, body = http_get(url, timeout=12,
                               headers={"Accept": "application/dns-json"})
        if st != 200 or not body:
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            continue
        answers = data.get("Answer", [])
        vals = []
        for a in answers:
            v = str(a.get("data", "")).strip().strip('"')
            if v:
                vals.append(v)
        if vals or data.get("Status") == 0:
            return vals
    return []


def dns_lookup(domain: str) -> dict:
    """Resolve common record types over DoH, with a stdlib socket fallback."""
    out = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        vals = _doh_query(domain, rtype)
        if vals:
            # MX answers look like "10 mail.example.com."; tidy trailing dots
            out[rtype] = [v.rstrip(".") for v in vals]
    # socket fallback if DoH gave us nothing at all (e.g. offline resolver)
    if not out.get("A"):
        try:
            infos = socket.getaddrinfo(domain, None)
            v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
            v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
            if v4:
                out["A"] = v4
            if v6:
                out.setdefault("AAAA", v6)
        except OSError:
            pass
    return out


# ---- WHOIS / RDAP ----------------------------------------------------
def rdap_lookup(domain: str) -> dict:
    """RDAP: the modern, structured, key-less successor to WHOIS (JSON).

    Uses rdap.org, which redirects to the authoritative registry RDAP server.
    Returns tidy fields; falls back to {} so whois can take over.
    """
    st, _, body = http_get(f"https://rdap.org/domain/{urllib.parse.quote(domain)}",
                           timeout=15, headers={"Accept": "application/rdap+json"})
    if st != 200 or not body:
        return {}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {}
    out = {}
    # events: registration / expiration / last changed
    for ev in data.get("events", []):
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")
        if action and date:
            out[action] = date[:19].replace("T", " ")
    # status flags
    if data.get("status"):
        out["status"] = ", ".join(data["status"])
    # nameservers
    ns = [n.get("ldhName", "") for n in data.get("nameservers", [])]
    if any(ns):
        out["nameservers"] = ", ".join(sorted(x.lower() for x in ns if x))
    # registrar (from entities with role 'registrar')
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in ent.get("vcardArray", [[], []])[1]:
                if item and item[0] == "fn":
                    out["registrar"] = item[3]
                    break
    return out


def whois_lookup(domain: str) -> str:
    # Prefer RDAP (structured, key-less, standard); format it like whois.
    rd = rdap_lookup(domain)
    if rd:
        lines = [f"    {k}: {v}" for k, v in rd.items()]
        return "\n".join(lines)
    # Fall back to the whois CLI, then a stdlib socket whois client.
    w = shutil.which("whois")
    if w:
        rc, so, _ = run_tool([w, domain], timeout=25)
        if rc == 0 and so.strip():
            return _trim_whois(so)
    try:
        return _trim_whois(_whois_socket(domain))
    except Exception as e:
        return f"(whois/RDAP unavailable: {e})"


def _whois_socket(domain: str) -> str:
    def ask(server, query):
        s = socket.create_connection((server, 43), timeout=15)
        s.settimeout(15)
        try:
            s.sendall((query + "\r\n").encode())
            data = b""
            # Cap the response so a hostile/broken whois server cannot exhaust
            # memory by streaming without end.
            while len(data) < 262144:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        return data.decode("utf-8", errors="replace")

    tld = domain.rsplit(".", 1)[-1]
    ref = ask("whois.iana.org", tld)
    m = re.search(r"whois:\s*(\S+)", ref)
    server = m.group(1) if m else "whois.verisign-grs.com"
    return ask(server, domain)


_WHOIS_KEEP = ("registrar", "creation", "created", "updated", "expir",
               "name server", "nameserver", "status", "registrant",
               "org", "country")


def _trim_whois(text: str) -> str:
    lines = []
    for l in text.splitlines():
        low = l.lower().strip()
        if any(k in low for k in _WHOIS_KEEP) and ":" in l:
            lines.append("    " + l.strip())
        if len(lines) >= 25:
            break
    return "\n".join(dict.fromkeys(lines)) or "(no salient whois fields)"


# ---- crt.sh certificate-transparency subdomains ----------------------
def crtsh_subdomains(domain: str) -> list[str]:
    # URL-encode the domain (it is already validated, but encoding keeps a stray
    # character from altering the query string).
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain, safe="") + "&output=json"
    st, _, body = http_get(url, timeout=25)
    subs = set()
    if st == 200 and body:
        try:
            for row in json.loads(body):
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain) and "@" not in name:
                        subs.add(name)
        except json.JSONDecodeError:
            pass
    return sorted(subs)


# ---- reverse IP / PTR ------------------------------------------------
def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


# ---- HTTP header + tech fingerprint ----------------------------------
_TECH_SIGNS = [
    ("Server header", re.compile(r"", re.I)),  # handled specially below
]

_TECH_BODY = {
    "WordPress": re.compile(r"/wp-content/|wp-json", re.I),
    "Drupal": re.compile(r"Drupal|/sites/default/", re.I),
    "Joomla": re.compile(r"/media/jui/|Joomla", re.I),
    "React": re.compile(r"data-reactroot|__NEXT_DATA__", re.I),
    "Angular": re.compile(r"ng-version|angular", re.I),
    "Vue": re.compile(r"data-v-[0-9a-f]{8}|__vue__", re.I),
    "Laravel": re.compile(r"laravel_session|XSRF-TOKEN", re.I),
    "jQuery": re.compile(r"jquery(\.min)?\.js", re.I),
    "Bootstrap": re.compile(r"bootstrap(\.min)?\.(css|js)", re.I),
    "Cloudflare": re.compile(r"cloudflare", re.I),
}


def http_fingerprint(domain: str) -> dict:
    info = {"url": "", "status": 0, "server": "", "powered_by": "",
            "title": "", "tech": [], "security_headers": {}, "cookies": []}
    for scheme in ("https://", "http://"):
        url = scheme + domain
        st, hdrs, body = http_get(url, timeout=12)
        if st == 0:
            continue
        info["url"], info["status"] = url, st
        low = {k.lower(): v for k, v in hdrs.items()}
        info["server"] = low.get("server", "")
        info["powered_by"] = low.get("x-powered-by", "")
        m = re.search(r"<title[^>]*>(.*?)</title>", body,
                      re.I | re.S)
        if m:
            info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        tech = []
        for name, rx in _TECH_BODY.items():
            if rx.search(body) or rx.search(info["server"]) \
                    or rx.search(info["powered_by"]):
                tech.append(name)
        if info["powered_by"]:
            tech.append(info["powered_by"])
        info["tech"] = sorted(set(tech))
        for shdr in ("content-security-policy", "strict-transport-security",
                     "x-frame-options", "x-content-type-options",
                     "referrer-policy", "permissions-policy"):
            info["security_headers"][shdr] = low.get(shdr, "")
        for k, v in hdrs.items():
            if k.lower() == "set-cookie":
                info["cookies"].append(v.split(";")[0])
        break
    return info


def missing_security_headers(fp: dict) -> list[str]:
    return [h for h, v in fp.get("security_headers", {}).items() if not v]


def run_infrastructure(domain: str, use_spiderfoot: bool,
                       tools: dict) -> dict:
    log_phase(f"Infrastructure OSINT — {domain}")
    data = {"domain": domain}

    log_step("DNS records (DNS-over-HTTPS)")
    data["dns"] = dns_lookup(domain)
    ip_list = data["dns"].get("A", [])
    log_result("dns", ", ".join(f"{k}:{len(v)}" for k, v in data["dns"].items())
               or "no records")

    log_step("WHOIS / RDAP")
    data["whois"] = whois_lookup(domain)
    log_result("whois", "collected" if "unavailable" not in data["whois"]
               else "unavailable")

    log_step("crt.sh certificate-transparency subdomains")
    data["subdomains"] = crtsh_subdomains(domain)
    log_result("subdomains", f"{len(data['subdomains'])} found")
    for s in data["subdomains"][:12]:
        log_info("  " + s)
    if len(data["subdomains"]) > 12:
        log_info(f"  … and {len(data['subdomains']) - 12} more")

    if ip_list:
        log_step("reverse DNS (PTR)")
        data["ptr"] = {ip: reverse_dns(ip) for ip in ip_list}
        for ip, ptr in data["ptr"].items():
            if ptr:
                log_result("ptr", f"{ip} → {ptr}")

    log_step("HTTP header / technology fingerprint")
    data["http"] = http_fingerprint(domain)
    fp = data["http"]
    if fp["status"]:
        log_result("http", f"{fp['status']}  {fp['server'] or ''} "
                           f"{'· '+fp['title'] if fp['title'] else ''}")
        if fp["tech"]:
            log_result("tech", ", ".join(fp["tech"]))
        miss = missing_security_headers(fp)
        if miss:
            log_warn("missing security headers: " + ", ".join(miss))
    else:
        log_warn("host did not respond over HTTP/HTTPS")

    # Optional: SpiderFoot passive footprint, if user asked and it exists
    if use_spiderfoot and tools.get("spiderfoot"):
        log_step("spiderfoot (passive footprint)")
        data["spiderfoot"] = run_spiderfoot(domain, tools["spiderfoot"])
        log_result("spiderfoot", first_line(data["spiderfoot"]))

    # theHarvester (installed) — emails + hosts from public sources
    if tools.get("theHarvester"):
        log_step("theHarvester (installed) — emails / hosts")
        data["theharvester"] = run_theharvester(domain, tools["theHarvester"])
        th = data["theharvester"]
        log_result("theHarvester",
                   f"{len(th['emails'])} email(s), {len(th['hosts'])} host(s)")
        for e in th["emails"][:8]:
            log_hit("email", e)

    return data


def first_line(text, n=80):
    for l in str(text).splitlines():
        if l.strip():
            return l.strip()[:n]
    return "-"


def run_spiderfoot(target: str, binpath: str) -> str:
    # Passive-only, single target, CSV to stdout. Version flags vary; keep simple.
    rc, so, se = run_tool([binpath, "-s", target, "-q", "-o", "csv"],
                          timeout=240)
    if rc == 0 and so.strip():
        return so.strip()[:4000]
    return f"(spiderfoot returned rc={rc}: {first_line(se)})"


# ---- theHarvester wrapper (emails / hosts from public sources) -----------
def run_theharvester(domain: str, binpath: str) -> dict:
    """Wrap theHarvester with passive sources; parse emails + hosts."""
    rc, so, se = run_tool(
        [binpath, "-d", domain, "-b", "crtsh,duckduckgo,bing,otx",
         "-l", "200"], timeout=300)
    emails = sorted(set(re.findall(
        r"[a-zA-Z0-9._%+-]+@" + re.escape(domain), so)))
    hosts = sorted(set(re.findall(
        r"\b[a-zA-Z0-9._-]+\." + re.escape(domain) + r"\b", so)))
    return {"emails": emails, "hosts": hosts,
            "ok": rc == 0, "raw_tail": first_line(se) if rc else ""}


# ======================================================================
# BREACH / LEAK CHECK  (privacy-preserving only)
# ======================================================================
def pwned_password_count(password: str) -> int:
    """HIBP Pwned Passwords via k-anonymity.

    Only the first 5 chars of the password's SHA-1 hash are ever sent; the
    rest is matched locally. The password itself NEVER leaves this machine.
    Returns how many times the password appears in known breaches (0 = not
    found). This is the only breach service Strix uses, because it is free,
    key-less, and privacy-preserving by design.
    """
    import hashlib
    # SHA-1 is mandated by the HIBP range API; this is an interop hash, not a
    # security control (usedforsecurity=False documents that and clears B324).
    sha1 = hashlib.sha1(password.encode("utf-8"),
                        usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    st, _, body = http_get(f"https://api.pwnedpasswords.com/range/{prefix}",
                           timeout=15,
                           headers={"Add-Padding": "true"})
    if st != 200 or not body:
        return -1  # service unavailable
    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            try:
                return int(parts[1])
            except ValueError:
                return -1
    return 0





# ======================================================================
# IDENTITY OSINT
# ======================================================================
# Built-in username checker. Each site: (name, url_template, absent_marker).
# "absent" logic: a 404 status = not found; if status 200 we additionally
# check the body does not contain an explicit not-found marker.
USERNAME_SITES = [
    ("GitHub",      "https://github.com/{u}",                 None),
    ("GitLab",      "https://gitlab.com/{u}",                 None),
    ("Reddit",      "https://www.reddit.com/user/{u}/about.json", None),
    ("Twitter/X",   "https://twitter.com/{u}",                None),
    ("Instagram",   "https://www.instagram.com/{u}/",         None),
    ("TikTok",      "https://www.tiktok.com/@{u}",            None),
    ("Twitch",      "https://www.twitch.tv/{u}",              None),
    ("Pinterest",   "https://www.pinterest.com/{u}/",         None),
    ("Steam",       "https://steamcommunity.com/id/{u}",      "The specified profile could not be found"),
    ("Medium",      "https://medium.com/@{u}",                None),
    ("DevTo",       "https://dev.to/{u}",                     None),
    ("HackerNews",  "https://news.ycombinator.com/user?id={u}", "No such user"),
    ("Keybase",     "https://keybase.io/{u}",                 None),
    ("Replit",      "https://replit.com/@{u}",                None),
    ("About.me",    "https://about.me/{u}",                   None),
    ("Gravatar",    "https://en.gravatar.com/{u}",            None),
    ("Telegram",    "https://t.me/{u}",                       None),
    ("YouTube",     "https://www.youtube.com/@{u}",           None),
    ("SoundCloud",  "https://soundcloud.com/{u}",             None),
    ("Patreon",     "https://www.patreon.com/{u}",            None),
]


_RATE_LOCK = threading.Lock()
_RATE_STATE = {"next": 0.0}


def _rate_gate(min_interval: float) -> None:
    """Globally space outbound requests at least `min_interval` seconds apart.

    `check_username_site` runs in a small thread pool, so a plain per-task
    `time.sleep(delay)` would still let `workers` requests leave at once. This
    gate serializes the *pacing* (not the request itself) so `--delay` throttles
    the whole scan and stays polite to the sites being probed.
    """
    if min_interval <= 0:
        return
    with _RATE_LOCK:
        now = time.monotonic()
        wait = max(0.0, _RATE_STATE["next"] - now)
        _RATE_STATE["next"] = max(now, _RATE_STATE["next"]) + min_interval
    if wait > 0:
        time.sleep(wait)


def check_username_site(name, tmpl, absent, username, delay):
    """Return dict with presence result. Rate-limited by `delay`."""
    _rate_gate(delay)
    url = tmpl.format(u=urllib.parse.quote(username))
    st, _, body = http_get(url, timeout=12)
    found = None
    if st == 200:
        found = True
        if absent and absent.lower() in body.lower():
            found = False
    elif st in (404, 410):
        found = False
    elif st in (301, 302, 303, 307, 308):
        found = None  # ambiguous redirect
    elif st == 0:
        found = None
    else:
        found = None
    return {"site": name, "url": url, "status": st, "found": found}


def builtin_username_scan(username: str, delay: float,
                          workers: int = 6) -> list[dict]:
    results = []
    # Rate-limited but parallel within a small pool; delay applies per task.
    with futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(check_username_site, n, t, a, username, delay)
                for (n, t, a) in USERNAME_SITES]
        for f in futures.as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                log_debug(f"username task error: {e}")
    results.sort(key=lambda d: (d["found"] is not True, d["site"].lower()))
    return results


def run_sherlock(username: str, binpath: str) -> list[str]:
    """Wrap sherlock if installed; parse the '[+] Site: url' lines."""
    _, so, _ = run_tool([binpath, "--print-found", "--no-color",
                           "--timeout", "12", "--", username], timeout=300)
    hits = []
    for line in so.splitlines():
        m = re.search(r"\[\+\]\s{0,8}([^:]{1,256}):\s{0,8}(https?://\S{1,2048})", line)
        if m:
            hits.append(f"{m.group(1).strip()} → {m.group(2).strip()}")
    return hits


def run_maigret(username: str, binpath: str) -> list[str]:
    _, so, _ = run_tool([binpath, "--print-found", "--no-color",
                           "--", username], timeout=300)
    hits = []
    for line in so.splitlines():
        m = re.search(r"\[\+\]\s{0,8}([^:]{1,256}):\s{0,8}(https?://\S{1,2048})", line)
        if m:
            hits.append(f"{m.group(1).strip()} → {m.group(2).strip()}")
    return hits


def run_github(username: str) -> dict:
    """GitHub OSINT via the public, key-less api.github.com: profile, public
    profile email, emails leaked in public commit metadata, and top repos.
    Unauthenticated rate limit is 60 requests/hour per IP."""
    enc = urllib.parse.quote(username)
    hdr = {"Accept": "application/vnd.github+json"}
    out = {"available": True, "exists": False, "rate_limited": False,
           "profile": {}, "emails": [], "repos": []}

    st, _, body = http_get(f"https://api.github.com/users/{enc}", timeout=15, headers=hdr)
    if st == 0:
        out["available"] = False
        return out
    if st == 403 and "rate limit" in (body or "").lower():
        out["available"] = False
        out["rate_limited"] = True
        return out
    if st != 200 or not body:
        return out  # 404 -> user does not exist (exists stays False)
    try:
        p = json.loads(body)
    except Exception:
        return out
    out["exists"] = True
    for k in ("login", "name", "company", "blog", "location", "bio",
              "twitter_username", "public_repos", "followers", "following",
              "created_at", "html_url"):
        v = p.get(k)
        if v not in (None, ""):
            out["profile"][k] = v
    emails = set()
    if p.get("email"):
        emails.add(p["email"])

    # public events -> author emails leaked in push commits
    st2, _, body2 = http_get(f"https://api.github.com/users/{enc}/events/public?per_page=100",
                             timeout=20, headers=hdr)
    if st2 == 200 and body2:
        try:
            for ev in json.loads(body2):
                if ev.get("type") == "PushEvent":
                    for c in ev.get("payload", {}).get("commits", []):
                        em = (c.get("author") or {}).get("email")
                        if em:
                            emails.add(em)
        except Exception:
            pass
    out["emails"] = sorted(emails)

    # top repos (most recently pushed)
    st3, _, body3 = http_get(f"https://api.github.com/users/{enc}/repos?sort=pushed&per_page=5",
                             timeout=20, headers=hdr)
    if st3 == 200 and body3:
        try:
            for r in json.loads(body3):
                out["repos"].append({
                    "name": r.get("name"), "desc": r.get("description"),
                    "lang": r.get("language"), "stars": r.get("stargazers_count"),
                    "url": r.get("html_url")})
        except Exception:
            pass
    return out


def gravatar_from_email(email: str) -> dict:
    """Gravatar profile presence via MD5 of the email (public API)."""
    import hashlib
    # MD5 is mandated by the Gravatar API; interop hash, not a security control.
    h = hashlib.md5(email.strip().lower().encode(),
                    usedforsecurity=False).hexdigest()
    prof = f"https://en.gravatar.com/{h}.json"
    st, _, body = http_get(prof, timeout=12)
    out = {"hash": h, "avatar": f"https://gravatar.com/avatar/{h}",
           "profile": None}
    if st == 200 and body:
        try:
            out["profile"] = json.loads(body).get("entry", [{}])[0]
        except Exception:
            pass
    return out


def run_holehe(email: str, binpath: str) -> list[str]:
    _, so, _ = run_tool([binpath, "--only-used", "--", email], timeout=200)
    used = []
    for line in so.splitlines():
        m = re.search(r"\[\+\]\s*(\S+)", line)
        if m:
            used.append(m.group(1))
    return used


def run_xposedornot(email: str) -> dict:
    """Email breach lookup via XposedOrNot — a free, key-less, documented API
    (api.xposedornot.com). Uses two endpoints: a quick breach list and richer
    analytics. Nothing here needs an API key; queries are not logged by them."""
    enc = urllib.parse.quote(email, safe="")
    out = {"available": True, "found": False, "breaches": [],
           "risk": None, "detail": []}

    # 1) quick breach list: {"breaches":[[names...]]} or {"Error":"Not found"}
    st, _, body = http_get(f"https://api.xposedornot.com/v1/check-email/{enc}",
                           timeout=15)
    if st == 0:
        out["available"] = False
        return out
    if st == 200 and body:
        try:
            br = json.loads(body).get("breaches")
            if isinstance(br, list) and br and isinstance(br[0], list):
                out["breaches"] = [str(x) for x in br[0] if x]
            elif isinstance(br, list):
                out["breaches"] = [str(x) for x in br if x]
        except Exception:
            pass
    out["found"] = bool(out["breaches"])
    # a 404 / {"Error":"Not found"} simply means not breached -> found=False

    time.sleep(0.6)  # respect the ~2 req/s rate limit

    # 2) analytics (risk score + per-breach detail) — best effort
    st2, _, body2 = http_get(
        f"https://api.xposedornot.com/v1/breach-analytics?email={enc}", timeout=20)
    if st2 == 200 and body2:
        try:
            a = json.loads(body2)
            risk = (a.get("BreachMetrics") or {}).get("risk")
            if isinstance(risk, list) and risk:
                out["risk"] = risk[0]
            elif isinstance(risk, dict):
                out["risk"] = risk
            details = (a.get("ExposedBreaches") or {}).get("breaches_details")
            if isinstance(details, list):
                for b in details[:50]:
                    if isinstance(b, dict):
                        out["detail"].append({
                            "name": b.get("breach") or b.get("breach_name"),
                            "domain": b.get("domain"),
                            "date": b.get("xposed_date"),
                            "records": b.get("xposed_records"),
                            "data": b.get("xposed_data"),
                        })
            if not out["breaches"] and out["detail"]:
                out["breaches"] = [d["name"] for d in out["detail"] if d["name"]]
                out["found"] = bool(out["breaches"])
        except Exception:
            pass
    return out


EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{1,63}$")


def run_identity(username: str, email: str, delay: float,
                 tools: dict) -> dict:
    log_phase("Identity OSINT" + (f" — {username}" if username else ""))
    data = {"username": username, "email": email}

    if username:
        # Prefer sherlock/maigret if present; ALWAYS also run built-in so the
        # report is self-contained and comparable.
        if tools.get("sherlock"):
            log_step("sherlock (installed) — username presence")
            data["sherlock"] = run_sherlock(username, tools["sherlock"])
            log_result("sherlock", f"{len(data['sherlock'])} hit(s)")
        if tools.get("maigret"):
            log_step("maigret (installed) — username presence")
            data["maigret"] = run_maigret(username, tools["maigret"])
            log_result("maigret", f"{len(data['maigret'])} hit(s)")

        log_step(f"built-in username scan ({len(USERNAME_SITES)} sites, "
                 f"{delay:.1f}s/site rate-limit)")
        data["username_builtin"] = builtin_username_scan(username, delay)
        hits = [r for r in data["username_builtin"] if r["found"] is True]
        maybe = [r for r in data["username_builtin"] if r["found"] is None]
        log_result("built-in", f"{len(hits)} found, {len(maybe)} inconclusive")
        for r in hits:
            log_hit(r["site"], r["url"])
        if maybe:
            log_info("inconclusive (manual check): "
                     + ", ".join(r["site"] for r in maybe))

        log_step("GitHub OSINT — profile + leaked commit emails (key-less)")
        gh = run_github(username)
        data["github"] = gh
        if not gh["available"]:
            log_warn("GitHub API unavailable"
                     + (" (rate limit: 60/hour unauthenticated)" if gh["rate_limited"] else ""))
        elif gh["exists"]:
            log_hit("github", gh["profile"].get("html_url") or f"user '{username}' exists")
            if gh["emails"]:
                shown = ", ".join(gh["emails"][:5])
                more = " …" if len(gh["emails"]) > 5 else ""
                log_hit("github emails", f"{shown}{more}")
        else:
            log_info(f"no GitHub user '{username}'")

    if email:
        if not EMAIL_RE.match(email):
            log_warn(f"'{email}' is not a valid email format")
        else:
            log_step("email — format OK, checking Gravatar")
            data["gravatar"] = gravatar_from_email(email)
            if data["gravatar"]["profile"]:
                log_hit("gravatar", "public profile exists")
            else:
                log_info("no public Gravatar profile")
            if tools.get("holehe"):
                log_step("holehe (installed) — account existence by email")
                data["holehe"] = run_holehe(email, tools["holehe"])
                log_result("holehe", f"{len(data['holehe'])} site(s)")
            log_step("XposedOrNot — email breach lookup (free, key-less)")
            xo = run_xposedornot(email)
            data["xposedornot"] = xo
            if not xo["available"]:
                log_warn("XposedOrNot service unavailable")
            elif xo["found"]:
                shown = ", ".join(xo["breaches"][:8])
                more = " …" if len(xo["breaches"]) > 8 else ""
                log_hit("xposedornot",
                        f"{len(xo['breaches'])} breach(es): {shown}{more}")
            else:
                log_result("xposedornot", "no breaches found")
    return data


# ======================================================================
# REPORTING
# ======================================================================
def write_txt_report(path, target, infra, identity):
    L = []
    L.append("=" * 64)
    L.append("  STRIX ARCHER — OSINT REPORT")
    L.append(f"  target : {target}")
    L.append(f"  date   : {datetime.now():%Y-%m-%d %H:%M:%S}")
    L.append("  scope  : authorized lab use (CTFs / owned targets)")
    L.append("=" * 64)

    if infra:
        L.append("\n[ INFRASTRUCTURE ]")
        dns = infra.get("dns", {})
        for rtype, vals in dns.items():
            L.append(f"  {rtype:5} : " + ", ".join(vals))
        if infra.get("ptr"):
            for ip, ptr in infra["ptr"].items():
                if ptr:
                    L.append(f"  PTR   : {ip} -> {ptr}")
        subs = infra.get("subdomains", [])
        L.append(f"\n  Subdomains (crt.sh): {len(subs)}")
        for s in subs:
            L.append(f"    - {s}")
        fp = infra.get("http", {})
        if fp.get("status"):
            L.append(f"\n  HTTP  : {fp['status']}  {fp.get('url','')}")
            if fp.get("server"):
                L.append(f"  Server: {fp['server']}")
            if fp.get("title"):
                L.append(f"  Title : {fp['title']}")
            if fp.get("tech"):
                L.append(f"  Tech  : {', '.join(fp['tech'])}")
            miss = missing_security_headers(fp)
            if miss:
                L.append(f"  Missing security headers: {', '.join(miss)}")
            if fp.get("cookies"):
                L.append(f"  Cookies: {', '.join(fp['cookies'])}")
        if infra.get("whois"):
            L.append("\n  WHOIS (salient):")
            L.append(infra["whois"])
        if infra.get("theharvester"):
            th = infra["theharvester"]
            L.append(f"\n  theHarvester — {len(th['emails'])} email(s), "
                     f"{len(th['hosts'])} host(s)")
            for e in th["emails"]:
                L.append(f"    email: {e}")
            for h in th["hosts"][:30]:
                L.append(f"    host : {h}")
        if infra.get("spiderfoot"):
            L.append("\n  SpiderFoot (passive):")
            L.append("  " + first_line(infra["spiderfoot"], 200))

    if identity:
        L.append("\n[ IDENTITY ]")
        if identity.get("username"):
            L.append(f"  username: {identity['username']}")
        for tool in ("sherlock", "maigret"):
            if identity.get(tool):
                L.append(f"\n  {tool} hits ({len(identity[tool])}):")
                for h in identity[tool]:
                    L.append(f"    - {h}")
        bi = identity.get("username_builtin", [])
        if bi:
            found = [r for r in bi if r["found"] is True]
            maybe = [r for r in bi if r["found"] is None]
            L.append(f"\n  built-in scan — found ({len(found)}):")
            for r in found:
                L.append(f"    + {r['site']:12} {r['url']}")
            if maybe:
                L.append(f"  inconclusive ({len(maybe)}): "
                         + ", ".join(r["site"] for r in maybe))
        gh = identity.get("github")
        if gh and gh.get("exists"):
            pr = gh["profile"]
            L.append(f"\n  GitHub: {pr.get('html_url','')}")
            for k in ("name", "bio", "company", "location", "blog",
                      "twitter_username", "created_at"):
                if pr.get(k):
                    L.append(f"    {k:9}: {pr[k]}")
            L.append(f"    repos    : {pr.get('public_repos','?')} · "
                     f"followers: {pr.get('followers','?')}")
            if gh["emails"]:
                L.append(f"    emails (profile + commits): {len(gh['emails'])}")
                for e in gh["emails"]:
                    L.append(f"      - {e}")
            for r in gh["repos"]:
                L.append(f"    repo: {r.get('name','')} "
                         f"({r.get('lang') or '-'}, ★{r.get('stars',0)}) {r.get('url','')}")
        elif gh and not gh.get("available"):
            L.append("\n  GitHub: API unavailable"
                     + (" (rate limited)" if gh.get("rate_limited") else ""))
        if identity.get("email"):
            L.append(f"\n  email: {identity['email']}")
            g = identity.get("gravatar")
            if g:
                L.append(f"    gravatar avatar : {g['avatar']}")
                L.append(f"    gravatar profile: "
                         + ("exists" if g.get("profile") else "none"))
            if identity.get("holehe"):
                L.append(f"    holehe — used on {len(identity['holehe'])} site(s):")
                for s in identity["holehe"]:
                    L.append(f"      - {s}")
            xo = identity.get("xposedornot")
            if xo:
                if not xo.get("available"):
                    L.append("    XposedOrNot: service unavailable")
                elif xo.get("found"):
                    L.append(f"    XposedOrNot — {len(xo['breaches'])} breach(es):")
                    for name in xo["breaches"]:
                        L.append(f"      - {name}")
                    r = xo.get("risk")
                    if isinstance(r, dict):
                        L.append(f"    risk: {r.get('risk_label','')} "
                                 f"{r.get('risk_score','')}".rstrip())
                    for d in xo.get("detail", [])[:20]:
                        if d.get("date") or d.get("records"):
                            L.append(f"        {d.get('name','?')}: "
                                     f"{d.get('date','?')}, "
                                     f"{d.get('records','?')} records")
                else:
                    L.append("    XposedOrNot: no breaches found")

    L.append("\n" + "=" * 64)
    L.append("  End of report — verify findings manually before relying on them.")
    text = "\n".join(L)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def write_html_report(path, target, infra, identity):
    def esc(x):
        return html.escape(str(x))
    rows = []
    rows.append(f"<h1>Strix Archer — {esc(target)}</h1>")
    rows.append(f"<p class=meta>{datetime.now():%Y-%m-%d %H:%M:%S} · "
                "authorized lab use only</p>")
    if infra:
        rows.append("<h2>Infrastructure</h2><table>")
        for rtype, vals in infra.get("dns", {}).items():
            rows.append(f"<tr><th>{rtype}</th><td>{esc(', '.join(vals))}</td></tr>")
        fp = infra.get("http", {})
        if fp.get("status"):
            rows.append(f"<tr><th>HTTP</th><td>{fp['status']} "
                        f"{esc(fp.get('server',''))}</td></tr>")
            if fp.get("tech"):
                rows.append(f"<tr><th>Tech</th><td>{esc(', '.join(fp['tech']))}</td></tr>")
            miss = missing_security_headers(fp)
            if miss:
                rows.append(f"<tr><th>Missing headers</th><td class=warn>"
                            f"{esc(', '.join(miss))}</td></tr>")
        rows.append("</table>")
        subs = infra.get("subdomains", [])
        if subs:
            rows.append(f"<h3>Subdomains ({len(subs)})</h3><ul>")
            rows += [f"<li>{esc(s)}</li>" for s in subs]
            rows.append("</ul>")
    if identity:
        rows.append("<h2>Identity</h2>")
        bi = identity.get("username_builtin", [])
        found = [r for r in bi if r["found"] is True]
        if found:
            rows.append(f"<h3>Found accounts ({len(found)})</h3><ul>")
            rows += [f'<li><a href="{esc(r["url"])}">{esc(r["site"])}</a></li>'
                     for r in found]
            rows.append("</ul>")
        gh = identity.get("github")
        if gh and gh.get("exists"):
            pr = gh["profile"]
            rows.append(f'<h3>GitHub — <a href="{esc(pr.get("html_url",""))}">'
                        f'{esc(pr.get("login",""))}</a></h3><table>')
            for k in ("name", "bio", "company", "location", "blog",
                      "twitter_username", "public_repos", "followers", "created_at"):
                if pr.get(k) not in (None, ""):
                    rows.append(f"<tr><th>{esc(k)}</th><td>{esc(pr[k])}</td></tr>")
            rows.append("</table>")
            if gh["emails"]:
                rows.append(f"<h3 class=warn>GitHub emails ({len(gh['emails'])})</h3><ul>")
                rows += [f"<li>{esc(e)}</li>" for e in gh["emails"]]
                rows.append("</ul>")
            if gh["repos"]:
                rows.append("<h3>Top repos</h3><ul>")
                rows += [f'<li><a href="{esc(r.get("url",""))}">{esc(r.get("name",""))}</a>'
                         f' — {esc(r.get("lang") or "-")}, ★{esc(r.get("stars",0))}</li>'
                         for r in gh["repos"]]
                rows.append("</ul>")
        for tool in ("sherlock", "maigret", "holehe"):
            if identity.get(tool):
                rows.append(f"<h3>{tool} ({len(identity[tool])})</h3><ul>")
                rows += [f"<li>{esc(h)}</li>" for h in identity[tool]]
                rows.append("</ul>")
        xo = identity.get("xposedornot")
        if xo and xo.get("found"):
            rows.append(f"<h3 class=warn>XposedOrNot breaches "
                        f"({len(xo['breaches'])})</h3><ul>")
            rows += [f"<li>{esc(n)}</li>" for n in xo["breaches"]]
            rows.append("</ul>")
        elif xo and xo.get("available"):
            rows.append("<h3>XposedOrNot</h3><p>No breaches found.</p>")
    doc = f"""<!doctype html><html><head><meta charset=utf-8>
<title>Strix Archer — {esc(target)}</title><style>
body{{background:#0c0e14;color:#e8eaf0;font:14px/1.5 system-ui,sans-serif;
max-width:820px;margin:2rem auto;padding:0 1rem}}
h1{{color:#b388ff}}h2{{color:#4fc3f7;border-bottom:1px solid #262a36;
padding-bottom:4px;margin-top:2rem}}h3{{color:#69f0ae}}
.meta{{color:#6b7280}}table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:4px 10px;border-bottom:1px solid #1a1e2a;
vertical-align:top}}th{{color:#6b7280;white-space:nowrap;width:130px}}
a{{color:#4fc3f7}}.warn{{color:#ffd54f}}ul{{margin:.3rem 0}}
li{{margin:2px 0}}</style></head><body>
{''.join(rows)}
<p class=meta>Verify all findings manually. Authorized targets only.</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


# ======================================================================
# CLI
# ======================================================================
def build_parser():
    p = StrixParser(
        prog="strix_archer.py",
        description="OSINT tool for authorized lab targets "
                    "(CTF challenges & fictional personas).")
    p.add_argument("-d", "--domain",
                   help="target domain for infrastructure OSINT "
                        "(e.g. acme-labs.example)")
    p.add_argument("-u", "--username",
                   help="username for identity OSINT")
    p.add_argument("-e", "--email",
                   help="email for identity OSINT (Gravatar / holehe)")
    p.add_argument("-o", "--output",
                   help="report basename (default: strix_<target>_<time>)")
    p.add_argument("--delay", type=float, default=0.7,
                   help="per-site rate-limit for username scan "
                        "(default 0.7s; be polite)")
    p.add_argument("--check-password", metavar="PASSWORD", nargs="?",
                   const="__PROMPT__", default=None,
                   help="check a password against HIBP Pwned Passwords using "
                        "k-anonymity (the password never leaves your machine). "
                        "Omit the value to be prompted without echo (recommended: "
                        "a value on the command line is saved to shell history).")
    p.add_argument("--setup", action="store_true",
                   help="check for optional OSINT tools and install missing "
                        "ones safely via pipx (shows every command first)")
    p.add_argument("--use-spiderfoot", action="store_true",
                   help="also run SpiderFoot passive footprint if installed")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="pre-accept the authorized-use consent (for scripts)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--version", action="version",
                   version="strix-archer %s" % VERSION)
    return p


def main():
    # Make the Unicode banner/glyphs safe on any console (e.g. a legacy Windows
    # code page) instead of crashing with UnicodeEncodeError.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = build_parser()
    args = parser.parse_args()

    global USE_COLOR, DEBUG
    if args.no_color or not sys.stdout.isatty():
        USE_COLOR = False
    DEBUG = args.debug

    # Input validation: reject values that could act as leading-dash options to a
    # wrapped tool, or contain unexpected characters (defense against argument
    # injection into sherlock/maigret/holehe/whois).
    if args.username and not re.match(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$", args.username):
        parser.error("username must be 1-64 chars of letters, digits, '.', '_' or '-' "
                     "and cannot start with '-'")
    if args.domain:
        _host = args.domain.split("//")[-1].split("/")[0].split(":")[0]
        if not re.match(r"^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$", _host):
            parser.error("domain looks invalid (hostname characters only, no leading/trailing dash)")
    if args.email and (args.email[0] == "-" or not EMAIL_RE.match(args.email)
                       or "/" in args.email):
        parser.error("email looks invalid (expected name@host.tld, no leading '-' or '/')")

    print_banner()

    # --setup runs standalone, no target or consent needed (it only installs)
    if args.setup:
        run_setup(args.i_am_authorized)
        return

    # --check-password is a self-contained privacy-preserving lookup
    if args.check_password is not None:
        pw = args.check_password
        if pw == "__PROMPT__":
            # Obtain the password WITHOUT putting it in argv (so it never lands in
            # shell history or the process table). Interactive terminals get a
            # no-echo prompt; non-interactive callers (a pipe, or the TUI) feed a
            # single line on stdin — this avoids getpass's /dev/tty fallback,
            # which would deadlock behind a TUI holding the terminal.
            if sys.stdin is not None and sys.stdin.isatty():
                import getpass
                try:
                    pw = getpass.getpass("  Password to check (not shown): ")
                except (EOFError, KeyboardInterrupt):
                    print()
                    return
            else:
                pw = sys.stdin.readline().rstrip("\r\n")
            if not pw:
                log_warn("no password provided")
                return
        else:
            log_warn("passing the password on the command line exposes it to your "
                     "shell history / process list — prefer `--check-password` with "
                     "no value to be prompted safely")
        log_phase("Pwned Passwords check (k-anonymity)")
        log_info("only the first 5 chars of the SHA-1 hash are sent; "
                 "the password itself stays local")
        count = pwned_password_count(pw)
        if count > 0:
            log_warn(f"this password appears in known breaches {count:,} "
                     "time(s) — do not use it")
        elif count == 0:
            log_result("pwned passwords", "not found in known breaches")
        else:
            log_warn("Pwned Passwords service was unavailable")
        if not (args.domain or args.username or args.email):
            print()
            return

    if not (args.domain or args.username or args.email):
        parser.print_help()
        print(_c("\n  Provide at least one of --domain / --username / --email"
                 "  (or use --setup / --check-password)\n", C.YELLOW))
        return

    if not check_consent(args.i_am_authorized):
        print(_c("\n  Consent not given — exiting.\n", C.RED))
        return

    tools = detect_tools()
    present = [t for t, p in tools.items() if p]
    log_phase("Environment")
    log_result("optional tools present",
               ", ".join(present) if present else "none (built-in engine only)")
    absent = [t for t, p in tools.items() if not p]
    if absent:
        log_info("not found (built-in fallback will be used): "
                 + ", ".join(absent))

    infra = identity = None
    if args.domain:
        infra = run_infrastructure(normalize_domain(args.domain),
                                   args.use_spiderfoot, tools)
    if args.username or args.email:
        identity = run_identity(args.username or "", args.email or "",
                                max(args.delay, 0.0), tools)

    log_phase("Report")
    target = args.domain or args.username or args.email
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    if args.output:
        # Reduce a user-supplied path to a safe basename so -o cannot write
        # outside the working directory (no traversal / absolute paths).
        base = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(args.output)) or f"strix_{safe}"
    else:
        base = f"strix_{safe}_{datetime.now():%Y%m%d_%H%M%S}"
    txt_path, html_path = base + ".txt", base + ".html"
    write_txt_report(txt_path, target, infra, identity)
    write_html_report(html_path, target, infra, identity)
    log_result("saved", txt_path)
    log_result("saved", html_path)
    print()


if __name__ == "__main__":
    main()
