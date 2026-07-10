# Strix Archer

> An OSINT **aggregator** for authorized investigations. Give it a domain,
> username, or email and it fans out across DNS/RDAP, Certificate Transparency,
> public breach data, and account-presence checks — wrapping installed tools when
> present and **falling back to built-in, standard-library checks** when they are
> not — then writes a tidy `.txt` + `.html` report. Ships with a cool terminal
> banner and an optional terminal UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20(Kali)-blue.svg)](#install)
[![Use](https://img.shields.io/badge/use-authorized%20only-critical.svg)](#-authorized-use-only)

Part of the open-source **[Strix Advanced Tools](https://github.com/strix-tool)** suite.

## ⚠️ Authorized use only

Archer gathers information about people and domains. Use it **only** against
targets you own or are explicitly permitted to investigate — e.g. **TryHackMe**
rooms and fictional lab personas. It requires you to pass `--i-am-authorized`
(the CLI) or tick **"I am authorized"** (the TUI) before every run. Collecting or
processing personal data may be regulated where you live. **You are responsible
for how you use it.**

## What it does

- **Domain / infrastructure:** DNS over HTTPS (Cloudflare + Google), RDAP/whois
  registration data, Certificate-Transparency subdomains (crt.sh), reverse DNS,
  and — when installed — theHarvester and a passive SpiderFoot footprint.
- **Identity:** username presence across ~20 public sites (built-in), plus
  Sherlock/Maigret when installed; GitHub profile + public-commit email leaks;
  Gravatar presence.
- **Email:** breach exposure via XposedOrNot; account discovery via holehe (when
  installed).
- **Password hygiene:** a **k-anonymity** check against HIBP Pwned Passwords — only
  the first 5 chars of the SHA-1 hash are sent; the password never leaves your box.

```bash
# a fictional TryHackMe persona, authorized
python3 strix_archer.py -u jackduggan -e jack@shining.thm --i-am-authorized

# domain footprint with an optional SpiderFoot passive pass
python3 strix_archer.py -d shining.thm --use-spiderfoot --i-am-authorized

# safe password check — omit the value to be prompted (never in shell history)
python3 strix_archer.py --check-password
```

See the full flag reference in [docs/ORIGINAL_README.md](docs/ORIGINAL_README.md).

## Install

Built for **Kali/Linux** (Python 3 is preinstalled, zero required dependencies for
the core tool). The wrapped tools are **optional** — Archer runs without them and
uses built-in checks. To add them:

```bash
git clone https://github.com/strix-tool/strix-archer
cd strix-archer
python3 strix_archer.py --version

# optional: install the wrappable tools (opt-in, prints what it will do)
python3 strix_archer.py --setup --i-am-authorized
```

Optional terminal UI:

```bash
pip install textual --break-system-packages
python3 strix_archer_tui.py
```

## Security (of the tool itself)

Archer is hardened so that running it can't be turned against you:

- **No shell.** Every wrapped tool is executed with an argument list
  (`subprocess.run([...])`), never `shell=True`. Positional inputs are passed after
  a `--` separator and validated, so a crafted username/domain can't inject flags.
- **Passwords are never in argv.** `--check-password` reads the password from a
  no-echo prompt (interactive) or from stdin (the TUI pipes it) — it never appears
  in your shell history or the process list. Only a SHA-1 **prefix** is sent.
- **Polite by design.** A global rate-gate makes `--delay` throttle the *whole*
  scan, not just per-thread; network calls are bounded (timeouts + a capped whois
  socket read) so a hostile server can't hang or exhaust the run.
- **Safe output paths.** `-o` is reduced to a filename-safe basename, so it can't
  write outside the working directory.

Full details and the threat model: [SECURITY.md](SECURITY.md).

## Credits

Archer is an **orchestrator** — it does not bundle or modify any scanner and it
calls only free, key-less public APIs. Enormous thanks to every upstream project
and service. Full list with authors, links, and licenses:
**[ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md)**.

## License

[MIT](LICENSE) © 2026 Strix Advanced Tools. The integrated tools and services
remain under their own licenses/terms. Use only where you are authorized.
