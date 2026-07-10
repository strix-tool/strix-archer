# Changelog

All notable changes to Strix Archer are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-08

Initial public release — an authorized-use OSINT automation tool with a CLI and a
Textual TUI.

### Added
- **Infrastructure OSINT** — DNS records, WHOIS, crt.sh certificate-transparency
  subdomains, reverse-IP, and HTTP header / technology fingerprinting.
- **Identity OSINT** — username presence across platforms, email format + Gravatar
  checks, and a per-target dossier that merges every clue into one report.
- **Wraps installed tools when present** (sherlock, maigret, holehe, theHarvester,
  SpiderFoot) and falls back to a built-in, dependency-free engine when they are
  not — so it runs on a bare Python install too.
- **Textual TUI** (`strix_archer_tui.py`) plus a tidy `.txt` + `.html` report.
- **Standard-library-only** built-in engine (Python 3.10+); optional tools are
  used automatically if they are on PATH.

### Security
- **Authorized-use consent gate** — a one-time typed acknowledgement before any
  collection; intended for CTF challenges/personas and targets you own or are
  explicitly authorized to test.
- **No shell** — every wrapped tool runs via an argv list; usernames, domains and
  emails are strictly validated (leading-dash rejected) before use.
- **Rate-limited** identity checks and **key-less** public APIs only (no secrets).
- **Bounded** regexes and a 2 MiB HTTP body cap (no catastrophic backtracking);
  report paths are reduced to a safe basename.

[1.0.0]: https://github.com/strix-tool/strix-archer/releases/tag/v1.0.0
