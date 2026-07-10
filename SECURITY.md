# Security Policy — Strix Archer

## Reporting a vulnerability

Report privately via GitHub Security Advisories (the repo's **Security** tab) or the
[Strix Advanced Tools](https://github.com/strix-tool) maintainer contacts — not a public
issue.

## Authorized use

Archer is an OSINT **aggregator**. Use it only against targets you own or are explicitly
authorized to investigate (e.g. TryHackMe rooms, fictional lab personas). This document is
about the security of **the tool itself** — so running it can't compromise your own machine
or leak your secrets — not about the investigations you perform with it.

## Threat model & hardening

Archer runs optional external tools and calls public web APIs. Two things therefore matter:
a crafted target must not be able to inject commands or flags into a wrapped tool, and the
tool must not leak the operator's own secrets (notably the password passed to the HIBP
check).

- **No shell / no injection.** Every external command uses an argument list
  (`subprocess.run([...])`) — never `shell=True`, `os.system`, or `os.popen`. Positional
  inputs (username/domain/email) are passed **after a `--` end-of-options separator**, and
  the username and domain are validated against a strict character set that **cannot start
  with `-`**, so a value like `--output=/etc/x` can't be reinterpreted as a flag by
  sherlock/maigret/holehe/whois. No `eval`/`exec`/`pickle`; the only deserialization is
  `json.loads` on a tool's or API's own output.

- **The password never touches argv.** `--check-password` takes an **optional** value.
  Omit it and Archer reads the password from a no-echo prompt (`getpass`) on an interactive
  terminal, or from **stdin** when non-interactive (how the TUI feeds it) — so it never
  lands in shell history or the process table. Only the **first 5 hex chars of the SHA-1
  hash** are sent to HIBP (k-anonymity); the password itself stays local. Passing a value
  on the command line still works but prints a warning.

- **Bounded network I/O.** Every HTTP call has a timeout. The stdlib whois socket client
  caps how much it will read (256 KB) and sets a socket timeout, so a hostile or broken
  whois server can't stream forever or exhaust memory. The crt.sh domain is URL-encoded.

- **Global, honest rate-limiting.** Username-presence checks run in a small thread pool. A
  process-wide rate-gate spaces outbound requests at least `--delay` seconds apart across
  *all* threads, so `--delay` throttles the whole scan and stays polite to the sites being
  probed (rather than firing `workers` requests at once).

- **Safe output filename.** A user-supplied `-o` is reduced to a filename-safe **basename**
  (no path traversal, no absolute paths), so the report can only be written in the working
  directory.

- **Robust console output.** stdout/stderr are reconfigured to UTF-8 with replacement, so
  the Unicode banner can't crash the tool on a legacy console code page.

## Known limitations

- The wrapped tools (Sherlock, Maigret, holehe, theHarvester, SpiderFoot, whois, dig) are
  installed and trusted by you; Archer does not pin or verify their versions. Install them
  from signed distro/official packages. `--setup` installs via `pipx` and is opt-in.
- Public APIs (HIBP, XposedOrNot, crt.sh, RDAP, DoH resolvers, GitHub, Gravatar) are third
  parties with their own privacy and retention policies; Archer sends the minimum needed for
  each lookup but cannot control what a provider logs.
- The TUI's *extra-flags* box and the `ARCHER_PATH` environment variable are trusted
  operator inputs by design (they can pass any flag / choose the script) — treat them as
  such.
- OSINT results are indicative, not authoritative: absence of a hit is not proof of absence,
  and a present profile is not proof of ownership.
