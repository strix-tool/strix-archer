# Contributing

Thanks for your interest in improving this **Strix Advanced Tools** project! Contributions of
all kinds are welcome: bug reports, documentation, translations, and code.

## Ground rules

- **Security first.** These are security/privacy tools. Preserve the existing guarantees:
  no shell (use argument lists for subprocesses, with a `--` separator before positional
  input), input validation, no dynamic code (`eval`/`exec`/`pickle`), no secrets in argv,
  bounded network I/O, and least privilege. If a change touches a security-relevant path,
  add or update a test and explain the reasoning.
- **Keep dependencies few and vetted.** The core tool runs on the Python standard library
  only; the TUI adds Textual/Rich. Prefer the standard library over new third-party packages.
- **Respect targets and services.** Keep the authorized-use gate, keep rate-limiting polite,
  and never send more data to a public API than a lookup requires.

## Development

1. Fork and clone the repo.
2. Run the app from source (see the README).
3. Syntax-check before opening a PR: `python -m py_compile strix_archer.py strix_archer_tui.py`.
4. Match the surrounding code style; keep functions small and readable.

## Reporting bugs

Open an issue using the templates in `.github/ISSUE_TEMPLATE/`. Include your OS, how you
installed, exact steps to reproduce, and what you expected.

## Security issues

**Do not** file security vulnerabilities as public issues — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the project's
[MIT License](LICENSE).
