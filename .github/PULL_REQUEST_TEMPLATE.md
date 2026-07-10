## Summary

<!-- What does this PR change and why? -->

## Checklist

- [ ] I read [CONTRIBUTING.md](../CONTRIBUTING.md).
- [ ] The change preserves the security guarantees (no shell, `--` before positional args,
      input validation, no secrets in argv, bounded network I/O, least privilege). See `SECURITY.md`.
- [ ] I syntax-checked: `python -m py_compile strix_archer.py strix_archer_tui.py`.
- [ ] The authorized-use gate and polite rate-limiting are preserved.
- [ ] Docs updated if user-facing behavior changed.
