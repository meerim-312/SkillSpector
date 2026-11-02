# Snyk Code Scan Findings

**Date:** 2026-10-30
**Scan:** `snyk code test .` (full repo, Snyk Code SAST)
**Initial result:** 0 high/critical, 6 medium, 33 low — 39 total issues
**After fixes:** 0 high/critical, 5 medium, 33 low — 38 total issues

## Fixed

| Rule | File | Line | Fix |
|---|---|---|---|
| `python/InsecureXmlParser` | `src/skillspector/dependency_sources.py` | 1384 | Replaced `xml.etree.ElementTree.fromstring` with `defusedxml.ElementTree.fromstring(content, forbid_dtd=True)`, added as a project dependency. Closes XXE and billion-laughs entity-expansion paths; confirmed by rescan (medium count dropped 6→5) and the existing 305-test `test_dependency_sources.py` suite still passes. |

Also made `subprocess.Popen` in `scripts/compare_scan_accuracy.py` pass `shell=False` explicitly (it was already the implicit default — this is a clarity/defense-in-depth change, not a behavior change). It did not clear the `CommandInjection` findings on rescan, confirming Snyk's rule flags any CLI-argument-tainted value reaching `Popen` regardless of `shell=`.

## Remaining findings — assessed as false positives, not fixed

Snyk Code issues cannot be suppressed locally via `.snyk` (`snyk ignore --help` confirms: *"Ignoring issues or vulnerabilities using the .snyk file is not supported for Snyk Code"*) — any dismissal has to happen in the Snyk web UI per-finding. Code changes were not made for the following because they would either break the tool's intended function or break tests that intentionally use fake-looking secrets to validate the scanner's own credential-redaction logic, for no real security gain:

### Medium — Command Injection (5×, `scripts/compare_scan_accuracy.py:829,837,868,1405,1412`)
All reach `subprocess.Popen(command, ...)` where `command` is always a **list**, never a string, and `shell=False` (now explicit). Python never invokes a shell for list-form `Popen`, so shell metacharacters in any argument are inert — this is the standard-safe subprocess pattern. The tainted value is the already-validated scanner executable / git worktree path (checked via `resolve(strict=True)`, `is_relative_to(root)`, and an exact git-revision/hash match earlier in `_resolve_scanner_identity`) or hardcoded git subcommands (`"status"`, `"--porcelain"`, etc.) — not an injectable string. Snyk's rule fires on any CLI-arg-tainted value reaching `Popen` regardless of `shell=`, so it cannot be cleared without removing the comparison harness's core ability to run a caller-specified scanner binary.

### Low — Path Traversal (7×: `scripts/compare_scan_accuracy.py:829,837,852,868,1670,1784`, `src/skillspector/providers/registry.py:54`)
Each is a CLI argument (`--baseline-executable`, `--approval-artifact`, etc.) or the `SKILLSPECTOR_MODEL_REGISTRY` env var used to read a file the operator explicitly named. There's no privilege boundary being crossed — the operator already has filesystem access to whatever they point the tool at — and most of these paths are already resolved + validated (`resolve(strict=True)`, `is_relative_to()`, `is_file()` checks) before use. This is inherent to any CLI tool that accepts file-path arguments.

### Low — Hardcoded secrets in tests (25×, all in `tests/`)
E.g. `api_key="sk-test"`, `"second-assignment-password-sentinel"`, `"synthetic-secret-token-123456"`. Several of these files (`test_dependency_sources.py`, `test_report_sanitizer.py`) specifically test SkillSpector's own credential-redaction logic and need realistic-looking fake secrets to do so; the rest are inert placeholders satisfying client constructors in LLM-provider tests. None are real credentials. Snyk already tags these with the `/test` rule-ID suffix, indicating lower confidence for test files.

## Notes

- The `~/.claude/skills/snyk-scan/scripts/snyk-scan.sh` helper's issue-count display uses GNU-only `grep -oP`, which silently fails on macOS (BSD grep) and always reports "total: 0". This does not affect pass/fail (Snyk's own exit code is authoritative), only the cosmetic count. Figures above come from `snyk code test` run directly.
