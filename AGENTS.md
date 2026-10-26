# Repository instructions

Read README.md, CONTRIBUTING.md, SECURITY.md and docs/SOURCES.md before changes.
Keep http2shell_check.py standalone on Python 3.10+ with standard-library-only runtime and tests.

Scope is CVE-2026-111497 only. HTTP2Shell, Node2Shell and Brotli RCE are aliases of this decoder flaw. No network scanning, decoder imports, exploit payloads, subprocess collection, installation hooks, or automatic rule updates belong in the checker.

Preserve vendor/backport uncertainty, strict package identity, independent component copies, evidence origin, system/bundled distinctions, and unknown coverage. Exploitability stays not_tested. A fixed version is not verified patch state. Declared dependencies do not prove installed code. Configuration and mitigation do not override patch classification.

Update rules, source matrix, methodology and meaningful boundary tests together after live primary-source verification. Preserve bounded parsing, escaping, CSV safety, atomic output, protected input paths and interruption receipts. Keep real inventories, target data and secrets outside Git. Collectors read metadata only.

Run python -m unittest -v, CLI examples/help, and git diff --check. Tests use synthetic inputs only. Review actual rendered HTML after visual changes. Verify hosted CI on the published commit and distinguish local validation from CI and deployment.

The agent skill must invoke the real CLI, locate it separately after installation, and preserve authorization boundaries. CLAUDE.md is a pointer here. Respect LICENSING.md and BRAND_ASSETS.md.
