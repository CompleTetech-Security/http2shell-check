---
name: http2shell-check
description: Assess authorized local Brotli/CVE-2026-111497 component inventories and produce evidence-based CSV, JSON or offline HTML reports using the standalone checker.
---

Locate the user's checkout or standalone `http2shell_check.py`; an installed skill is not a checker installation. If absent, obtain the public checker from https://github.com/CompleTetech-Security/http2shell-check using the user's chosen location. Inspect `--help` and the checkout's docs/REFERENCE.md for the actual schema and CLI.

Use authorized local inventory or supplied versions. Do not infer permission to scan targets, collect from remote machines, run applications/containers, or install packages. The CLI is offline. Optional collect_python.py reads distribution metadata only in its current interpreter; run it only in the environment the user authorizes.

Examples, substituting the actual checker path:

```sh
python /path/to/http2shell_check.py --component brotli=1.2.0 --format json
python /path/to/http2shell_check.py --inventory /path/to/authorized-inventory.json --format html --output /path/to/new-report.html
```

Keep output outside the repository, choose a new filename, and preserve existing reports. Do not use --force without an explicit replacement request. On interruption, inspect complete/operational_errors and retain completed observations; do not call a partial report complete.

Summarize affected components, unknowns, coverage gaps, rule date and evidence origin. Explain that HTTP2Shell/Node2Shell are aliases for the Brotli decoder flaw; HTTP/2 is not required. Preserve every component copy and vendor/backport uncertainty. Fixed_version_reported is not patch attestation; potentially_affected is not reachable RCE. Exploitability stays not_tested. Do not replace the real CLI with a second scanner or upload private inventory/report data.
