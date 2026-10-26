# CLI and schema reference

Python 3.10+, standard library only. The checker opens only explicitly supplied local inputs/output and its optional local logo. No network calls, proxy use, shell execution, application imports or decoder invocations occur.

## Commands

```sh
python http2shell_check.py --component brotli=1.0.9 --component brotli=1.1.1 --format json
python http2shell_check.py --inventory examples/inventory.json --format html --output report.html
python http2shell_check.py --pip-list examples/pip-list.json --format csv
python http2shell_check.py --node-inventory examples/node-runtime.json --format json
python collect_python.py > runtime.json
python http2shell_check.py --inventory runtime.json --format json
```

`--component PRODUCT=VERSION`, `--inventory PATH`, `--pip-list PATH` and `--node-inventory PATH` are repeatable and combinable. They create independent observations. Product identifiers are listed in [methodology](HTTP2SHELL.md); unknown identifiers produce unknown coverage, not a guessed match.

| Option | Default | Behavior |
| --- | --- | --- |
| `--format csv\|json\|html` | csv | Same component findings and report metadata |
| `--output PATH` | stdout | Atomically publish a completed report |
| `--force` | off | Explicitly replace output; inputs, checker and logo aliases stay protected |
| `--brand NAME` | CompleteTech LLC | HTML organization label |
| `--logo PATH` | local assets/logo.png for default brand, if present | Embed PNG up to 1 MiB; custom brand omits default logo |
| `--fail-on-finding` | off | Exit 1 for potentially_affected or unsupported_runtime |
| `--version` | — | Tool version |
| `--help` | — | Usage |

Exit 0 means report written without operational errors, subject to --fail-on-finding. Unknowns alone do not fail. Exit 2 means invalid arguments, input/collection/output error; valid observations from other inputs are retained where possible. Exit 130 means interruption. Interruption during assessment publishes completed component observations with `complete=false`; interruption during output preserves an existing destination and may leave no new report. A report already atomically published remains valid. Standard output streams cannot provide filesystem atomicity.

File publication uses a temporary sibling, fsync and atomic hard-link no-clobber, or replace with --force. Filesystems without hard-link support return an operational error rather than silently weakening protection. Missing output parents are errors. No silent overwrite; temporary files are cleaned up. Keep outputs outside this checkout.

## Canonical inventory v1

```json
{
  "schema_version": 1,
  "coverage": "Partial synthetic service export; loaded code unknown",
  "components": [
    {"asset": "api.example.com", "id": "python-copy-1", "product": "python-brotli",
     "ecosystem": "PyPI", "package": "brotli", "version": "1.2.0",
     "evidence_origin": "installed_metadata", "build_source": "unknown",
     "linkage": "bundled", "observed_at": "2026-10-25T20:00:00Z"}
  ]
}
```

Only `schema_version`, `components`, and optional string `coverage` are accepted at the root. Components may be empty; this is not absence proof. Duplicate component identifiers/copies are retained independently; callers should supply distinct ids. No cross-copy deduplication is performed.

Component fields:

| Field | Type/default | Meaning |
| --- | --- | --- |
| asset, id | string; unspecified / generated component-N | Operator asset/copy labels |
| product, ecosystem | string; unknown | Exact rule identifier and observed ecosystem; explicit mismatches remain unknown |
| version | string; empty | Observed version, unchanged |
| versions | array of at most 32 strings | Additional candidates for this same copy; conflicts remain unknown |
| evidence_origin | explicit, declared, installed_metadata, deployed_runtime, operator_inventory | Defaults operator_inventory; all are supplied claims |
| build_source | string; unknown | unknown/upstream/official/official_upstream permit comparison; other values require review |
| vendor, package, release | strings; unknown/empty/empty | Vendor/build identity; Debian needs vendor Debian, package brotli, release and build_source distribution |
| linkage | unknown, bundled, system | Reported relationship; system product builds need independent library evidence |
| loaded, decoder, configuration, reachability, mitigation, patch_evidence | strings; unknown | Independent unverified observations; non-unknown patch_evidence requires provenance review |
| observed_at | string; empty | ISO timestamp with timezone; absent time remains absent |
| brotli_version | optional string | Node embedded decoder context; not a patch verdict |
| brotli_decompress_available | optional boolean/null | Node collector API metadata |
| brotli_block_switch_error | optional integer/null | Node patch-related constant; inconsistent evidence remains unknown |

Unknown fields/types, duplicate JSON keys, non-finite numbers, control characters and invalid Unicode surrogates are rejected. Inputs are at most 4 MiB each, JSON nesting at most 8, object fields at most 40, strings at most 2048 characters, arrays and combined assessments at most 10,000 records. Comparable numeric version parts are bounded to six ASCII digits, with 3 parts except brotlicffi's 4. Unsupported PEP 440 forms remain unknown rather than requiring a package dependency.

## Optional adapters and collector

`--pip-list` accepts only an array of objects with exactly string `name` and `version`, as exported by `python -m pip list --format=json`. It selects normalized Brotli/brotlicffi names and reports total imported record count. Other packages are outside scope. No pip commands or installation hooks are executed by the checker.

`--node-inventory` accepts the existing node2shell-check collector v1 object or nonempty array: integer schema_version 1, runtime node, required string node_version, optional label/build_source/brotli_version/platform/architecture, boolean/null brotli_decompress_available and integer/null brotli_block_switch_error. Strings in this adapter are at most 512 characters. Unknown keys and other runtime identities are rejected. Platform/architecture are validated but not retained. The adapter describes the collector's own process, not serving-process identity.

`collect_python.py` enumerates `importlib.metadata.distributions()` for the current interpreter and emits canonical JSON, preserving multiple metadata copies. It never imports Brotli or application code, reads environment values/process arguments/hostnames, installs packages or opens connections. It records package names/versions and UTC observation time only. Run in a trusted Python environment; Python startup itself is outside the collector's control. Optional collector CI is separate from checker tests.

No SBOM formats, lockfiles, arbitrary command strings or automatic discovery are accepted.

## Result schema v1

JSON root: schema_version, tool, tool_version, cve, rules_as_of, generated_at, complete, counts by status, coverage notes, coverage_limitations, operational_errors, results. `complete` concerns requested input processing, not exhaustive asset coverage.

Each result retains normalized input/default fields plus schema_version, cve, status, reason, fixed_version, exploitability (always not_tested), rules_as_of, sources, assessed_at, limitations, remediation and rule_ecosystem. This last field names the rule's ecosystem independently of missing observed ecosystem. Missing observation time is not replaced by assessment time. Sources are embedded authoritative URLs. Unsupported products have empty matched sources and product_not_covered.

Results sort by status priority, asset, id, product, preserving separate observations. Generated/assessment times vary between runs; serialization of the same report is deterministic. Component evidence appears in JSON and CSV details; HTML displays core evidence and limitations.

CSV has record_type, asset, id, product, version, status, reason, details. The first `report` row contains root metadata excluding results, preserving errors and coverage even for empty reports. Each `component` row has full result JSON in details. Formula-like scalar cells receive an apostrophe; original evidence remains in JSON details/JSON output. HTML escapes all input values, embeds PNG/style only, and uses a restrictive content security policy without scripts, remote fonts or trackers.
