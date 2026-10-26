<p align="center"><img src="docs/images/banner.png" alt="HTTP2Shell Check — Brotli decoder exposure assessment by CompleteTech LLC" width="100%"></p>

<p align="center">
<a href="https://github.com/CompleTetech-Security/http2shell-check/actions/workflows/tests.yml"><img src="https://github.com/CompleTetech-Security/http2shell-check/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
<img src="https://img.shields.io/badge/Python-3.10%2B-1E3A8A" alt="Python 3.10+">
<img src="https://img.shields.io/badge/dependencies-none-166534" alt="No dependencies">
<a href="LICENSING.md">AGPL-3.0 / commercial</a>
</p>

# HTTP2Shell Check

**Brotli decoder exposure, with evidence.**

`http2shell-check` assesses reported versions and component inventories for **CVE-2026-111497**, the Google Brotli decoder vulnerability also called **HTTP2Shell** or **Node2Shell**. These names describe the same underlying flaw. HTTP/2 is not required.

It covers native Brotli, Node.js, Bun, Python Brotli/brotlicffi, Brotli4j, Envoy, Istio, and exact Debian source-package snapshots. The standalone Python checker makes no network requests, imports no decoder, and sends no exploit payloads. Version comparisons are triage, not proof: exploitability is always `not_tested`, and a reported fixed version is not a verified deployed patch.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
- [The report](#the-report)
- [Interpreting results](#interpreting-results)
- [Coverage and limitations](#coverage-and-limitations)
- [Safety and privacy](#safety-and-privacy)
- [Documentation](#documentation)
- [Agent skill](#agent-skill)
- [Development](#development)
- [Contributing and security](#contributing-and-security)
- [License and branding](#license-and-branding)

## Requirements

Python 3.10+ on Windows, Linux, or macOS. There is nothing to install: the checker and its tests use only the standard library. Use `python3` where `python` is not available.

## Quick start

```sh
git clone https://github.com/CompleTetech-Security/http2shell-check.git
cd http2shell-check

# Assess explicit versions
python http2shell_check.py --component brotli=1.2.0 --format json
python http2shell_check.py --component python-brotli=1.2.1 --component bun=1.4.3

# Assess an inventory and write an offline HTML report
python http2shell_check.py --inventory examples/inventory.json --format html --output report.html

# Assess the current Python environment's installed packages
python collect_python.py > runtime.json
python http2shell_check.py --inventory runtime.json --format json
```

Existing output files are refused unless `--force` is given. Keep real inventories and reports outside Git. The checker file also works when copied elsewhere; supply `--logo approved-logo.png` if you want a logo in HTML reports.

## Usage

Supply at least one input. `--component`, `--inventory`, `--pip-list`, and `--node-inventory` are repeatable and combinable; each creates independent observations.

| Input | Source |
| --- | --- |
| `--component PRODUCT=VERSION` | A single version supplied on the command line. |
| `--inventory PATH` | Canonical multi-component JSON inventory. |
| `--pip-list PATH` | Output of `python -m pip list --format=json`; only Brotli/brotlicffi entries are assessed. |
| `--node-inventory PATH` | An existing node2shell-check collector v1 file. |

Common options:

| Option | Default | Behavior |
| --- | --- | --- |
| `--format csv\|json\|html` | `csv` | Output format; all formats carry the same component findings and report metadata. |
| `--output PATH` | stdout | Atomically publish a completed report. |
| `--force` | off | Replace an existing output file. Inputs, the checker, and logo files stay protected. |
| `--brand NAME` | CompleteTech LLC | HTML organization label. |
| `--logo PATH` | bundled `assets/logo.png` for the default brand, if present | Embed a PNG up to 1 MiB. A custom brand omits the default logo. |
| `--fail-on-finding` | off | Exit 1 for `potentially_affected` or `unsupported_runtime` results. |
| `--version`, `--help` | | Print the tool version or usage. |

The canonical inventory schema, adapter details, field limits, and the complete option and exit-code reference are in [docs/REFERENCE.md](docs/REFERENCE.md). Product identifiers and version rules are in the [methodology](docs/HTTP2SHELL.md). Unknown identifiers produce unknown coverage, not a guessed match.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The report was written without operational errors. |
| `1` | With `--fail-on-finding`, at least one result is `potentially_affected` or `unsupported_runtime`. |
| `2` | Operational failure: invalid arguments, or an input, collection, or output error. Valid observations from other inputs are kept where possible. |
| `130` | Interrupted. |

An interruption during assessment publishes the completed component observations with `complete=false`. An interruption during output preserves an existing destination and may leave no new report. Operational errors are not assessment results, and a partial report is not a complete one.

## The report

The HTML report is one offline, script-free file. It includes an embedded logo, summary counts, prioritized component observations, evidence, unknowns, coverage gaps, remediation, branch fixes, and source links. It adapts to light and dark themes and prints cleanly. Use `--brand "Your Organization" --logo approved-logo.png` for custom branding.

<picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png"><img src="docs/images/report-light.png" alt="Synthetic Brotli exposure report with component counts and evidence" width="100%"></picture>

[Open the synthetic example](docs/example-report.html). The screenshots show actual generated output; no targets were scanned. See also the [narrow layout](docs/images/report-narrow.png) and [print preview](docs/images/report-print.png).

## Interpreting results

| Status | Meaning |
| --- | --- |
| `potentially_affected` | The reported version matches a verified affected interval or exact vendor package. Validate the actual deployed copy and input paths. |
| `fixed_version_reported` | The version meets the applicable rule. Deployed patch state and safety remain unverified. |
| `unsupported_runtime` | An older, unsupported Node.js line needs an upgrade or vendor review. This is not CVE confirmation. |
| `unknown` | Missing, disputed, qualified, custom, conflicting, or uncovered evidence needs review. |

Unknown results do not trigger exit code 1 but are prominently counted. A successful command is not a clean security assessment, and report counts are not an asset safety verdict. Each component copy is assessed separately, so a fixed result never erases an affected or unknown copy.

## Coverage and limitations

Rules are embedded and dated **2026-10-25**; they are offline snapshots, not an automatically refreshed feed. Each product identifier below is assessed by its own rule:

| Identifier | Component |
| --- | --- |
| `brotli` | Native Google Brotli (fixed independently by branch) |
| `node`, `bun` | Node.js and Bun runtimes |
| `python-brotli`, `brotlicffi` | PyPI packages |
| `brotli4j` | Java Brotli4j (Maven) |
| `envoy`, `istio` | Envoy proxy and Istio mesh |
| `debian-brotli` | Exact Debian `brotli` source-package snapshots |

Affected and fixed versions per identifier are tabulated in the [methodology](docs/HTTP2SHELL.md), and the primary sources behind them in the [verified source matrix](docs/SOURCES.md).

Key boundaries:

- Native Brotli maintenance fixes are independent from runtime and package fixes.
- Python versions below the shared advisory lower bound are disputed and remain unknown.
- Envoy findings use the exact affected patches named by its maintainer; older patches stay unknown.
- Debian assessment requires exact source package, release, and version provenance. It does not infer patch state for binary packages, or for Node.js from libbrotli alone.
- Red Hat generic comparisons are disabled.
- Vendor, custom, or backported builds need vendor review. A reported fixed version is not a verified deployed patch, and a declared dependency does not prove an installed or loaded copy.
- Configuration, reachability, and mitigation are operator-supplied evidence and never override version status.

Not provided: exhaustive discovery, SBOM ingestion, loaded-code attestation, passive website scanning, and reachability tests.

This tool complements [node2shell-check](https://github.com/CompleTetech-Security/node2shell-check), whose Node.js interface and ownership remain unchanged. See [scope and template parity](docs/SCOPE.md).

## Safety and privacy

- The checker is offline. It reads only the local inputs and optional logo you supply and writes only the output you choose. It performs no network calls, shell execution, application imports, or decoder invocations.
- Input parsing is bounded, HTML output escapes all input values, and CSV cells that look like formulas are neutralized.
- Output is staged and published atomically, never silently overwritten, and cannot replace an input, the checker, or a logo.
- `collect_python.py` reads installed package metadata only, in the interpreter that runs it. It never imports Brotli or application code. Run it only in an environment you are authorized to inspect.
- Use only authorized inventories, and keep real inventories, reports, and secrets outside Git. Examples in this repository are synthetic.

## Documentation

- [CLI and schemas](docs/REFERENCE.md): canonical multi-component JSON, pip-list subset, Node collector adapter, all options, exit codes, and result schema.
- [Brotli methodology](docs/HTTP2SHELL.md): affected and fixed intervals, uncertainty, decoder prerequisites, mitigation, and remediation.
- [Verified sources](docs/SOURCES.md): primary-source matrix, exact Debian snapshot, and unresolved disagreements.
- [Scope and template parity](docs/SCOPE.md): what this repository covers and what it deliberately excludes.
- [Validation](docs/VALIDATION.md): test coverage, example reproduction, and visual checks.
- [Changelog](CHANGELOG.md).

## Agent skill

The [agent skill](skills/http2shell-check/SKILL.md) invokes this CLI using authorized local inventories, including after separate installation. To install it separately, copy the entire `skills/http2shell-check/` directory to `.agents/skills/http2shell-check/` in your chosen project, or to your agent's personal skill directory. Preserve any existing installation before copying. The installed skill locates the checker separately; it does not bundle another implementation.

## Development

```sh
python -m unittest -v
python http2shell_check.py --help
git diff --check
```

Tests use synthetic inputs and mocks only. See [docs/VALIDATION.md](docs/VALIDATION.md) for what the suite covers and how the synthetic example report is regenerated.

## Contributing and security

Open a focused issue and pull request; see [CONTRIBUTING.md](CONTRIBUTING.md). Report sensitive checker flaws privately as described in [SECURITY.md](SECURITY.md).

## License and branding

Licensed under [AGPL-3.0](LICENSE), including commercial use under its terms, or under a separately agreed [commercial license](LICENSING.md) from CompleteTech LLC. Names and logos have [separate brand restrictions](BRAND_ASSETS.md).

<p align="center"><a href="https://complete.tech"><img src="assets/logo.png" alt="CompleteTech LLC" width="160"></a><br>Built by CompleteTech LLC · Innovation at Every Integration</p>
