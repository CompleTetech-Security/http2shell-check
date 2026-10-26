# Scope and reference parity

This repository covers CVE-2026-111497 in Google's Brotli decoder and product advisories explicitly linked to it. HTTP2Shell, Node2Shell and Brotli RCE describe the same underlying vulnerability. HTTP/2 is not required. No separate Brotli repository is needed.

The user explicitly requested this broader standalone companion. [node2shell-check](https://github.com/CompleTetech-Security/node2shell-check) already assesses the Node.js manifestation; it remains unchanged, with its existing CLI, schema and ownership. This repository adds native Brotli, Python packages, Bun, Java Brotli4j, Envoy, Istio and exact Debian source-package observations to one inventory report. It accepts the existing Node collector format through an explicit adapter, while preserving uncertainty from detailed decoder metadata.

## Reference revisions inspected

Current default branches were verified live on 2026-10-25:

| Repository | Exact commit |
| --- | --- |
| [php2shell-check](https://github.com/CompleTetech-Security/php2shell-check) | `f244a5597cf6f2bf24d1501cc4730ff178bae97e` |
| [node2shell-check](https://github.com/CompleTetech-Security/node2shell-check) | `ad1ac3bfea1c90cdb022c9543c1ebb7596c56675` |

Inspection included README, AGENTS/CLAUDE, contribution/security/license/brand policies, methodology, CLI reference, implementations, local test patterns, workflows and HTML samples. The Node [checker-family roadmap](https://github.com/CompleTetech-Security/node2shell-check/blob/ad1ac3bfea1c90cdb022c9543c1ebb7596c56675/docs/CHECKER_FAMILY.md) keeps each exploit self-contained and permits multiple affected products in the same checker. The explicit request authorizes this companion despite overlapping Node coverage; no reference repository was modified.

| Standard | Delivery |
| --- | --- |
| Python 3.10+, no third-party runtime/test packages | One standalone entry point; unittest suite |
| Conservative version comparison | Primary-source rules; disputed/uncovered/custom cases unknown |
| Evidence and exploitability boundaries | Separate origin/build/linkage/use/reachability/mitigation; not_tested |
| Useful reports | CSV, JSON and script-free HTML, summary counts and coverage gaps |
| Output integrity | Atomic staging, no-clobber default, protected input aliases, partial interruption reports |
| Branding and presentation | Reference logo, local banner, real screenshots, light/dark/mobile/print |
| Privacy | Synthetic fixtures; no telemetry, scanning, secrets or private inventories |
| Documentation/skill | Versioned schema, sources, methodology, real CLI skill |
| CI | Linux/Windows/macOS, Python 3.10 and 3.14; optional collector job separate |
| Licensing | Retained AGPL/commercial model and separate trademarks |

Website fingerprinting, unrelated integrations, hosted scanning, update channels, SBOM parsing and deployment infrastructure are excluded. curl/libcurl and cdxgen versions do not map reliably to a single decoder build here. No full ecosystem discovery or production acceptance is claimed.
