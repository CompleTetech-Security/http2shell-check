# Brotli assessment methodology

Snapshot verified **2026-10-25** (America/New_York). Scope: **CVE-2026-111497** only. The defect is in Google's Brotli decoder. A program must pass attacker-controlled compressed data to the affected decoder for the corresponding exposure path; HTTP/2 support or compression output alone is insufficient.

## Rules

| Product identifier | Comparable scope | First fixed release / handling |
| --- | --- | --- |
| `brotli` | Native 1.0 from 1.0.3, 1.1, 1.2 | 1.0.10, 1.1.1, 1.2.1, independently by branch |
| `node` | 22.x, 24.x, 26.x | 22.23.4, 24.22.1, 26.12.1 |
| `bun` | Major 1 from 1.0.21 | 1.4.4 |
| `python-brotli` | PyPI Brotli, 1.0.3 through 1.2.0; fixed reported within 1.0–1.2 | 1.2.1; earlier disputed versions unknown; native maintenance exceptions are not applied to PyPI |
| `brotlicffi` | Four-part major-1 versions at/above 1.0.3.0 through 1.2.0.x | 1.2.1.0; older/disputed versions unknown |
| `brotli4j` | Major 1 through 1.23.0 | 1.24.0; unlisted 1.23.1–1.23.x interval unknown |
| `envoy` | Exact affected 1.36.11, 1.37.7, 1.38.5, 1.39.2 | 1.36.12, 1.37.8, 1.38.6, 1.39.3, 1.40.0 within those branches; older patches unknown |
| `istio` | 1.29.0–1.29.8, 1.30.0–1.30.5, 1.31.0–1.31.1 | 1.29.9, 1.30.6, 1.31.2; 1.29 is end of life |
| `debian-brotli` | Exact source-package snapshots only | See SOURCES.md; vendor, release and source package required |

Unknown future branches do not inherit thresholds. Newer patch/minor releases within the explicitly documented covered line may report a fixed version. Bun and Brotli4j comparisons are bounded to major 1; native Brotli/Python/proxy/mesh comparisons use the listed minor branches; Node uses listed major branches.

## Evidence limits

Malformed, partial, prerelease, qualified, conflicting and vendor/custom versions remain unknown. Explicit package/ecosystem mismatches are unknown. A dependency declaration does not establish an installed copy and remains unknown. Installed metadata does not establish loaded code or running workloads. All supplied evidence and timestamps are retained; omitted observation timestamps remain empty rather than fabricated.

Runtime/product rules describe bundled upstream builds. Explicit system linkage requires independent decoder/build evidence and remains unknown. Native `brotli` and exact Debian source-package observations can describe system libraries, but cannot clear bundled copies. Every copy is assessed separately; fixed results never erase affected/unknown copies. Report counts do not constitute an asset safety verdict.

Vendor, distribution and custom provenance requires vendor review unless an exact vendor rule applies. Supplied patch/backport evidence does not independently attest the patch. Node.js cherry-picked the fix without necessarily updating the Brotli version string. Detailed Node metadata inconsistent with its version threshold or suggesting a backport remains unknown; even a matching patch constant is not proof of patch completeness.

Decoder capability, configuration, inbound/outbound reachability, loaded state and mitigation are independently reported strings. They are operator evidence, not verified by the checker, and cannot override version status. Envoy/Istio impact depends on configured Brotli decompression. Python HTTP clients can enable response decoding when an optional Brotli provider is installed; package presence alone does not establish a specific active path. Java wrappers can load native decoders; Java memory safety does not attest those libraries.

## Remediation and mitigation

Identify every deployed copy, select a maintained fixed release or exact vendor security update, update locks as appropriate, rebuild artifacts and images, redeploy, restart, then verify the actual running component. Bun compiled executables and Brotli4j native artifacts require replacement/rebuild; a system-library update cannot replace embedded copies.

For incoming requests, reject Brotli Content-Encoding before any decoder processes the body, including case-insensitive and stacked encodings. For outbound responses, remove Brotli negotiation and disable automatic Brotli decoding or reject Brotli before automatic body processing. An Accept-Encoding change alone is insufficient against unsolicited responses. Direct decoder calls need their own review. Mitigations reduce paths; they do not prove patch status.

Exploitability always remains `not_tested`. No payloads, malformed streams, decompression, RCE checks or network requests occur. All rules are offline snapshots, not automatically refreshed feeds. [Source matrix and conflicts](SOURCES.md).
