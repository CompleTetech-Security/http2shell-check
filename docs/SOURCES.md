# Verified sources and coverage

Verified live **2026-10-25 America/New_York**. URLs are provenance, not runtime dependencies. Scope of every enabled row is CVE-2026-111497. Primary maintainer/vendor evidence governs; secondary reporting cannot override it.

| Product / ecosystem | Primary source | Enabled scope and fix | Prerequisite / qualification |
| --- | --- | --- | --- |
| Google Brotli / native | [1.2.1 release](https://github.com/google/brotli/releases/tag/v1.2.1), [1.0.10](https://github.com/google/brotli/releases/tag/v1.0.10), [1.1.1](https://github.com/google/brotli/releases/tag/v1.1.1) | Native affected from 1.0.3; independent fixes 1.0.10, 1.1.1, 1.2.1 in listed branches | Attacker-controlled decoding; vendor builds/backports need provenance |
| Node.js / runtime | [October security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), [22.23.4](https://nodejs.org/en/blog/release/v22.23.4), [24.22.1](https://nodejs.org/en/blog/release/v24.22.1), [26.12.1](https://nodejs.org/en/blog/release/v26.12.1) | Listed major branches below their fixes potentially affected | Bundled decoder; older unsupported lines require review; cherry-picked fix need not change Brotli version |
| Bun / runtime | [GHSA-663w-cv8g-jj2p](https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p) | >=1.0.21,<1.4.4; major-1 fixed from 1.4.4 | Includes response/direct decoding paths; rebuild compiled executables |
| Brotli / PyPI | [PYSEC-2026-4322](https://github.com/pypa/advisory-database/blob/main/vulns/brotli/PYSEC-2026-4322.yaml), [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) | Shared undisputed >=1.0.3,<1.2.1; fixed reported 1.2.1 within listed minor lines | Earlier affected scope disagrees; unknown there; optional HTTP-client decoding depends on configuration |
| brotlicffi / PyPI | [PYSEC-2026-4323](https://github.com/pypa/advisory-database/blob/main/vulns/brotlicffi/PYSEC-2026-4323.yaml), same GHSA | Four-part supported releases at/above 1.0.3.0,<1.2.1.0; fixed 1.2.1.0 | Earlier/disputed package versions remain unknown; no native-decoder import |
| Brotli4j / Maven | [GHSA-x524-jrqf-vwq6](https://github.com/hyperxpro/Brotli4j/security/advisories/GHSA-x524-jrqf-vwq6) | Major-1 <=1.23.0 potentially affected; >=1.24.0 fixed reported; interval between unknown | JNI native artifacts must also be replaced; system lib patch does not replace jars |
| Envoy / proxy | [GHSA-3wvj-j6qm-62mr](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr) | Exact affected 1.36.11,1.37.7,1.38.5,1.39.2; branch fixes 1.36.12,1.37.8,1.38.6,1.39.3,1.40.0 | Brotli decompressor configured; older unlisted patches unknown; support lifecycle separate |
| Istio / mesh | [ISTIO-SECURITY-2026-007](https://istio.io/latest/news/security/istio-security-2026-007/) | 1.29.0–8,1.30.0–5,1.31.0–1 affected; fixed 1.29.9,1.30.6,1.31.2 | Brotli decompression enabled, e.g. EnvoyFilter; 1.29 end of life |
| Debian / brotli source package | [Security tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497) | Exact source-package rows below | Vendor/release/source package exact; no inferred binary package or Node remediation |
| Red Hat / vendor products | [CVE statement](https://access.redhat.com/security/cve/cve-2026-111497) | Generic classification disabled; no verified product-specific errata mapping captured | Statement/mitigation retrieved; vendor backports cannot be compared with upstream thresholds |
| NVD / CVE metadata | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-111497), [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-111497) | No executable rules derived from these pages | NVD returned no readable record; CVE page required JavaScript during retrieval |

The original decoder commit was resolved through GitHub's commit API from abbreviated `0ed4268a4401abcb44720963` to **[0ed4268a4401abcb4472096340477cf4af7d1a2b](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)**. Other supplied patch leads: [b418fa81](https://github.com/google/brotli/commit/b418fa81c48262a86a95332b0bc6d62c30aa78b6), [da980636](https://github.com/google/brotli/commit/da9806362874b9bd4b552a3af360b5d6347beb12). Those individual patch diffs were not separately verified; enabled maintenance fixes use release evidence.

## Exact Debian source-package snapshot

| Release | Reported version | Result |
| --- | --- | --- |
| bookworm | 1.0.9-2 | potentially_affected |
| bookworm | 1.0.9-2+deb12u1 | fixed_version_reported |
| trixie | 1.1.0-2 | potentially_affected |
| trixie | 1.1.0-2+deb13u1 | fixed_version_reported |
| forky | 1.2.0-4 | potentially_affected |
| sid | 1.2.0-4.1 | fixed_version_reported |

Requires product=debian-brotli, vendor=Debian, package=brotli, build_source=distribution and matching release. Other versions are unknown; no dpkg/RPM comparator or monotonic vendor inference exists. These are source package records, not evidence that a particular binary package is installed/loaded. The tracker separately lists Node.js as affected; updating libbrotli alone must not clear Node.

Non-unknown patch evidence requires provenance review before either an affected or fixed exact-match classification. A custom rebuild may retain a Debian version label without retaining its patch set; supplied patch claims alone establish neither affectedness nor remediation.

## Disagreements and unresolved coverage

PyPA marks package histories affected from zero, while GHSA uses a 1.0.3 lower bound. We do not choose a broader assertion from this disagreement: earlier package releases remain unknown, with the shared range enabled. Native fixed maintenance releases do not automatically apply to PyPI package histories. Four-part brotlicffi parsing is a documented subset; other legitimate package version forms remain unknown.

Envoy's maintainer names exact affected patch releases, so earlier patches are not guessed affected. Istio's advisory groups several issues and displays an earlier publication date than other disclosures; only its explicit Brotli entry, listed release ranges, and upgrade guidance are used. No unrelated HTTP/2 authorization issue enters this checker. Severity scores are deliberately not unified across product advisories.

Red Hat, other distribution builds, curl/libcurl and cdxgen product-level mappings remain uncertain/disabled. SBOMs, lockfiles, loaded-library attestation and complete deployment discovery are outside implemented scope.

## Additional bibliography supplied by the user

Unless explicitly marked verified above, the following are **unverified research leads**, retained for follow-up rather than executable thresholds. This catalog does not claim every linked page was fetched.

Technical research:

- [Aikido HTTP2Shell ecosystem analysis](https://www.aikido.dev/blog/python-packages-vulnerable-node2shell-brotli-cve-2026-111497) — retrieved; secondary context only.
- [Aikido Node.js analysis](https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497).
- [Imperva](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/).
- [Sysdig](https://www.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce).
- [Semgrep](https://semgrep.dev/blog/2026/patch-your-node-and-eat-your-brotli-or-you-wont-get-dessert/).
- [OpenSourceMalware](https://opensourcemalware.com/blog/node2shell-affects-python).
- [Vercel bulletin](https://vercel.com/kb/bulletin/node-js-security-advisory).

Other databases and vendor leads:

- [Ubuntu](https://ubuntu.com/security/CVE-2026-111497).
- [Debian DSA-6582-1](https://lists.debian.org/debian-security-announce/2026/msg00498.html).
- [Debian bug 1151690](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1151690).
- [Singapore CSA](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-154/).
- [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-111497).
- [Snyk Conan Brotli](https://security.snyk.io/vuln/SNYK-CONAN-BROTLI-21429335).
- [OpenCVE](https://app.opencve.io/cve/CVE-2026-111497).
- [cdxgen bundled runtime advisory](https://github.com/cdxgen/cdxgen/security/advisories/GHSA-5266-jm88-3grm).

Detection/discovery tools, not incorporated or executed:

- [Trail of Bits Brotli Checker](https://github.com/trailofbits/brotli-checker).
- [Assetnote Node2Shell Scanner](https://github.com/assetnote/node2shell-scanner).
- [Repository search](https://github.com/search?q=node2shell&type=repositories).
- [Remediation PR search](https://github.com/search?q=CVE-2026-111497&type=pullrequests).
- [Issue search](https://github.com/search?q=CVE-2026-111497&type=issues).

Release and initiative leads:

- [Bun 1.4.4](https://bun.com/blog/bun-v1.4.4).
- [Envoy releases](https://github.com/envoyproxy/envoy/releases).
- [Patch the Planet Brotli](https://patchtheplanet.org/brotli).
- [OpenAI initiative](https://openai.com/index/patch-the-planet/).
- [Trail of Bits initiative](https://trailofbits.com/patch-the-planet/).
