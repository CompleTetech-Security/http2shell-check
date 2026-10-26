#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Offline CVE-2026-111497 inventory assessment; Python 3.10+, no dependencies."""
from __future__ import annotations

import argparse
import base64
import csv
import html
import io
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
RULE_DATE = "2026-10-25"
CVE = "CVE-2026-111497"
MAX_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 10000
STATUS = ("potentially_affected", "unsupported_runtime", "unknown", "fixed_version_reported")
SOURCES = {
    "brotli": "https://github.com/google/brotli/releases/tag/v1.2.1",
    "node": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
    "bun": "https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p",
    "python-brotli": "https://github.com/pypa/advisory-database/blob/main/vulns/brotli/PYSEC-2026-4322.yaml",
    "brotlicffi": "https://github.com/pypa/advisory-database/blob/main/vulns/brotlicffi/PYSEC-2026-4323.yaml",
    "brotli4j": "https://github.com/hyperxpro/Brotli4j/security/advisories/GHSA-x524-jrqf-vwq6",
    "envoy": "https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr",
    "istio": "https://istio.io/latest/news/security/istio-security-2026-007/",
    "debian-brotli": "https://security-tracker.debian.org/tracker/CVE-2026-111497",
}
ECOSYSTEMS = {"brotli": "native", "node": "runtime", "bun": "runtime",
              "python-brotli": "PyPI", "brotlicffi": "PyPI", "brotli4j": "Maven",
              "envoy": "proxy", "istio": "mesh", "debian-brotli": "Debian"}
FIXES = {"node": {(22,): (22, 23, 4), (24,): (24, 22, 1), (26,): (26, 12, 1)},
         "brotli": {(1, 0): (1, 0, 10), (1, 1): (1, 1, 1), (1, 2): (1, 2, 1)},
         "envoy": {(1, 36): (1, 36, 12), (1, 37): (1, 37, 8),
                   (1, 38): (1, 38, 6), (1, 39): (1, 39, 3), (1, 40): (1, 40, 0)},
         "istio": {(1, 29): (1, 29, 9), (1, 30): (1, 30, 6), (1, 31): (1, 31, 2)}}
DEBIAN = {"bookworm": {"1.0.9-2": False, "1.0.9-2+deb12u1": True},
          "trixie": {"1.1.0-2": False, "1.1.0-2+deb13u1": True},
          "sid": {"1.2.0-4.1": True}, "forky": {"1.2.0-4": False}}
GAPS = ["No exhaustive discovery of installed, loaded, bundled or deployed copies.",
        "Red Hat and other unimplemented vendor builds require exact vendor errata; no generic distribution comparison.",
        "Python versions below the shared advisory lower bound remain disputed and unknown.",
        "Envoy older patches not explicitly named in its advisory remain unknown.",
        "curl/libcurl and cdxgen product versions are not mapped to their bundled decoder/runtime."]
REMEDIATION = ("Verify the exact deployed package and vendor advisory. Upgrade to a fixed maintained release; "
               "rebuild bundled artifacts/images, redeploy, restart, and verify the running component. "
               "Review inbound requests, outbound responses and direct decoding independently.")
FIELDS = {"asset", "id", "product", "ecosystem", "version", "versions", "evidence_origin",
          "build_source", "vendor", "package", "release", "linkage", "loaded", "observed_at",
          "decoder", "configuration", "reachability", "mitigation", "patch_evidence",
          "brotli_version", "brotli_decompress_available", "brotli_block_switch_error"}
ORIGINS = {"explicit", "declared", "installed_metadata", "deployed_runtime", "operator_inventory"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_tree(value, depth=0):
    if depth > 8:
        raise ValueError("JSON nesting exceeds 8 levels")
    if isinstance(value, str):
        if len(value) > 2048 or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError("Strings must be at most 2048 characters with no control characters")
    elif isinstance(value, dict):
        if len(value) > 40:
            raise ValueError("Too many object fields")
        for k, v in value.items():
            validate_tree(k, depth + 1)
            validate_tree(v, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_RECORDS:
            raise ValueError("Too many records")
        for v in value:
            validate_tree(v, depth + 1)
    elif value is not None and type(value) not in (bool, int):
        raise ValueError("Unsupported JSON value type")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Non-finite JSON number: " + value)


def read_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Input exceeds 4 MiB")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_pairs,
                           parse_constant=reject_constant)
        validate_tree(value)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("Invalid or excessively nested UTF-8 JSON") from exc
    return value


def component(record, index=0):
    if not isinstance(record, dict) or set(record) - FIELDS:
        raise ValueError("Component must be an object containing only documented fields")
    for key, value in record.items():
        if key == "brotli_decompress_available":
            if value is not None and type(value) is not bool:
                raise ValueError("brotli_decompress_available must be boolean or null")
        elif key == "brotli_block_switch_error":
            if value is not None and type(value) is not int:
                raise ValueError("brotli_block_switch_error must be integer or null")
        elif key == "versions":
            if not isinstance(value, list) or len(value) > 32 or any(not isinstance(v, str) for v in value):
                raise ValueError("versions must contain at most 32 strings")
        elif not isinstance(value, str):
            raise ValueError(key + " must be a string")
    validate_tree(record)
    r = {k: "unknown" for k in ("build_source", "vendor", "linkage", "loaded", "decoder",
                                "configuration", "reachability", "mitigation", "patch_evidence")}
    r.update(asset="unspecified", id=f"component-{index + 1}", product="unknown", version="",
             ecosystem="unknown", package="", release="", observed_at="", evidence_origin="operator_inventory")
    r.update(record)
    if r["evidence_origin"] not in ORIGINS:
        raise ValueError("Unknown evidence_origin")
    if r["linkage"] not in {"unknown", "bundled", "system"}:
        raise ValueError("linkage must be unknown, bundled or system")
    if r["observed_at"]:
        try:
            stamp = datetime.fromisoformat(r["observed_at"].replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                raise ValueError("Timestamp requires timezone")
        except ValueError as exc:
            raise ValueError("observed_at must be an ISO timestamp with timezone") from exc
    if not r["product"] or not r["asset"] or not r["id"]:
        raise ValueError("product, asset and id cannot be empty")
    return r


def load_inventory(path):
    value = read_json(path)
    if not isinstance(value, dict) or set(value) - {"schema_version", "components", "coverage"}:
        raise ValueError("Expected canonical inventory object")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("Inventory schema_version must be 1")
    rows = value.get("components")
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise ValueError("components must be a bounded array")
    coverage = value.get("coverage", "unspecified")
    if not isinstance(coverage, str):
        raise ValueError("coverage must be a string")
    return [component(row, i) for i, row in enumerate(rows)], coverage


def load_node(path):
    value = read_json(path)
    rows = value if isinstance(value, list) else [value]
    if not rows:
        raise ValueError("Node inventory cannot be empty")
    allowed = {"schema_version", "runtime", "label", "node_version", "build_source", "brotli_version",
               "brotli_decompress_available", "brotli_block_switch_error", "platform", "architecture"}
    result = []
    for i, row in enumerate(rows):
        if (not isinstance(row, dict) or set(row) - allowed or type(row.get("schema_version")) is not int
                or row["schema_version"] != 1 or row.get("runtime") != "node"
                or not isinstance(row.get("node_version"), str)):
            raise ValueError("Expected Node2Shell schema 1 standalone Node runtime inventory")
        for key, value in row.items():
            if key not in {"schema_version", "brotli_decompress_available", "brotli_block_switch_error"}:
                if not isinstance(value, str) or len(value) > 512:
                    raise ValueError("Invalid Node inventory string")
        record = {"product": "node", "ecosystem": "runtime", "id": f"node-{i+1}",
                  "asset": row.get("label", "local-node"), "version": row["node_version"],
                  "evidence_origin": "installed_metadata", "build_source": row.get("build_source", "unknown"),
                  "linkage": "bundled"}
        for key in ("brotli_version", "brotli_decompress_available", "brotli_block_switch_error"):
            if key in row:
                record[key] = row[key]
        result.append(component(record, i))
    return result, "Node collector describes its own process, not verified serving processes; platform/architecture not retained"


def load_pip(path):
    """Strict pip list --format=json subset; unrelated packages are counted, not assessed."""
    rows = read_json(path)
    if not isinstance(rows, list):
        raise ValueError("pip-list must be an array")
    results = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"name", "version"} or any(not isinstance(v, str) for v in row.values()):
            raise ValueError("pip-list records require only name and version strings")
        name = re.sub(r"[-_.]+", "-", row["name"].lower())
        if name in {"brotli", "brotlicffi"}:
            results.append(component({"product": "python-brotli" if name == "brotli" else name,
                                      "ecosystem": "PyPI", "package": name, "version": row["version"],
                                      "evidence_origin": "installed_metadata"}, len(results)))
    return results, f"pip-list: {len(rows)} package records; only Brotli/brotlicffi selected; loaded code unknown"


def assess(record):
    r = component(record)
    product = r["product"]
    result = dict(r, schema_version=1, cve=CVE, status="unknown", reason="product_not_covered",
                  fixed_version="", exploitability="not_tested", rules_as_of=RULE_DATE,
                  sources=[SOURCES[product]] if product in SOURCES else [],
                  assessed_at=now(), limitations=["Reported metadata does not attest deployed patches or decoder reachability."],
                  remediation=REMEDIATION)
    result["rule_ecosystem"] = ECOSYSTEMS.get(product, "unknown")
    if not r["observed_at"]:
        result["limitations"].append("Observation time was not supplied; assessment time is separate.")

    def verdict(status, reason, fixed=""):
        result.update(status=status, reason=reason, fixed_version=fixed)
        return result

    if product not in SOURCES:
        return result
    if r["ecosystem"] not in {"unknown", ECOSYSTEMS[product]}:
        return verdict("unknown", "ecosystem_identity_mismatch")
    package = r["package"]
    if package:
        allowed = {"brotli": {"brotli", "libbrotli"}, "node": {"node", "nodejs"}, "bun": {"bun"},
                   "envoy": {"envoy"}, "istio": {"istio"},
                   "python-brotli": {"brotli"}, "brotlicffi": {"brotlicffi"},
                   "debian-brotli": {"brotli"}}
        if product in allowed and package.lower() not in allowed[product]:
            return verdict("unknown", "package_identity_mismatch")
        if product == "brotli4j" and package not in BROTLI4J_PACKAGES:
            return verdict("unknown", "package_identity_mismatch")
    values = {v.strip() for v in [r["version"], *r.get("versions", [])] if v.strip()}
    if len(values) != 1:
        return verdict("unknown", "version_missing" if not values else "conflicting_versions")
    version = values.pop()
    if r["evidence_origin"] == "declared":
        return verdict("unknown", "declaration_not_installed_evidence")
    if product not in {"brotli", "debian-brotli"} and r["linkage"] == "system":
        return verdict("unknown", "system_decoder_requires_independent_library_and_build_evidence")
    if product == "debian-brotli":
        if r["vendor"].lower() != "debian" or r["package"] != "brotli" or r["build_source"] != "distribution":
            return verdict("unknown", "exact_debian_source_package_provenance_required")
        fixed = DEBIAN.get(r["release"], {}).get(version)
        if fixed is None:
            return verdict("unknown", "debian_exact_snapshot_miss")
        return verdict("fixed_version_reported" if fixed else "potentially_affected", "debian_exact_source_package_match")
    if (r["build_source"] not in {"unknown", "upstream", "official", "official_upstream"}
            or r["vendor"] not in {"unknown", "upstream"} or r["patch_evidence"] != "unknown"):
        return verdict("unknown", "vendor_custom_or_patch_provenance_requires_review")
    numeric = version.removeprefix("v") if product in {"node", "bun", "envoy"} else version
    count = 4 if product == "brotlicffi" else 3
    pattern = r"(0|[1-9][0-9]{0,5})" + r"\.(0|[1-9][0-9]{0,5})" * (count - 1)
    if len(numeric) > 128 or not re.fullmatch(pattern, numeric):
        return verdict("unknown", "qualified_partial_or_malformed_version")
    parsed = tuple(int(v) for v in numeric.split("."))
    if product in FIXES:
        key = parsed[:1] if product == "node" else parsed[:2]
        threshold = FIXES[product].get(key)
        if threshold is None:
            if product == "node" and parsed[0] < 26:
                return verdict("unsupported_runtime", "unsupported_node_line_not_cve_confirmation")
            return verdict("unknown", "release_line_not_in_snapshot")
        fixed = ".".join(map(str, threshold))
        if product == "brotli" and parsed < (1, 0, 3):
            return verdict("unknown", "below_verified_lower_bound")
        if product == "envoy" and parsed < threshold and parsed != threshold[:-1] + (threshold[-1] - 1,):
            return verdict("unknown", "envoy_older_patch_not_explicitly_named", fixed)
    else:
        threshold, lower = {
            "bun": ((1, 4, 4), (1, 0, 21)),
            "python-brotli": ((1, 2, 1), (1, 0, 3)),
            "brotlicffi": ((1, 2, 1, 0), (1, 0, 3, 0)),
            "brotli4j": ((1, 24, 0), (0, 0, 0)),
        }[product]
        fixed = ".".join(map(str, threshold))
        if parsed < lower:
            return verdict("unknown", "below_verified_or_disputed_lower_bound", fixed)
        if parsed[0] != 1 or (product in {"python-brotli", "brotlicffi"} and parsed[:2] > (1, 2)):
            return verdict("unknown", "release_line_not_in_snapshot", fixed)
        if product == "brotli4j" and (1, 23, 0) < parsed < threshold:
            return verdict("unknown", "between_listed_affected_and_fixed_versions", fixed)
    if product == "envoy" and parsed[:2] == (1, 36):
        result["limitations"].append("Envoy 1.36 is an older branch; verify current vendor support independently.")
    if product == "istio" and parsed[:2] == (1, 29):
        result["limitations"].append("Istio 1.29 is end of life; move to a maintained branch.")
    if product == "node":
        available = r.get("brotli_decompress_available")
        constant = r.get("brotli_block_switch_error")
        if (available is False or (constant is not None and constant != -17)
                or (parsed < threshold and constant == -17)
                or (parsed >= threshold and available is True and r.get("brotli_version") and constant is None)):
            return verdict("unknown", "decoder_metadata_or_backport_requires_review", fixed)
    return verdict("fixed_version_reported" if parsed >= threshold else "potentially_affected",
                   "reported_version_meets_branch_fix" if parsed >= threshold else "reported_version_in_affected_interval", fixed)


BROTLI4J_PACKAGES = {"com.aayushatharva.brotli4j:" + v for v in
                    ("all", "brotli4j", "native-linux-aarch64", "native-linux-armv7",
                     "native-linux-ppc64le", "native-linux-riscv64", "native-linux-s390x",
                     "native-linux-x86_64", "native-osx-aarch64", "native-osx-x86_64",
                     "native-windows-x86_64", "native-windows-aarch64")}


def make_report(results, coverage, errors, complete=True):
    return {"schema_version": 1, "tool": "http2shell-check", "tool_version": VERSION,
            "cve": CVE, "rules_as_of": RULE_DATE, "generated_at": now(), "complete": complete,
            "counts": {s: sum(r["status"] == s for r in results) for s in STATUS},
            "coverage": coverage, "coverage_limitations": GAPS, "operational_errors": errors,
            "results": sorted(results, key=lambda r: (STATUS.index(r["status"]), r["asset"], r["id"], r["product"]))}


def csv_safe(value):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text


def render_html(report, brand="CompleteTech LLC", logo=""):
    e = lambda value: html.escape(str(value), quote=True)
    image = ""
    if logo:
        with Path(logo).open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("Logo must be a PNG of at most 1 MiB")
        image = '<img class="logo" alt="Organization logo" src="data:image/png;base64,' + base64.b64encode(data).decode() + '">'
    cards = ""
    for r in report["results"]:
        evidence = "".join(f"<dt>{e(k.replace('_', ' '))}</dt><dd>{e(r.get(k, 'not supplied'))}</dd>" for k in
                           ("evidence_origin", "ecosystem", "package", "build_source", "vendor", "release", "linkage", "loaded", "decoder", "configuration", "reachability", "mitigation", "patch_evidence", "versions", "brotli_version", "brotli_decompress_available", "brotli_block_switch_error", "observed_at"))
        links = " · ".join(f'<a href="{e(url)}">Authoritative advisory</a>' for url in r["sources"])
        cards += f'''<article><div class="cardhead"><div><p class="eyebrow">{e(r['asset'])} / {e(r['id'])}</p><h3>{e(r['product'])} <code>{e(r['version'] or 'not reported')}</code></h3></div><span class="pill {e(r['status'])}">{e(r['status'].replace('_',' '))}</span></div>
<p><b>{e(r['reason'].replace('_',' '))}</b> · Fix: <code>{e(r['fixed_version'] or 'requires review')}</code></p>
<p>{e(r['remediation'])}</p><details open><summary>Evidence and limitations</summary><dl>{evidence}</dl><ul>{''.join('<li>'+e(v)+'</li>' for v in r['limitations'])}</ul></details><p class="sources">{links} · Exploitability: <code>not_tested</code></p></article>'''
    tiles = "".join(f'<div class="tile {s}"><strong>{report["counts"][s]}</strong><span>{e(s.replace("_", " "))}</span></div>' for s in STATUS)
    warnings = report["coverage_limitations"] + report["coverage"] + report["operational_errors"]
    table = "".join(f'<tr><td>{e(p)}</td><td>{e("; ".join(".".join(map(str,k))+" → "+".".join(map(str,v)) for k,v in branches.items()))}</td></tr>' for p, branches in FIXES.items())
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>HTTP2Shell exposure report</title><style>
:root{{color-scheme:light dark;--bg:#f2f5fa;--panel:#fff;--text:#17243b;--muted:#4c5c72;--line:#cbd5e1;--accent:#1e3a8a;--warn:#9a3412;--ok:#166534}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0c1422;--panel:#142034;--text:#e4ecfa;--muted:#b1bed3;--line:#3f516b;--accent:#a8c6ff;--warn:#ffbf95;--ok:#91e3b0}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,sans-serif}}main{{max-width:1120px;margin:auto;padding:40px 24px}}header{{display:flex;align-items:center;gap:28px;border-bottom:3px solid var(--accent);padding-bottom:28px}}.logo{{width:150px;background:white;border-radius:12px;padding:10px}}h1{{font-size:clamp(28px,5vw,44px);line-height:1.15;margin:8px 0}}h2{{margin-top:36px}}h3{{margin:5px 0;font-size:22px}}p{{margin:10px 0}}.eyebrow{{text-transform:uppercase;letter-spacing:.12em;font-size:12px;font-weight:750;color:var(--muted)}}.subtitle,.sources,footer{{color:var(--muted);font-size:14px}}.callout{{border-left:4px solid var(--accent);padding:16px 20px;background:var(--panel);margin:24px 0}}.tiles{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}.tile,article,.coverage{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}}.tile strong{{display:block;font-size:38px;line-height:1.2}}.tile span{{display:block;font-size:13px;margin-top:8px}}article{{margin:16px 0;overflow-wrap:anywhere}}.cardhead{{display:flex;justify-content:space-between;gap:16px;align-items:center}}.pill{{border:1px solid currentColor;border-radius:30px;padding:5px 12px;font-size:12px;font-weight:700;white-space:normal}}.potentially_affected,.unsupported_runtime,.unknown{{color:var(--warn)}}.fixed_version_reported{{color:var(--ok)}}a{{color:var(--accent);overflow-wrap:anywhere}}code{{font-size:.9em;overflow-wrap:anywhere}}summary{{cursor:pointer;font-weight:650}}dl{{display:grid;grid-template-columns:180px 1fr;gap:4px 18px;font-size:14px}}dt{{color:var(--muted)}}dd{{margin:0}}table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;border-bottom:1px solid var(--line);padding:12px;overflow-wrap:anywhere}}footer{{border-top:1px solid var(--line);padding-top:20px;margin-top:32px}}li{{margin:5px 0}}
@media(max-width:650px){{main{{padding:20px 14px}}header,.cardhead{{align-items:flex-start;flex-direction:column}}.logo{{width:110px}}.tiles{{grid-template-columns:repeat(2,1fr)}}dl{{grid-template-columns:1fr}}dd{{margin-bottom:8px}}article{{padding:16px}}}}
@media print{{:root{{--bg:white;--panel:white;--text:#111;--muted:#333;--line:#aaa;--accent:#172b61;--warn:#733000;--ok:#17552c}}main{{max-width:none;padding:0}}body{{font-size:10pt}}article{{break-inside:avoid;border-radius:0}}.tiles{{grid-template-columns:repeat(4,1fr)}}a{{color:#172b61}}h2{{break-after:avoid}}}}
</style></head><body><main><header>{image}<div><div class="eyebrow">{e(brand)} / security research tools</div><h1>Brotli decoder<br>Exposure &amp; inventory report</h1><p class="subtitle">{CVE} · rules {RULE_DATE} · generated {e(report['generated_at'])}</p></div></header>
<div class="callout"><b>Version evidence requires verification.</b> Exploitability is always <code>not_tested</code>. A fixed version report is not a safety guarantee. HTTP/2 and Brotli response headers do not establish vulnerable decoding. Report complete: <b>{e(report['complete'])}</b>.</div>
<section class="tiles" aria-label="Assessment counts">{tiles}</section><h2>Coverage &amp; unknowns</h2><div class="coverage"><p>{len(report['results'])} component observations. {len(report['operational_errors'])} operational errors. No exhaustive discovery or reachability verification.</p><ul>{''.join('<li>'+e(v)+'</li>' for v in warnings)}</ul></div>
<h2>Component assessments</h2>{cards or '<p>No matching component observations. This does not establish absence.</p>'}<h2>Branch-specific fixes</h2><table><thead><tr><th>Product</th><th>Branch → fix</th></tr></thead><tbody>{table}<tr><td>Python Brotli / brotlicffi</td><td>1.2.1 / 1.2.1.0; disputed older ranges remain unknown</td></tr><tr><td>Bun / Brotli4j</td><td>1.4.4 / 1.24.0 within covered major 1</td></tr><tr><td>Debian</td><td>Exact source-package/release matches only; see each result</td></tr></tbody></table>
<h2>Verify the running application</h2><p>{e(REMEDIATION)} For incoming bodies, reject Brotli before decoding. For outbound requests, disable automatic Brotli response decoding or reject it before body processing; changing Accept-Encoding alone is insufficient. Mitigations do not change patch status.</p>
<footer>{e(brand)} · http2shell-check {VERSION} · offline metadata assessment · <a href="https://github.com/CompleTetech-Security/http2shell-check">Source and methodology</a></footer></main></body></html>'''


def serialize(report, format="json", brand="CompleteTech LLC", logo=""):
    if format == "html":
        return render_html(report, brand, logo)
    if format == "json":
        return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    stream = io.StringIO(newline="")
    columns = ["record_type", "asset", "id", "product", "version", "status", "reason", "details"]
    writer = csv.writer(stream)
    writer.writerow(columns)
    writer.writerow(["report", "", "", "", "", "", "", csv_safe({k:v for k,v in report.items() if k != "results"})])
    for r in report["results"]:
        writer.writerow(["component", *[csv_safe(r[k]) for k in columns[1:-1]], csv_safe(r)])
    return stream.getvalue()


def save_output(path, text, force=False):
    """Stage complete bytes beside destination, publish atomically, refuse overwrite by default."""
    target = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=target.parent,
                                         prefix=".http2shell-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, target)
        else:
            os.link(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", action="append", default=[], metavar="PRODUCT=VERSION")
    parser.add_argument("--inventory", action="append", default=[], metavar="PATH")
    parser.add_argument("--pip-list", action="append", default=[], metavar="PATH")
    parser.add_argument("--node-inventory", action="append", default=[], metavar="PATH")
    parser.add_argument("--format", choices=["csv", "json", "html"], default="csv")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--brand", default="CompleteTech LLC")
    parser.add_argument("--logo", default="")
    parser.add_argument("--fail-on-finding", action="store_true")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if not (args.component or args.inventory or args.pip_list or args.node_inventory):
        parser.error("Supply --component, --inventory or --pip-list")
    results, coverage, errors = [], [], []
    interrupted = False
    published = False
    try:
        validate_tree(args.brand)
        if args.brand == "CompleteTech LLC" and not args.logo:
            default_logo = Path(__file__).resolve().parent / "assets" / "logo.png"
            if default_logo.is_file():
                args.logo = str(default_logo)
        protected = [Path(__file__).resolve(), *[Path(p).resolve() for p in
                    args.inventory + args.pip_list + args.node_inventory]]
        if args.logo:
            protected.append(Path(args.logo).resolve())
        if args.output and (args.output.resolve() in protected or any(
                p.exists() and args.output.exists() and os.path.samefile(p, args.output) for p in protected)):
            raise ValueError("Output must not replace an input, checker, or logo, even with --force")
        try:
            for index, item in enumerate(args.component):
                if len(results) >= MAX_RECORDS:
                    raise ValueError("Combined assessment exceeds 10000 records")
                if "=" not in item:
                    raise ValueError("--component requires PRODUCT=VERSION")
                product, version = item.split("=", 1)
                results.append(assess(component({"product": product, "version": version,
                                                "id": f"explicit-{index+1}", "evidence_origin": "explicit"})))
            for paths, loader in ((args.inventory, load_inventory), (args.pip_list, load_pip), (args.node_inventory, load_node)):
                for path in paths:
                    try:
                        rows, note = loader(path)
                        if len(results) + len(rows) > MAX_RECORDS:
                            raise ValueError("Combined assessment exceeds 10000 records")
                        coverage.append(note)
                        for row in rows:
                            results.append(assess(row))
                    except (ValueError, OSError) as exc:
                        errors.append(f"{Path(path).name}: {exc}")
        except KeyboardInterrupt:
            interrupted = True
        except ValueError as exc:
            errors.append(str(exc))
        report = make_report(results, coverage, errors, not interrupted and not errors)
        text = serialize(report, args.format, args.brand, args.logo)
        if args.output:
            save_output(args.output, text, args.force)
        else:
            sys.stdout.write(text)
        published = True
        for error in errors:
            print(error, file=sys.stderr)
        if interrupted:
            return 130
        if errors:
            return 2
        return int(args.fail_on_finding and any(r["status"] in STATUS[:2] for r in results))
    except KeyboardInterrupt:
        print("Interrupted; completed report preserved." if published else "Interrupted during output; existing destination preserved.", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(f"Report error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
