#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Read distribution metadata only; never import Brotli or application modules."""
import json
import re
import sys
from datetime import datetime, timezone
from importlib import metadata


def collect():
    rows = []
    for dist in metadata.distributions():
        name = re.sub(r"[-_.]+", "-", dist.metadata.get("Name", "").lower())
        if name not in {"brotli", "brotlicffi"}:
            continue
        if len(rows) >= 10000 or len(dist.version) > 128:
            raise ValueError("Metadata exceeds bounds")
        rows.append({"asset": "local-python-environment", "id": f"package-{len(rows)+1}",
                     "product": "python-brotli" if name == "brotli" else name,
                     "ecosystem": "PyPI", "package": name, "version": dist.version,
                     "evidence_origin": "installed_metadata", "build_source": "unknown",
                     "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    return {"schema_version": 1, "coverage": "Current interpreter distribution metadata only; not loaded-code or deployment attestation; missing packages do not establish global absence", "components": rows}


if __name__ == "__main__":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(json.dumps(collect(), indent=2, sort_keys=True))
    except (ValueError, OSError) as exc:
        print(f"Collection failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
