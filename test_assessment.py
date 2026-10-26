import unittest
from unittest.mock import patch
import http2shell_check as c


def assess(product, version, **values):
    return c.assess(dict(product=product, version=version, **values))


class Rules(unittest.TestCase):
    def test_all_branch_boundaries(self):
        cases = [
            ("brotli", "1.0.9", "1.0.10"), ("brotli", "1.1.0", "1.1.1"),
            ("brotli", "1.2.0", "1.2.1"), ("node", "22.23.3", "22.23.4"),
            ("node", "24.22.0", "24.22.1"), ("node", "26.12.0", "26.12.1"),
            ("bun", "1.4.3", "1.4.4"), ("python-brotli", "1.2.0", "1.2.1"),
            ("brotlicffi", "1.2.0.2", "1.2.1.0"), ("brotli4j", "1.23.0", "1.24.0"),
            ("envoy", "1.36.11", "1.36.12"), ("envoy", "1.37.7", "1.37.8"),
            ("envoy", "1.38.5", "1.38.6"), ("envoy", "1.39.2", "1.39.3"),
            ("istio", "1.29.8", "1.29.9"), ("istio", "1.30.5", "1.30.6"),
            ("istio", "1.31.1", "1.31.2")]
        for product, old, fixed in cases:
            for version, status in [(old, "potentially_affected"), (fixed, "fixed_version_reported")]:
                with self.subTest(product=product, version=version):
                    r = assess(product, version)
                    self.assertEqual(status, r["status"])
                    self.assertEqual(fixed, r["fixed_version"])
                    self.assertEqual("not_tested", r["exploitability"])
                    self.assertTrue(r["sources"])
        self.assertEqual("fixed_version_reported", assess("envoy", "1.40.0")["status"])

    def test_affected_lower_bounds_and_unknown_older_ranges(self):
        for p, v in [("brotli", "1.0.3"), ("bun", "1.0.21"), ("python-brotli", "1.0.3"),
                     ("brotlicffi", "1.0.3.0"), ("istio", "1.29.0"), ("istio", "1.30.0"), ("istio", "1.31.0")]:
            self.assertEqual("potentially_affected", assess(p, v)["status"])
        for p, v in [("brotli", "1.0.2"), ("bun", "1.0.20"), ("python-brotli", "0.5.2"),
                     ("brotlicffi", "0.8.0.0"), ("envoy", "1.39.1"), ("envoy", "1.35.0")]:
            self.assertEqual("unknown", assess(p, v)["status"])

    def test_future_branches_do_not_inherit_fixes(self):
        for p, v in [("brotli", "1.3.0"), ("node", "28.0.0"), ("bun", "2.0.0"),
                     ("python-brotli", "1.3.0"), ("brotlicffi", "1.3.0.0"),
                     ("brotli4j", "2.0.0"), ("envoy", "1.41.0"), ("istio", "1.32.0")]:
            self.assertEqual("unknown", assess(p, v)["status"])
        self.assertEqual("unsupported_runtime", assess("node", "20.19.0")["status"])

    def test_qualifiers_conflicts_and_missing(self):
        for version in ["", "latest", "1.2", "1.2.1+vendor", "1.2.1-rc1", "01.2.1", "１.２.１", "1.2.1\"<script>"]:
            self.assertEqual("unknown", assess("brotli", version)["status"])
        self.assertEqual("unknown", assess("brotli", "1.2.1", versions=["1.2.0"])["status"])
        for key, value in [("vendor", "Red Hat"), ("build_source", "custom"), ("patch_evidence", "backported"),
                           ("ecosystem", "PyPI"), ("evidence_origin", "declared")]:
            self.assertEqual("unknown", assess("brotli", "1.2.1", **{key:value})["status"])

    def test_package_identity(self):
        for p in c.SOURCES:
            self.assertEqual("unknown", assess(p, "1.2.1", package="unrelated")["status"])
        for package in c.BROTLI4J_PACKAGES:
            self.assertEqual("fixed_version_reported", assess("brotli4j", "1.24.0", package=package)["status"])
        self.assertEqual("unknown", assess("brotli4j", "1.23.1")["status"])

    def test_system_linked_product_needs_decoder_build_evidence(self):
        for product, version in [("node","24.22.1"),("bun","1.4.4"),("envoy","1.40.0"),
                                 ("istio","1.31.2"),("python-brotli","1.2.1"),
                                 ("brotlicffi","1.2.1.0"),("brotli4j","1.24.0")]:
            self.assertEqual("unknown",assess(product,version,linkage="system")["status"])

    def test_debian_exact_source_package_matches(self):
        for release, versions in c.DEBIAN.items():
            for version, fixed in versions.items():
                r = assess("debian-brotli", version, release=release, vendor="Debian", package="brotli", build_source="distribution")
                self.assertEqual("fixed_version_reported" if fixed else "potentially_affected", r["status"])
        for values in [{}, {"vendor":"Debian", "package":"libbrotli1", "build_source":"distribution"},
                       {"vendor":"Debian", "package":"brotli", "build_source":"distribution", "release":"bullseye"}]:
            self.assertEqual("unknown", assess("debian-brotli", "1.0.9-2+deb12u1", **values)["status"])

    def test_patch_state_independent_of_use_and_linkage(self):
        for linkage in ["system", "bundled", "unknown"]:
            r = assess("brotli", "1.2.0", linkage=linkage, decoder="disabled", configuration="disabled", reachability="unreachable", mitigation="reject br before decoding")
            self.assertEqual("potentially_affected", r["status"])
            self.assertEqual(linkage, r["linkage"])
            self.assertEqual("unreachable", r["reachability"])

    def test_node_metadata_does_not_clear_contradictions(self):
        cases = [("24.22.0", {"brotli_block_switch_error":-17}),
                 ("24.22.1", {"brotli_decompress_available":False}),
                 ("24.22.1", {"brotli_block_switch_error":17}),
                 ("24.22.1", {"brotli_decompress_available":True,"brotli_version":"1.2.0"})]
        for version, fields in cases:
            self.assertEqual("unknown", assess("node", version, **fields)["status"])
        self.assertEqual("fixed_version_reported", assess("node", "24.22.1", brotli_version="1.2.0", brotli_block_switch_error=-17)["status"])

    def test_no_network_or_process_execution(self):
        with patch("socket.socket", side_effect=AssertionError("network")), patch("subprocess.Popen", side_effect=AssertionError("process")):
            for product in c.SOURCES:
                assess(product, "1.2.0")


if __name__ == "__main__":
    unittest.main()
