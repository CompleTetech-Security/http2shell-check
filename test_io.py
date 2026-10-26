import csv
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch
from types import SimpleNamespace
import collect_python
import http2shell_check as c


class IO(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, value, name="input.json"):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = c.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_canonical_multiple_copies_and_incomplete_coverage(self):
        records = [{"asset":"api.example.com", "id":str(i), "product":"brotli", "version":v} for i,v in enumerate(["1.2.0", "1.2.1", ""])]
        path = self.file({"schema_version":1,"coverage":"partial export","components":records})
        code, output, _ = self.invoke("--inventory",str(path),"--format","json","--fail-on-finding")
        report = json.loads(output)
        self.assertEqual(1, code)
        self.assertEqual(3, len(report["results"]))
        self.assertEqual(1, report["counts"]["unknown"])
        self.assertEqual(["partial export"], report["coverage"])

    def test_invalid_inputs_and_types(self):
        for value in [{"schema_version":True,"components":[]}, {"schema_version":2,"components":[]},
                      {"schema_version":1,"components":[{"version":4}]},
                      {"schema_version":1,"components":[{"execute":"bad"}]},
                      {"schema_version":1,"components":[{"versions":[1]}]},
                      {"schema_version":1,"coverage":{},"components":[]},
                      {"schema_version":1,"components":[{"observed_at":"yesterday"}]},
                      {"schema_version":1,"components":[{"brotli_block_switch_error":True}]}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                c.load_inventory(self.file(value))

    def test_json_bounds_duplicate_keys_and_unsafe_values(self):
        for raw in ['{"schema_version":1,"schema_version":1}', '{"x":NaN}', '{"x":"\\ud800"}', '['*1000+']'*1000,
                    json.dumps({"x":"x"*2049}), json.dumps({"x":"\x00"}), '['+'0,'*10000+'0]']:
            path = self.root / "bad.json"
            path.write_text(raw, encoding="utf-8")
            with self.assertRaises(ValueError):
                c.read_json(path)
        path.write_bytes(b" "*(c.MAX_BYTES+1))
        with self.assertRaises(ValueError):
            c.read_json(path)

    def test_pip_subset_and_empty_scope(self):
        rows, note = c.load_pip(self.file([{"name":"Brotli","version":"1.2.0"},{"name":"other","version":"1"}]))
        self.assertEqual("python-brotli", rows[0]["product"])
        self.assertEqual(1,len(rows))
        self.assertIn("2 package records",note)
        self.assertEqual([],c.load_pip(self.file([]))[0])

    def test_node_adapter(self):
        row = {"schema_version":1,"runtime":"node","node_version":"24.22.0","label":"local-node",
               "build_source":"unknown","brotli_version":"1.2.0","brotli_decompress_available":True,
               "brotli_block_switch_error":-17,"platform":"linux","architecture":"x64"}
        records, _ = c.load_node(self.file(row))
        self.assertEqual("unknown", c.assess(records[0])["status"])
        row["node_version"]="24.22.1"
        self.assertEqual("fixed_version_reported", c.assess(c.load_node(self.file(row))[0][0])["status"])
        row["runtime"]="bun"
        with self.assertRaises(ValueError):
            c.load_node(self.file(row))

    def test_collector_does_not_import_native_modules_or_lose_duplicates(self):
        distributions = [SimpleNamespace(metadata={"Name":"Brotli"},version="1.2.0"),
                         SimpleNamespace(metadata={"Name":"Brotli"},version="1.2.1")]
        with patch.object(collect_python.metadata,"distributions",return_value=distributions), patch.dict(sys.modules,{"brotli":None,"brotlicffi":None}):
            inventory = collect_python.collect()
        self.assertEqual(2,len(inventory["components"]))
        for r in inventory["components"]:
            self.assertEqual("installed_metadata",r["evidence_origin"])
            self.assertNotIn("hostname",r)
        c.load_inventory(self.file(inventory))

    def test_reports_escape_and_preserve_evidence(self):
        r = c.assess({"product":"brotli","version":"1.2.0","asset":"=HYPERLINK(\"bad\")","id":"<script>alert(1)</script>"})
        report = c.make_report([r],["partial"],["synthetic error"])
        doc = c.serialize(report,"html",brand="<img onerror=bad>")
        self.assertNotIn("<script>",doc)
        self.assertNotIn("<img onerror",doc)
        self.assertIn("&lt;script&gt;",doc)
        csv_rows=list(csv.DictReader(io.StringIO(c.serialize(report,"csv"))))
        self.assertTrue(csv_rows[1]["asset"].startswith("'="))
        self.assertEqual("potentially_affected",csv_rows[1]["status"])
        self.assertEqual(r["asset"],json.loads(csv_rows[1]["details"])["asset"])
        self.assertEqual(report,json.loads(c.serialize(report,"json")))
        self.assertIn("synthetic error",csv_rows[0]["details"])
        for value in ["=1"," +2","-1","@SUM(1)"]:
            self.assertTrue(c.csv_safe(value).startswith("'"))

    def test_deterministic_serialization_for_same_report(self):
        report=c.make_report([c.assess({"product":"brotli","version":"1.2.0"})],[],[])
        for format in ["csv","json","html"]:
            self.assertEqual(c.serialize(report,format),c.serialize(report,format))

    def test_atomic_overwrite_and_failed_publish(self):
        path=self.root/"report.json"
        c.save_output(path,"original")
        with self.assertRaises(FileExistsError):
            c.save_output(path,"replacement")
        self.assertEqual("original",path.read_text())
        with patch.object(c.os,"replace",side_effect=OSError("failed")), self.assertRaises(OSError):
            c.save_output(path,"replacement",True)
        self.assertEqual("original",path.read_text())
        self.assertEqual([],list(self.root.glob(".http2shell-*")))
        c.save_output(path,"replacement",True)
        self.assertEqual("replacement",path.read_text())

    def test_interruption_publishes_completed_observations(self):
        original=c.assess
        calls=0
        def interrupt(record):
            nonlocal calls
            calls+=1
            if calls==2:
                raise KeyboardInterrupt()
            return original(record)
        with patch.object(c,"assess",side_effect=interrupt):
            code,output,_=self.invoke("--component","brotli=1.2.0","--component","bun=1.4.3","--format","json")
        self.assertEqual(130,code)
        report=json.loads(output)
        self.assertFalse(report["complete"])
        self.assertEqual(1,len(report["results"]))

    def test_interrupt_after_publication_preserves_output(self):
        path=self.root/"report.json"
        original=c.save_output
        def save(*args,**kwargs):
            original(*args,**kwargs)
            raise KeyboardInterrupt()
        with patch.object(c,"save_output",side_effect=save):
            code,_,_=self.invoke("--component","brotli=1.2.1","--format","json","--output",str(path))
        self.assertEqual(130,code)
        self.assertTrue(json.loads(path.read_text())["complete"])

    def test_exit_codes_and_operational_errors(self):
        self.assertEqual(0,self.invoke("--component","brotli=1.2.0")[0])
        self.assertEqual(1,self.invoke("--component","brotli=1.2.0","--fail-on-finding")[0])
        self.assertEqual(0,self.invoke("--component","unknown=1","--fail-on-finding")[0])
        self.assertEqual(2,self.invoke("--inventory",str(self.root/"missing"))[0])
        self.assertEqual(2,self.invoke("--component","bad")[0])

    def test_protected_inputs_even_with_force_and_hardlinks(self):
        path=self.file({"schema_version":1,"components":[]})
        before=path.read_bytes()
        self.assertEqual(2,self.invoke("--inventory",str(path),"--output",str(path),"--force")[0])
        self.assertEqual(before,path.read_bytes())
        alias=self.root/"alias.json"
        alias.hardlink_to(path)
        self.assertEqual(2,self.invoke("--inventory",str(path),"--output",str(alias),"--force")[0])
        self.assertEqual(before,path.read_bytes())

    def test_standalone_cli(self):
        path=self.root/"http2shell_check.py"
        shutil.copyfile(Path(c.__file__),path)
        for format in ["json","csv","html"]:
            result=subprocess.run([sys.executable,str(path),"--component","brotli=1.2.1","--format",format],cwd=self.root,capture_output=True,text=True,encoding="utf-8")
            self.assertEqual(0,result.returncode,result.stderr)
            self.assertIn("fixed_version_reported" if format!="html" else "fixed version reported",result.stdout)

    def test_all_offline_modes_make_no_network_calls(self):
        path=self.file({"schema_version":1,"components":[{"product":"brotli","version":"1.2.0"}]})
        with patch("socket.socket",side_effect=AssertionError("network")), patch("subprocess.Popen",side_effect=AssertionError("process")):
            self.assertEqual(0,self.invoke("--component","bun=1.4.4","--inventory",str(path),"--format","json")[0])

    def test_default_logo_and_checker_protected(self):
        for path in [Path(c.__file__),Path(c.__file__).parent/"assets"/"logo.png"]:
            before=path.read_bytes()
            for options in [[],["--brand","Other Organization"],["--logo",str(self.file({},"custom.png"))]]:
                self.assertEqual(2,self.invoke("--component","brotli=1.2.1","--output",str(path),"--force",*options)[0])
            self.assertEqual(before,path.read_bytes())
        bundled=Path(c.__file__).parent/"assets"/"logo.png"
        with tempfile.TemporaryDirectory(dir=bundled.parent) as alias_dir:
            alias=Path(alias_dir)/"bundled-alias.png"
            alias.hardlink_to(bundled)
            before=bundled.read_bytes()
            self.assertEqual(2,self.invoke("--component","brotli=1.2.1","--brand","Other Organization","--output",str(alias),"--force")[0])
            self.assertEqual(before,bundled.read_bytes())

    def test_logo_validation_and_missing_output_parent(self):
        bad=self.root/"bad.png"
        bad.write_bytes(b"not png")
        self.assertEqual(2,self.invoke("--component","brotli=1.2.1","--format","html","--logo",str(bad))[0])
        bad.write_bytes(b"\x89PNG\r\n\x1a\n"+b"x"*(1024*1024))
        self.assertEqual(2,self.invoke("--component","brotli=1.2.1","--format","html","--logo",str(bad))[0])
        self.assertEqual(2,self.invoke("--component","brotli=1.2.1","--output",str(self.root/"missing"/"report"))[0])


if __name__=="__main__":
    unittest.main()
