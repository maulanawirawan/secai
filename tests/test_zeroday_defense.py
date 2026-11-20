"""Zero-day defense toolkit (wave-13): taint_engine, api_fuzz_lab,
exploit_behavior_hunt, crash_triage — discovery, detection, triage.

Every tool is proven on a vulnerable fixture AND an FP-control fixture
(tests/fixtures/zeroday/), plus its fail-closed and safety properties.
Zero external network: the fuzzer only talks to a loopback fixture.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "zeroday"
for p in (ROOT / "core", ROOT / "tools", FIX):
    sys.path.insert(0, str(p))

import api_fuzz_lab  # noqa: E402
import crash_triage  # noqa: E402
import exploit_behavior_hunt as ebh  # noqa: E402
import fuzz_app  # noqa: E402
import taint_engine  # noqa: E402


def run_main(fn, argv, env=None):
    clean = {k: v for k, v in os.environ.items()
             if k not in ("LAB", "LAB_REMOTE_ACK")}
    clean.update(env or {})
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, clean, clear=True), \
            redirect_stdout(out), redirect_stderr(err):
        code = fn(argv)
    return code, out.getvalue(), err.getvalue()


def rows(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["findings"]


class TaintEngineTest(unittest.TestCase):
    EXPECTED = {
        ("cmdi", "app.py", 29), ("ssti", "app.py", 41),
        ("deser", "app.py", 46), ("deser", "app.py", 51),
        ("ssrf", "app.py", 57), ("path", "app.py", 64),
        ("redirect", "app.py", 70), ("code", "app.py", 76),
        ("sqli", "db.py", 7), ("code", "fastapi_app.py", 8),
        ("cmdi", "helpers.py", 7),
        ("sqli", "index.php", 4), ("cmdi", "index.php", 5),
        ("path", "index.php", 6), ("deser", "index.php", 7),
        ("xss", "index.php", 8), ("redirect", "index.php", 9),
        ("cmdi", "server.js", 8), ("sqli", "server.js", 12),
        ("path", "server.js", 15), ("redirect", "server.js", 17),
        ("ssrf", "server.js", 19), ("code", "server.js", 22)}

    def _run(self, repo, *extra):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "t.json"
            code, so, se = run_main(taint_engine.main, [
                "--repo", str(repo), "--out", str(out), *extra])
            return code, (rows(out) if out.exists() else []), se

    def test_vulnerable_tree_every_flow(self):
        code, rs, _ = self._run(FIX / "taint_vuln")
        got = {(r["class"], r["file_path"], r["line_start"]) for r in rs}
        self.assertEqual(got, self.EXPECTED)
        self.assertEqual(code, 1)  # critical/high present
        self.assertTrue(all(r["verdict"] == 1 for r in rs), "static = L1")

    def test_fp_control_safe_twin_reports_nothing(self):
        code, rs, _ = self._run(FIX / "taint_safe")
        self.assertEqual(rs, [])
        self.assertEqual(code, 0)

    def test_cross_file_trace(self):
        _, rs, _ = self._run(FIX / "taint_vuln", "--lang", "py")
        sqli = next(r for r in rs if r["class"] == "sqli")
        self.assertEqual(sqli["flow"][0], "app.py:21 request.args")
        self.assertIn("app.py:22 -> find_user(arg 0)", sqli["flow"])
        self.assertTrue(sqli["flow"][-1].startswith("db.py:7 SINK"))
        code = next(r for r in rs if r["file_path"] == "app.py" and
                    r["class"] == "code")
        self.assertEqual(code["flow"][0], "helpers.py:11 request.args")

    def test_never_executes_target_code(self):
        with tempfile.TemporaryDirectory() as td:
            canary = Path(td) / "imported.flag"
            (Path(td) / "evil.py").write_text(
                "from flask import request\nimport os\n"
                f"open({str(canary)!r}, 'w').write('x')\n"
                "os.system(request.args['c'])\n", encoding="utf-8")
            code, rs, _ = self._run(Path(td))
            self.assertFalse(canary.exists(), "target code was executed")
            self.assertEqual([r["class"] for r in rs], ["cmdi"])

    def test_crlf_and_broken_files(self):
        with tempfile.TemporaryDirectory() as td:
            src = (FIX / "taint_vuln" / "helpers.py").read_bytes()
            (Path(td) / "helpers.py").write_bytes(src.replace(b"\n",
                                                              b"\r\n"))
            (Path(td) / "broken.py").write_text("def x(:\n", "utf-8")
            with tempfile.TemporaryDirectory() as td2:
                out = Path(td2) / "t.json"
                run_main(taint_engine.main, ["--repo", td, "--out", str(out)])
                doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["data"]["parse_errors"],
                             ["broken.py: SyntaxError"])

    def test_fail_closed_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(self._run(Path(td) / "nope")[0], 2)
            self.assertEqual(self._run(Path(td))[0], 2)  # no source files
            self.assertEqual(self._run(FIX / "taint_vuln", "--lang",
                                       "cobol")[0], 2)

    def test_deterministic(self):
        a = self._run(FIX / "taint_vuln")[1]
        b = self._run(FIX / "taint_vuln")[1]
        self.assertEqual([r["id"] for r in a], [r["id"] for r in b])


class ApiFuzzLabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = fuzz_app.start()
        cls._td = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._td.name)
        cls.spec = str(FIX / "fuzz_openapi.json")
        out, corpus = cls.tmp / "fuzz.json", cls.tmp / "corpus.jsonl"
        posts_before = cls.srv.posts
        cls.code, _, _ = run_main(api_fuzz_lab.main, [
            "--spec", cls.spec, "--base-url", cls.base, "--max-requests",
            "2000", "--rps", "500", "--slow-ms", "300", "--out", str(out),
            "--corpus-out", str(corpus)], {"LAB": "1"})
        cls.rows = rows(out)
        cls.meta = json.loads(out.read_text(encoding="utf-8"))["data"]
        cls.corpus = corpus
        cls.posts = cls.srv.posts - posts_before

    @classmethod
    def tearDownClass(cls):
        fuzz_app.stop(cls.srv)
        cls._td.cleanup()

    def _by_op(self):
        return {(r["title"].split(": ", 1)[1].split(" param")[0],
                 r["kind"]): r for r in self.rows}

    def test_every_fragile_route_found_and_reproduced(self):
        got = self._by_op()
        expected = {("GET /crash", "connection-drop"),
                    ("GET /greet", "template-eval"),
                    ("GET /items/{item_id}", "server-error"),
                    ("GET /search", "server-error"),
                    ("GET /slow", "slow-response")}
        self.assertEqual(set(got), expected)
        self.assertTrue(all(r["verdict"] == 2 for r in self.rows))
        self.assertEqual(got[("GET /search", "server-error")]["cwe"],
                         "CWE-89")
        self.assertEqual(self.code, 1)

    def test_fp_controls_stay_quiet(self):
        titles = " ".join(r["title"] for r in self.rows)
        for route in ("/safe/", "/echo", "/docs-page", "/flaky", "/orders"):
            self.assertNotIn(route, titles)
        self.assertEqual(self.meta["skipped_ops"][0]["op"], "GET /flaky")
        self.assertEqual(self.posts, 0, "POST must not be sent by default")
        self.assertIsNone(self.meta["stopped"])

    def test_budget_and_corpus(self):
        self.assertLessEqual(self.meta["requests"], 2000)
        lines = self.corpus.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), len(self.rows))

    def test_gate_refuses_before_any_request(self):
        before = self.srv.hits
        out = self.tmp / "refused.json"
        for env in ({}, {"LAB": "0"}):
            code, _, err = run_main(api_fuzz_lab.main, [
                "--spec", self.spec, "--base-url", self.base, "--out",
                str(out)], env)
            self.assertEqual(code, 2)
        self.assertEqual(self.srv.hits, before)
        self.assertFalse(out.exists())

    def test_loopback_only_even_with_remote_ack(self):
        code, _, err = run_main(api_fuzz_lab.main, [
            "--spec", self.spec, "--base-url", "http://192.0.2.10/",
            "--out", str(self.tmp / "r.json")],
            {"LAB": "1", "LAB_REMOTE_ACK": "own staging, ticket SEC-142"})
        self.assertEqual(code, 2)
        self.assertIn("loopback-only", err)

    def test_post_requires_explicit_opt_in(self):
        before = self.srv.posts
        run_main(api_fuzz_lab.main, [
            "--spec", self.spec, "--base-url", self.base, "--methods",
            "post", "--max-requests", "40", "--rps", "500", "--out",
            str(self.tmp / "p.json")], {"LAB": "1"})
        self.assertGreater(self.srv.posts, before)

    def test_bad_spec_fail_closed(self):
        bad = self.tmp / "bad.json"
        bad.write_text('{"openapi": "3.0.0"}', encoding="utf-8")
        for spec in (str(bad), str(self.tmp / "missing.json")):
            code, _, _ = run_main(api_fuzz_lab.main, [
                "--spec", spec, "--base-url", self.base, "--out",
                str(self.tmp / "b.json")], {"LAB": "1"})
            self.assertEqual(code, 2)

    def test_pipeline_fuzz_corpus_into_crash_triage(self):
        out = self.tmp / "ct.json"
        code, _, _ = run_main(crash_triage.main, [
            "--input", str(self.corpus), "--out", str(out),
            "--fail-on", "none"])
        rs = rows(out)
        item = [r for r in rs if r["frames"] == ["get_item@api.py"]]
        self.assertEqual(len(item), 1)
        self.assertEqual(item[0]["verdict"], 2)  # fuzzer reproduced it


class ExploitBehaviorHuntTest(unittest.TestCase):
    T = FIX / "telemetry"

    def _run(self, *args):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "h.json"
            code, so, se = run_main(ebh.main, [*args, "--out", str(out),
                                               "--fail-on", "none"])
            if not out.exists():
                return code, [], {}, se
            doc = json.loads(out.read_text(encoding="utf-8"))
            return code, doc["findings"], doc["data"], se

    def _checks(self, rs):
        out = {}
        for r in rs:
            out[r["check"]] = out.get(r["check"], 0) + 1
        return out

    def test_intrusion_timeline_with_baseline(self):
        _, rs, meta, _ = self._run("--events", str(self.T / "attack.jsonl"),
                                   "--baseline",
                                   str(self.T / "baseline.jsonl"))
        self.assertEqual(self._checks(rs), {
            "server-spawns-shell": 1, "exec-from-writable": 1,
            "novel-lineage": 1, "novel-egress": 1,
            "exploitation-chain": 2})
        chain = [r for r in rs if r["check"] == "exploitation-chain"]
        self.assertTrue(all(r["severity"] == "critical" for r in chain))

    def test_windows_sysmon(self):
        _, rs, _, _ = self._run("--events",
                                str(self.T / "windows_sysmon.xml"))
        self.assertEqual(self._checks(rs), {
            "server-spawns-shell": 1, "db-spawns-shell": 1,
            "exploitation-chain": 1})
        self.assertNotIn("explorer", json.dumps(rs).lower())

    def test_fp_control_benign_activity(self):
        for extra in ([], ["--baseline", str(self.T / "baseline.jsonl")]):
            _, rs, meta, _ = self._run("--events",
                                       str(self.T / "benign.jsonl"), *extra)
            self.assertEqual(rs, [], extra)
            self.assertTrue(meta["notes"])  # gaps stated, not "clean"

    def test_allow_pair_suppresses(self):
        _, rs, _, _ = self._run("--events", str(self.T / "attack.jsonl"),
                                "--allow-pair", "java>sh")
        self.assertNotIn("server-spawns-shell", self._checks(rs))

    def test_xml_with_dtd_refused(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "x.xml"
            f.write_text('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a '
                         '"aaaa">]><Events>&a;</Events>', encoding="utf-8")
            code, rs, _, err = self._run("--events", str(f))
            self.assertEqual(code, 2)
            self.assertIn("XXE", err)

    def test_fail_closed_on_nothing_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "e.jsonl"
            f.write_text("not json\n{\"type\": \"other\"}\n", "utf-8")
            self.assertEqual(self._run("--events", str(f))[0], 2)
            self.assertEqual(self._run("--events",
                                       str(Path(td) / "nope"))[0], 2)

    def test_external_address_logic(self):
        self.assertTrue(ebh.is_public("203.0.113.9"))
        self.assertTrue(ebh.is_public("8.8.8.8"))
        for ip in ("10.1.2.3", "172.20.0.1", "192.168.1.1", "127.0.0.1",
                   "169.254.169.254", "fd00::1", "not-an-ip"):
            self.assertFalse(ebh.is_public(ip), ip)


class CrashTriageTest(unittest.TestCase):
    C = FIX / "crashes"

    def _run(self, *args):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "c.json"
            code, so, se = run_main(crash_triage.main, [
                *args, "--out", str(out), "--fail-on", "none"])
            return code, (rows(out) if out.exists() else [])

    def test_buckets_ranked_and_deduplicated(self):
        code, rs = self._run("--dir", str(self.C))
        self.assertEqual(len(rs), 9)
        self.assertEqual(rs[0]["class"], "heap-buffer-overflow-write")
        self.assertEqual(rs[0]["count"], 2)  # two builds, one bug
        self.assertEqual(rs[0]["severity"], "critical")
        uaf = next(r for r in rs if r["class"] == "use-after-free")
        self.assertEqual(uaf["frames"], ["session_touch@session.c",
                                         "handle_packet@server.c"])
        go = next(r for r in rs if r["engine"] == "go")
        self.assertEqual(go["frames"][0], "main.(*Store).Get@store.go")
        py = next(r for r in rs if r["frames"] == ["get_item@api.py"])
        self.assertEqual((py["count"], py["verdict"]), (3, 2))

    def test_fp_control_prose_is_not_a_crash(self):
        code, rs = self._run("--input",
                             str(FIX / "not_crashes.log"))
        self.assertEqual((code, rs), (2, []))

    def test_crlf_identical(self):
        with tempfile.TemporaryDirectory() as td:
            for f in self.C.iterdir():
                shutil.copy(f, td)
                p = Path(td) / f.name
                p.write_bytes(p.read_bytes().replace(b"\n", b"\r\n"))
            a = [r["bucket"] for r in self._run("--dir", td)[1]]
        b = [r["bucket"] for r in self._run("--dir", str(self.C))[1]]
        self.assertEqual(sorted(a), sorted(b))

    def test_python_traceback_not_split_by_last_line(self):
        reps = crash_triage.split_reports(
            (self.C / "python.log").read_text(encoding="utf-8"))
        self.assertEqual(len(reps), 4)
        self.assertTrue(all(r.startswith("Traceback") for r in reps))

    def test_fail_closed_inputs(self):
        self.assertEqual(self._run()[0], 2)
        self.assertEqual(self._run("--dir", str(self.C / "nope"))[0], 2)


if __name__ == "__main__":
    unittest.main()
