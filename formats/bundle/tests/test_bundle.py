"""python3 -m unittest discover -s formats/bundle/tests -p 'test_*.py'"""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import corpus  # noqa: E402
import lighthouse_bundle as lb  # noqa: E402


class CorpusTest(unittest.TestCase):
    def test_every_corpus_case_returns_its_expected_code(self):
        with tempfile.TemporaryDirectory() as out:
            expected = corpus.main(out)
            self.assertGreaterEqual(len(expected), 50)
            mismatches = []
            for name, code in sorted(expected.items()):
                try:
                    lb.verify(os.path.join(out, name))
                    got = "OK"
                except lb.BundleError as error:
                    got = error.code
                if got != code:
                    mismatches.append(f"{name}: expected {code}, got {got}")
            self.assertEqual(mismatches, [])


class CreateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.src = os.path.join(self.root, "export")
        os.makedirs(os.path.join(self.src, "photos"))
        with open(os.path.join(self.src, "backup.json"), "wb") as handle:
            handle.write(b'{"items": 3}\n')
        with open(os.path.join(self.src, "photos", "a.jpg"), "wb") as handle:
            handle.write(os.urandom(5000))

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, name="out.zip", **kwargs):
        args = dict(app="omnilist", version="1.2.3", payload_schema="omnilist.backup.v3",
                    reality="unknown", created="2026-10-14T12:00:00Z")
        args.update(kwargs)
        path = os.path.join(self.root, name)
        lb.create(path, [self.src], **args)
        return path

    def test_round_trip_lists_every_file_under_payload(self):
        path = self.make(omissions=[{"what": "audio", "why": "too large"}],
                         source={"id": "workspace-1"}, commit="abc1234", repository="LighthouseRobotics/omnilist")
        report = lb.verify(path)
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["files"], 2)
        self.assertEqual(report["payloadBytes"], 5000 + 13)
        self.assertEqual(report["producer"]["commit"], "abc1234")
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(sorted(archive.namelist()),
                             ["lighthouse-bundle.json", "payload/backup.json", "payload/photos/a.jpg"])
            manifest = json.loads(archive.read(lb.MANIFEST))
        self.assertEqual([f["path"] for f in manifest["files"]], ["payload/backup.json", "payload/photos/a.jpg"])

    def test_output_is_reproducible_for_the_same_inputs_and_time(self):
        first = self.make("one.zip")
        second = self.make("two.zip")
        with open(first, "rb") as a, open(second, "rb") as b:
            self.assertEqual(hashlib.sha256(a.read()).hexdigest(), hashlib.sha256(b.read()).hexdigest())

    def test_existing_output_is_not_replaced_without_overwrite(self):
        path = self.make()
        with self.assertRaises(FileExistsError):
            self.make()
        self.make(overwrite=True)
        lb.verify(path)

    def test_symlinked_input_is_refused(self):
        os.symlink("/etc/hostname", os.path.join(self.src, "link"))
        with self.assertRaises(lb.BundleError) as caught:
            self.make()
        self.assertEqual(caught.exception.code, "E_PATH")
        self.assertFalse(os.path.exists(os.path.join(self.root, "out.zip")))

    def test_invalid_manifest_fields_are_refused_before_writing(self):
        with self.assertRaises(lb.BundleError) as caught:
            self.make(app="Bad App")
        self.assertEqual(caught.exception.code, "E_MANIFEST")
        self.assertEqual([n for n in os.listdir(self.root) if n.endswith(".zip")], [])

    def test_case_colliding_inputs_are_refused(self):
        with open(os.path.join(self.src, "Backup.json"), "wb") as handle:
            handle.write(b"{}")
        if len({n.lower() for n in os.listdir(self.src)}) == len(os.listdir(self.src)):
            self.skipTest("case-insensitive filesystem")
        with self.assertRaises(lb.BundleError) as caught:
            self.make()
        self.assertEqual(caught.exception.code, "E_PATH")

    def test_stream_input_and_expected_checksum(self):
        path = self.make()
        with open(path, "rb") as handle:
            data = handle.read()
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(lb.verify(io.BytesIO(data), expected_sha256=digest)["bundleSha256"], digest)
        with self.assertRaises(lb.BundleError) as caught:
            lb.verify(io.BytesIO(data), expected_sha256="0" * 64)
        self.assertEqual(caught.exception.code, "E_CHECKSUM")

    def test_limits_reject_before_member_reads(self):
        path = self.make()
        for limits, code in (({"entries": 2}, "E_LIMIT"), ({"archive_bytes": 50}, "E_SIZE"),
                             ({"directory_bytes": 10}, "E_LIMIT"), ({"manifest_bytes": 10}, "E_LIMIT"),
                             ({"total_uncompressed": 100}, "E_LIMIT")):
            with self.subTest(limits=limits):
                with self.assertRaises(lb.BundleError) as caught:
                    lb.verify(path, limits=limits)
                self.assertEqual(caught.exception.code, code)


class InteropTest(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("zip"), "Info-ZIP not installed")
    def test_bundle_built_by_info_zip_verifies(self):
        import subprocess
        with tempfile.TemporaryDirectory() as root:
            stage = os.path.join(root, "stage")
            os.makedirs(os.path.join(stage, "payload", "sub"))
            data = {"payload/a.txt": b"hello\n", "payload/sub/r.bin": os.urandom(300000)}
            for path, body in data.items():
                with open(os.path.join(stage, path), "wb") as handle:
                    handle.write(body)
            with open(os.path.join(stage, lb.MANIFEST), "wb") as handle:
                handle.write(corpus.encode(corpus.manifest_for(data)))
            out = os.path.join(root, "iz.zip")
            subprocess.run(["zip", "-qr", out, lb.MANIFEST, "payload"], cwd=stage, check=True)
            report = lb.verify(out)
            self.assertEqual((report["status"], report["files"]), ("verified", 2))


class CliTest(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = lb.main(list(argv))
        return code, out.getvalue()

    def test_create_then_verify_and_reject(self):
        with tempfile.TemporaryDirectory() as root:
            src = os.path.join(root, "data.csv")
            with open(src, "w") as handle:
                handle.write("a,b\n1,2\n")
            out = os.path.join(root, "b.zip")
            code, text = self.run_cli("create", "--out", out, "--app", "manta", "--version", "0.1",
                                      "--payload-schema", "manta.photo-package.v1", "--reality", "synthetic",
                                      "--omission", "originals=not selected", "--created", "2026-10-14T00:00:00Z", src)
            self.assertEqual(code, 0, text)
            self.assertEqual(json.loads(text)["files"], 1)
            code, text = self.run_cli("verify", out)
            self.assertEqual((code, json.loads(text)["status"]), (0, "verified"))
            code, text = self.run_cli("verify", out, "--sha256", "f" * 64)
            self.assertEqual((code, json.loads(text)["code"]), (1, "E_CHECKSUM"))
            code, _ = self.run_cli("create", "--out", out, "--app", "manta", "--version", "0.1",
                                   "--payload-schema", "x", src)
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
