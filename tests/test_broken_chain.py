"""Regression tests for presentations whose root mandate is damaged (issue #1).

Each test copies the committed vectors to a temporary directory, changes the
00-baseline presentation, and runs check.validate on it. The checker must return
a Validation Result with outcome invalid, never raise.

Usage: python -m unittest discover -s tests
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join("cases", "00-baseline")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


check = load_module("check_under_test", os.path.join(ROOT, "check.py"))


def flip_signature_char(jws):
    """Change one character in the middle of the signature so the bytes change."""
    head, payload, sig = jws.split(".")
    i = len(sig) // 2
    sig = sig[:i] + ("A" if sig[i] != "A" else "B") + sig[i + 1:]
    return ".".join((head, payload, sig))


class BrokenRootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        for name in ("cases", "keys", "profile", "trust-anchors.json"):
            src, dst = os.path.join(ROOT, name), os.path.join(self.tmp, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy(src, dst)
        self.cdir = os.path.join(self.tmp, BASELINE)
        self.pres_path = os.path.join(self.cdir, "presentation.json")
        self.pres = json.load(open(self.pres_path))
        self.root_jws = open(os.path.join(self.cdir, "root-mandate.jws")).read().strip()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_case(self):
        with open(self.pres_path, "w") as f:
            json.dump(self.pres, f)
        result, _ = check.validate(self.tmp, self.cdir)
        return result

    def codes(self, result):
        return [e["code"] for e in result["errors"]]

    def test_root_signature_changed_breaks_parent_link(self):
        # The case in issue #1: one character of the root signature changed. The
        # root's digest no longer matches the sub-mandate's parent.dig.
        bad = flip_signature_char(self.root_jws)
        self.pres["mandate_evidence"] = [bad if x == self.root_jws else x
                                         for x in self.pres["mandate_evidence"]]
        result = self.run_case()
        self.assertEqual(result["outcome"], "invalid")
        self.assertEqual(result["authority"], "not_evaluated")
        self.assertIn("chain_broken", self.codes(result))
        for alt in result["alternatives"]:
            self.assertNotIn("sum_max", [o["type"] for o in alt["obligations"]])

    def test_root_not_presented(self):
        # Parent link broken because the root is missing from mandate_evidence.
        self.pres["mandate_evidence"] = [x for x in self.pres["mandate_evidence"]
                                         if x != self.root_jws]
        result = self.run_case()
        self.assertEqual(result["outcome"], "invalid")
        self.assertEqual(result["authority"], "not_evaluated")
        self.assertIn("chain_broken", self.codes(result))

    def test_root_signature_invalid_with_intact_link(self):
        # A bad root signature that the sub-mandate still links to: the sub-mandate
        # is re-signed with the published test key over the damaged root, so the
        # chain is complete and step 4 has to catch the signature.
        sys.path.insert(0, ROOT)
        try:
            gen = load_module("generate_for_test", os.path.join(ROOT, "generate.py"))
        finally:
            sys.path.remove(ROOT)
        bad_root = flip_signature_char(self.root_jws)
        sub = gen.sign(gen.hdr("mandate+jwt", jwk=dict(gen.KEYS["ai-treasury-1"]["pub"])),
                       gen.sub_payload(bad_root), "ai-treasury-1")
        self.pres["subject_token"] = sub
        self.pres["mandate_evidence"] = [bad_root if x == self.root_jws else x
                                         for x in self.pres["mandate_evidence"]]
        result = self.run_case()
        self.assertEqual(result["outcome"], "invalid")
        self.assertIn({"code": "signature_invalid", "artifact": {"dig": check.dig(bad_root.encode("ascii"))}},
                      result["errors"])
        self.assertNotIn("chain_broken", self.codes(result))


if __name__ == "__main__":
    unittest.main()
