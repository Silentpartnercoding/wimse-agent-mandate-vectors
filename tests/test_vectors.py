"""Run check.py on the committed vectors and confirm generate.py reproduces them byte for byte.

Usage: python -m unittest discover -s tests
"""

import filecmp
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATED = ["cases", "keys", "profile", "trust-anchors.json"]


def compare_trees(a, b):
    """Return a list of relative paths that differ or exist on one side only."""
    out = []
    cmp = filecmp.dircmp(a, b)
    out += [os.path.join(a, n) for n in cmp.left_only + cmp.right_only]
    for name in cmp.common_files:
        pa, pb = os.path.join(a, name), os.path.join(b, name)
        with open(pa, "rb") as fa, open(pb, "rb") as fb:
            if fa.read() != fb.read():
                out.append(pa)
    for name in cmp.common_dirs:
        out += compare_trees(os.path.join(a, name), os.path.join(b, name))
    return out


class VectorTests(unittest.TestCase):
    def test_check_passes(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "check.py"), ROOT],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run([sys.executable, os.path.join(ROOT, "generate.py"), tmp],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            for name in GENERATED:
                a, b = os.path.join(ROOT, name), os.path.join(tmp, name)
                if os.path.isdir(a):
                    self.assertEqual(compare_trees(a, b), [], name)
                else:
                    with open(a, "rb") as fa, open(b, "rb") as fb:
                        self.assertEqual(fa.read(), fb.read(), name)
            self.assertEqual(sorted(os.listdir(tmp)), sorted(GENERATED))

    def test_generated_check_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, os.path.join(ROOT, "generate.py"), tmp], check=True,
                           capture_output=True)
            r = subprocess.run([sys.executable, os.path.join(ROOT, "check.py"), tmp],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
