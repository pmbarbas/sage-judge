import json, unittest, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from sage_judge import __version__
from sage_judge.api import adjudicate, verify
from sage_judge.errors import AdjudicationError

class ReleaseExampleTests(unittest.TestCase):
    def load(self, name):
        a = ROOT / "examples" / (name + ".json")
        b = ROOT / "src/sage_judge/examples" / (name + ".json")
        self.assertEqual(a.read_bytes(), b.read_bytes())
        return json.loads(a.read_text())
    def test_release_identity(self):
        self.assertEqual(__version__, "0.1.0")
    def test_published_example_outcomes_and_replay(self):
        for name, posture, verdict in [("inspection_positive", "SUPPORTED", "KEEP"), ("inspection_unknown", "UNKNOWN", "REVIEW"), ("inspection_conflict", "BOTH", "REVIEW")]:
            with self.subTest(name=name):
                x = self.load(name)
                r = adjudicate(x["bundle"], x["trusted_registry"], x["policy"], x["limits"])
                self.assertEqual((r["proof_posture"], r["business_verdict"], r["execution_authority"]), (posture, verdict, "NONE"))
                self.assertTrue(verify(r, x["trusted_registry"], x["bundle"], x["policy"])["valid"])
    def test_unsupported_example_refuses(self):
        x = self.load("unsupported_dependency")
        with self.assertRaisesRegex(AdjudicationError, "UNSUPPORTED_RULE_DEPENDENCY_SCOPE"):
            adjudicate(x["bundle"], x["trusted_registry"], x["policy"], x["limits"])
