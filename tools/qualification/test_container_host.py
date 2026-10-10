import unittest
from container_host import SUCCESS, verdict


class ContainerOracleTests(unittest.TestCase):
    def test_complete_success_requires_exact_marker_and_success_exit(self):
        self.assertTrue(verdict(0, SUCCESS + "\n", "", None))
        for code, stdout in ((1, SUCCESS), (0, "OSCORE: received all 199 bytes"), (0, SUCCESS + "\n" + SUCCESS)):
            self.assertFalse(verdict(code, stdout, "", None))

    def test_crash_or_wrong_refusal_never_passes(self):
        self.assertTrue(verdict(1, "", "Error: --alloc requires building with features", "--alloc requires building"))
        for code, stdout, stderr in ((0, "", "usage"), (137, "", "usage"), (1, SUCCESS, "usage"), (1, "", "socket failed")):
            self.assertFalse(verdict(code, stdout, stderr, "usage"))


if __name__ == "__main__":
    unittest.main()
