import unittest

from build_source import LOCKS, build_source, verify_report_source


LIBRARY = "1" * 40
SUITE = "2" * 40


class BuildSourceTests(unittest.TestCase):
    def fixture(self):
        return dict(source=LIBRARY, suite_source=SUITE, dirty=False, suite_dirty=False,
                    suite_locks={name: "3" * 64 for name in LOCKS})

    def test_clean_exact_candidate_is_retained_and_recordable(self):
        report = build_source(LIBRARY, self.fixture)
        self.assertEqual(report, self.fixture())
        verify_report_source(report, LIBRARY, SUITE)

    def test_build_refuses_stale_dirty_or_unidentified_sources(self):
        for changes in (dict(source="4" * 40), dict(dirty=True),
                        dict(suite_dirty=True), dict(suite_source="main")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build_source(LIBRARY, lambda: self.fixture() | changes)
        for invalid in ("main", "a" * 39, "A" * 40, None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                build_source(invalid, self.fixture)

    def test_capture_refuses_stale_or_missing_provenance(self):
        for changes in (dict(source="4" * 40), dict(suite_source="4" * 40),
                        dict(dirty=True), dict(suite_dirty=True), dict(dirty=None),
                        dict(suite_locks={}), dict(suite_locks=None),
                        dict(suite_locks={name: "malformed" for name in LOCKS})):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_report_source(self.fixture() | changes, LIBRARY, SUITE)
        with self.assertRaises(ValueError):
            verify_report_source({}, LIBRARY, SUITE)
