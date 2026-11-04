import copy
import json
import unittest

from read_campaign_records import MARKER, analyze, parse_capture


def fixture(io_mode="sync", security="unprotected"):
    protected = security == "durable-oscore"
    run_id = "a" * 32
    def record(words):
        return dict(run_id=run_id, mode=6 if protected else 7, protected=protected,
                    io_mode=io_mode, words=words + [0] * (16 - len(words)))
    records = [record([0, 100 if protected else 0, 32000, 4096, 128,
                       400 if protected else 0, 49152, 40, 1024, 112,
                       1 if io_mode == "async" else 0])]
    for iteration in range(8):
        for path, size in enumerate((32, 7, 2000)):
            start = (iteration * 3 + path) * 100_000
            records.append(record([2, iteration, path, size, start, 10_000,
                                   100, 1000, 100 if protected else 0, 100, 100, 4000, 2]))
    records.append(record([3, 1, 24, len(records)]))
    source = dict(core_revision="b" * 40, suite_revision="c" * 40, ota_sha256="d" * 64)
    bindings = dict(expected_run_id=run_id, expected_io_mode=io_mode,
                    expected_security=security, expected_source=source,
                    build=dict(passed=True, run_id=run_id, io_mode=io_mode, security=security, **source),
                    installation=dict(passed=True, run_id=run_id, ota_sha256=source["ota_sha256"]))
    return records, bindings


class ReadCampaignRecordsTests(unittest.TestCase):
    def test_both_native_modes_and_security_selections_have_same_24_reads(self):
        for mode in ("sync", "async"):
            for security in ("unprotected", "durable-oscore"):
                with self.subTest(mode=mode, security=security):
                    rows, bindings = fixture(mode, security)
                    result = analyze(rows, **bindings)
                    self.assertEqual((result["completed"], result["records"]), (24, 26))
                    self.assertEqual(result["io_mode"], mode)
                    self.assertEqual([r["samples"] for r in result["summary"]], [8, 8, 8])

    def test_raw_and_existing_capture_envelopes_decode_identically(self):
        rows, bindings = fixture("async")
        raw = "unrelated log\n" + "\n".join("[I] " + MARKER + json.dumps(r) for r in rows)
        capture = "\n".join(json.dumps(dict(kind="log", line=MARKER + json.dumps(r))) for r in rows)
        capture += "\n" + json.dumps(dict(kind="capture_complete", overflow=False, connections=1))
        self.assertEqual(parse_capture(raw), rows)
        self.assertEqual(parse_capture(capture), rows)
        colored = capture.replace(MARKER, "\\u001b[32m" + MARKER).replace(']}"', ']}\\u001b[0m"')
        self.assertEqual(parse_capture(colored), rows)
        self.assertTrue(analyze(parse_capture(capture), **bindings)["passed"])

    def test_original_count_identity_duration_and_layout_guards_refuse_then_recover(self):
        original, bindings = fixture("async", "durable-oscore")
        mutations = (
            lambda r: r.pop(), lambda r: r.append(copy.deepcopy(r[1])),
            lambda r: r[1]["words"].pop(), lambda r: r[1]["words"].__setitem__(1, 1),
            lambda r: r[1]["words"].__setitem__(2, 2), lambda r: r[1]["words"].__setitem__(3, 31),
            lambda r: r[2]["words"].__setitem__(4, 0), lambda r: r[1]["words"].__setitem__(5, 0),
            lambda r: r[1]["words"].__setitem__(5, 5_000_000_000),
            lambda r: r[1]["words"].__setitem__(6, 100_000),
            lambda r: r[1]["words"].__setitem__(12, 0), lambda r: r[1]["words"].__setitem__(12, 100001),
            lambda r: r[1]["words"].__setitem__(13, 1), lambda r: r[1]["words"].__setitem__(1, True),
            lambda r: r[1]["words"].__setitem__(5, 1.0), lambda r: r[1]["words"].__setitem__(4, -1),
            lambda r: r[-1]["words"].__setitem__(1, 0), lambda r: r[-1]["words"].__setitem__(3, 24),
            lambda r: r[0]["words"].__setitem__(2, 50000), lambda r: r[0]["words"].__setitem__(3, 2048),
            lambda r: r[0]["words"].__setitem__(4, 64), lambda r: r[0]["words"].__setitem__(5, 0),
            lambda r: r[0]["words"].__setitem__(6, 65536), lambda r: r[0]["words"].__setitem__(7, 49),
            lambda r: r[0]["words"].__setitem__(8, 2048), lambda r: r[0]["words"].__setitem__(9, 129),
            lambda r: r[0]["words"].__setitem__(11, 1),
        )
        for mutation in mutations:
            rows = copy.deepcopy(original)
            mutation(rows)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                analyze(rows, **bindings)
        self.assertTrue(analyze(original, **bindings)["passed"])

    def test_log_mode_word_mode_security_and_external_source_must_all_match(self):
        original, original_bindings = fixture("async", "durable-oscore")
        mutations = (
            lambda r, b: r[1].__setitem__("io_mode", "sync"),
            lambda r, b: r[0]["words"].__setitem__(10, 0),
            lambda r, b: r[1].__setitem__("run_id", "e" * 32),
            lambda r, b: r[1].__setitem__("mode", 7),
            lambda r, b: r[1].__setitem__("mode", True),
            lambda r, b: r[1].__setitem__("protected", False),
            lambda r, b: r[1].__setitem__("protected", 1),
            lambda r, b: b["build"].__setitem__("core_revision", "e" * 40),
            lambda r, b: b["build"].__setitem__("suite_revision", "e" * 40),
            lambda r, b: b["build"].__setitem__("ota_sha256", "e" * 64),
            lambda r, b: b["build"].__setitem__("run_id", "e" * 32),
            lambda r, b: b["build"].__setitem__("io_mode", "sync"),
            lambda r, b: b["build"].__setitem__("security", "unprotected"),
            lambda r, b: b["build"].__setitem__("passed", 1),
            lambda r, b: b["installation"].__setitem__("passed", False),
            lambda r, b: b["installation"].__setitem__("ota_sha256", "e" * 64),
            lambda r, b: b["installation"].__setitem__("run_id", "e" * 32),
            lambda r, b: b["expected_source"].__setitem__("core_revision", "bad"),
        )
        for mutation in mutations:
            rows, bindings = copy.deepcopy(original), copy.deepcopy(original_bindings)
            mutation(rows, bindings)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                analyze(rows, **bindings)

    def test_protected_refill_is_counted_separately_and_unprotected_refuses_it(self):
        rows, bindings = fixture("sync", "durable-oscore")
        reservation = copy.deepcopy(rows[0])
        reservation["words"] = [1, 2500] + [0] * 14
        rows.insert(1, reservation)
        rows[-1]["words"][3] += 1
        result = analyze(rows, **bindings)
        self.assertEqual((result["records"], result["sender_reservations"], result["sender_reservation_ns"]),
                         (27, 1, 2500))
        rows.insert(1, copy.deepcopy(reservation))
        rows[-1]["words"][3] += 1
        with self.assertRaises(ValueError):
            analyze(rows, **bindings)
        rows, bindings = fixture()
        reservation.update(mode=7, protected=False)
        rows.insert(1, reservation)
        rows[-1]["words"][3] += 1
        with self.assertRaises(ValueError):
            analyze(rows, **bindings)

    def test_malformed_capture_is_never_silently_skipped(self):
        for text in (MARKER + "{", MARKER + "[]", MARKER + "{} " + MARKER + "{}",
                     MARKER + '{"mode":6,"mode":7}',
                     json.dumps(dict(kind="connected", line=MARKER + "{}")),
                     json.dumps(dict(kind="log", line=MARKER + "{}")),
                     json.dumps(dict(kind="capture_complete", overflow=True, connections=1)),
                     json.dumps(dict(kind="capture_complete", overflow=False, connections=0)),
                     json.dumps(dict(kind="capture_complete", overflow=False, connections=True)),
                     json.dumps(dict(kind="capture_complete", overflow=False, connections=1)) + "\n"
                     + json.dumps(dict(kind="log", line=MARKER + "{}")),
                     "x" * (1024 * 1024 + 1)):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                parse_capture(text)


if __name__ == "__main__":
    unittest.main()
