"""Correlate a source-bound Call trace and device Wi-Fi receipt.

This checks temporal overlap; an isolated slow Call or unrelated recovery log
cannot pass. Clock offsets are bracketed by a matched fast request round trip.
"""
import re


def grade_reconnect(line, rows, run_id):
    identifiers = re.findall(r"\brun_id=([0-9a-f]{32})", line)
    assert identifiers and all(value == run_id for value in identifiers)
    fields = dict(re.findall(r"([a-z_]+)=([^ ]+)", line))
    assert fields["run_id"] == run_id and fields["connected"] == "true"
    assert rows[-1]["passed"] and rows[-1]["run_id"] == run_id
    calls = [row for row in rows if row.get("case") == "reconnect_call"]
    by_token = {row["token"]: row for row in calls}
    assert len(by_token) == len(calls) and 0 < len(calls) <= 128
    assert all(re.fullmatch(r"[0-9a-f]{16}", token) for token in by_token)
    assert all(row["identity_verified"] and row["start_ns"] >= 0 and row["elapsed_ns"] >= 0 for row in calls)
    disabled = int(fields["disabled_at_us"]) * 1000
    available = (int(fields["enabled_at_us"]) + int(fields["reconnect_us"])) * 1000
    assert 0 < disabled < available
    # Bound clock offset by causality: the matched MCU receive occurred between
    # host request preparation and authenticated response completion. Add 10ms
    # on both sides for clock-rate/anchor uncertainty over this finite campaign.
    # Only the first eligible receive of this firmware lifetime is admissible:
    # last/sample marks may instead be late duplicates after a completed Call.
    # The runner starts reconnect traffic before any other eight-byte-token I/O.
    for prefix in ("first",):
        calibration = by_token.get(fields.get(prefix + "_rx_token"))
        received = int(fields.get(prefix + "_rx_us", 0)) * 1000
        if not calibration or calibration["index"] != 0 or received <= 0 or calibration["elapsed_ns"] > 100_000_000:
            continue
        low = calibration["start_ns"] - received - 10_000_000
        high = calibration["start_ns"] + calibration["elapsed_ns"] - received + 10_000_000
        for index, call in enumerate(calls[:-1]):
            end = call["start_ns"] + call["elapsed_ns"]
            fresh = calls[index + 1]
            if (call["elapsed_ns"] >= 500_000_000
                    and call["start_ns"] < low + available
                    and end > high + available
                    and fresh["elapsed_ns"] < 500_000_000
                    and fresh["identity_verified"]):
                return {"passed": True, "calibration_token": calibration["token"],
                        "clock_offset_low_ns": low, "clock_offset_high_ns": high,
                        "clock_uncertainty_ns": 10_000_000,
                        "delayed_call": call["index"], "fresh_call": fresh["index"],
                        "request_started": "before_disable" if call["start_ns"] < low + disabled else "not_proven_before_disable",
                        "scope": "same-App Call during interruption completes after connection observation"}
    raise AssertionError("no calibrated delayed Call overlaps the device interruption with fresh recovery")
