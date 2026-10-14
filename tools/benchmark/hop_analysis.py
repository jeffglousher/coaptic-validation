"""Correlate bounded complete-operation traces without subtracting clock epochs.

This consumes the finite ESPHome timing diagnostic, not comparative benchmark
results. Service spans include preemption and instrumentation. The round-trip
residual includes delivery, queueing and host polling; it is not radio airtime.
"""
import argparse
import collections
import json
import statistics
from pathlib import Path

LIMIT = 16 * 1024 * 1024
PATHS = {"identity": 32, "test": 7, "large": 2000}
STAGES = ("prepare_ns", "poll_ns", "checkpoint_ns", "take_ns", "verify_ns", "sleep_ns")


def number(value, maximum=10**15):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid bounded integer")
    return value


def read(path):
    path = Path(path)
    if path.stat().st_size > LIMIT:
        raise ValueError("input size bound")
    return path.read_text(encoding="utf8")


def event(row, device=False):
    if device:
        values = [row["kind"], number(row["at_us"]) * 1000,
                  number(row["duration_us"]) * 1000, row["bytes"], row["mid"]]
        if type(row["result"]) is not int or row["result"] != 1:
            raise ValueError("device event failure")
    else:
        if not isinstance(row, list) or len(row) != 5:
            raise ValueError("event shape")
        values = row
    values = [number(value) for value in values]
    kind, start, duration, size, mid = values
    if kind not in (1, 2, 3, 4, 5, 6) or size > 65535 or mid > 65536:
        raise ValueError("event bounds")
    if kind in (1, 2) and mid == 65536:
        raise ValueError("packet MID missing")
    return dict(kind=kind, start=start, duration=duration, end=start + duration, bytes=size, mid=mid)


def server_events(report):
    if "end" in report:
        end = report["end"]
        rows = report["events"]
        if end["overflow"] is not False or number(end["events"], 512) != len(rows):
            raise ValueError("device trace incomplete")
        if [number(r["index"], 511) for r in rows] != list(range(len(rows))):
            raise ValueError("device trace index gap")
        if any(r["run_id"] != end["run_id"] for r in rows):
            raise ValueError("device run mismatch")
        return [event(r, True) for r in rows]
    if report.get("passed") is not True or report.get("overflow") is not False:
        raise ValueError("loopback server refused")
    if len(report["events"]) > 512:
        raise ValueError("server trace bound")
    return [event(r) for r in report["events"]]


def packets(events, kind):
    result = {}
    for row in events:
        if row["kind"] == kind:
            if row["mid"] in result:
                raise ValueError("retransmitted/ambiguous MID requires separate analysis")
            result[row["mid"]] = row
    return result


def summarize(values):
    return dict(samples=len(values), mean_us=statistics.mean(values) / 1000,
                median_us=statistics.median(values) / 1000,
                min_us=min(values) / 1000, max_us=max(values) / 1000)


def analyze(client, server):
    if not isinstance(client, list) or not client or len(client) > 100:
        raise ValueError("client report bounds")
    final = client[-1]
    if final.get("case") != "timing_campaign" or final.get("passed") is not True or number(final.get("completed"), 24) != 24:
        raise ValueError("client campaign incomplete")
    operations = [r for r in client if r.get("case") == "complete_operation"]
    if len(operations) != 24 or collections.Counter(r["path"] for r in operations) != {p: 8 for p in PATHS}:
        raise ValueError("missing operation coverage")
    if {(r["path"], number(r["iteration"], 7)) for r in operations} != {(p, i) for p in PATHS for i in range(8)}:
        raise ValueError("duplicate or missing operation identity")
    if "end" in server and server["end"]["run_id"] != final.get("run_id"):
        raise ValueError("host/device run mismatch")
    if "run_id" in server and server["run_id"] != final.get("run_id"):
        raise ValueError("host/server run mismatch")
    se = server_events(server)
    sr, st = packets(se, 1), packets(se, 2)
    if len(sr) != 32 or set(sr) != set(st):
        raise ValueError("server packet coverage")
    all_client_send, all_client_recv = set(), set()
    observations = []
    for row in operations:
        if row.get("passed") is not True or number(row["bytes"], 2000) != PATHS[row["path"]]:
            raise ValueError("unverified representation")
        start = number(row["start_ns"])
        elapsed = number(row["elapsed_ns"])
        stages = {k: number(row[k]) for k in STAGES}
        if sum(stages.values()) > elapsed:
            raise ValueError("top-level intervals overlap")
        if len(row["events"]) > 128:
            raise ValueError("client event bound")
        ce = [event(e) for e in row["events"]]
        if any(e["start"] < start or e["end"] > start + elapsed for e in ce):
            raise ValueError("client event outside operation")
        cs, cr = packets(ce, 2), packets(ce, 1)
        expected = 2 if row["path"] == "large" else 1
        if len(cs) != expected or set(cs) != set(cr):
            raise ValueError("complete hop coverage")
        if all_client_send.intersection(cs) or all_client_recv.intersection(cr):
            raise ValueError("ambiguous campaign MID")
        all_client_send.update(cs)
        all_client_recv.update(cr)
        hops = []
        for mid in cs:
            if mid not in sr or cs[mid]["bytes"] != sr[mid]["bytes"] or cr[mid]["bytes"] != st[mid]["bytes"]:
                raise ValueError("host/server datagram mismatch")
            receive, send = sr[mid], st[mid]
            if send["start"] < receive["end"] or cr[mid]["start"] < cs[mid]["end"]:
                raise ValueError("causal event ordering")
            service = send["end"] - receive["start"]
            round_trip = cr[mid]["end"] - cs[mid]["start"]
            if service > round_trip:
                raise ValueError("service exceeds corresponding round trip")
            nested = [e for e in se if e["kind"] in (3, 4) and e["start"] >= receive["end"] and e["end"] <= send["start"]]
            if [e["kind"] for e in nested] != [3, 4, 3] or any(a["end"] > b["start"] for a, b in zip(nested, nested[1:])):
                raise ValueError("durable barrier order/overlap")
            reads = sum(e["duration"] for e in nested if e["kind"] == 3)
            commits = sum(e["duration"] for e in nested if e["kind"] == 4)
            protocol = service - reads - commits - receive["duration"] - send["duration"]
            if protocol < 0 or sum(e["kind"] == 4 for e in nested) != 1 or sum(e["kind"] == 3 for e in nested) != 2:
                raise ValueError("durable service coverage")
            hops.append(dict(mid=mid, round_trip_ns=round_trip, service_ns=service,
                             receive_ns=receive["duration"], send_ns=send["duration"],
                             state_read_ns=reads, state_commit_ns=commits,
                             protocol_and_unobserved_ns=protocol,
                             transport_and_host_wait_residual_ns=round_trip - service,
                             before_first_state_read_ns=nested[0]["start"] - receive["end"],
                             after_last_state_read_ns=send["start"] - nested[-1]["end"]))
        observations.append(dict(path=row["path"], iteration=row["iteration"], elapsed_ns=elapsed,
                                 stages=stages, control_and_instrumentation_ns=elapsed - sum(stages.values()), hops=hops))
    if all_client_send != set(sr) or all_client_recv != set(st):
        raise ValueError("server trace missing or extra traffic")
    summary = []
    for path in PATHS:
        subset = [r for r in observations if r["path"] == path]
        item = dict(path=path, bytes=PATHS[path], complete_operation=summarize([r["elapsed_ns"] for r in subset]),
                    client_stages={k: summarize([r["stages"][k] for r in subset]) for k in STAGES})
        for field in ("round_trip_ns", "service_ns", "receive_ns", "send_ns", "state_read_ns", "state_commit_ns", "protocol_and_unobserved_ns", "transport_and_host_wait_residual_ns", "before_first_state_read_ns", "after_last_state_read_ns"):
            item[field] = summarize([sum(h[field] for h in r["hops"]) for r in subset])
        summary.append(item)
    return dict(passed=True, schema="coaptic-correlated-hops/1", complete_operations=24,
                request_response_exchanges=32, datagrams=64,
                summary=summary, operations=observations,
                limitations=["instrumented elapsed-time spans include preemption and tracing overhead",
                             "initialization and sender refills remain separate from read operations",
                             "parent and nested intervals must not be added together",
                             "round-trip residual combines transport, queues and host scheduling/polling",
                             "independent clock epochs are never subtracted; no one-way/radio claim",
                             "protocol residual includes decrypt, replay validation, record encoding, handler and encrypt; not individually timed",
                             "eight observations per body per session do not qualify tails or throughput"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = analyze([json.loads(line) for line in read(args.client).splitlines()], json.loads(read(args.server)))
    except (ValueError, KeyError, TypeError, OSError) as error:
        report = dict(passed=False, schema="coaptic-correlated-hops/1", reason=type(error).__name__ + ": " + str(error))
    with args.output.open("x", encoding="utf8") as output:
        json.dump(report, output, indent=2)
    print(json.dumps({k: v for k, v in report.items() if k not in ("operations", "summary")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
