"""Offline validation of bounded MCU UDP wall spans; never runs device work.



The wall interval is send-entry minus receive-return on the MCU's esp_timer

clock. It includes task preemption and RX observer work. It is not task CPU,

RTT, cache-miss cost, or a clean performance comparison.

"""

from __future__ import annotations

from collections import Counter

from dataclasses import dataclass

import argparse
import base64

import json

from pathlib import Path

import statistics



PACKET_BYTES = 1152

WIRE_BYTES = 90
MAX_ROWS = 96

EXPECTED_DATAGRAMS = 64

EXPECTED_IP = 3221225985

MARKERS = {"MCU_SPAN_BEGIN", "MCU_SPAN_SOCKET", "MCU_SPAN_STARTUP", "MCU_SPAN_NATIVE", "MCU_SPAN_PEER", "MCU_SPAN_NESTED", "MCU_SPAN_RESOURCES", "MCU_SPAN_STACK", "MCU_SPAN_PAIR", "MCU_SPAN_TIME", "MCU_SPAN_WIRE", "MCU_SPAN_COUNTS", "MCU_SPAN_END"}



class Refused(ValueError):

    pass



def require(condition, reason):

    if not condition:

        raise Refused(reason)



def integer(value, low=0, high=(1 << 63) - 1):

    require(type(value) is int and low <= value <= high, "invalid integer")

    return value



@dataclass(frozen=True)

class Packet:

    type: int

    code: int

    mid: int

    token: bytes

    options: tuple[tuple[int, bytes], ...]

    payload: bytes



    def values(self, number):

        return [value for key, value in self.options if key == number]



    def single(self, number):

        values = self.values(number)

        require(len(values) <= 1, "duplicate singleton option")

        return values[0] if values else None



    @property

    def path(self):

        return b"/".join(self.values(11))





def parse_packet(data):

    require(type(data) is bytes and 4 <= len(data) <= PACKET_BYTES, "packet length outside full-capture bound")

    first, code = data[0], data[1]

    require(first >> 6 == 1, "wrong CoAP version")

    tkl = first & 15

    require(tkl <= 8 and len(data) >= 4 + tkl, "invalid token length")

    if code == 0:

        require(tkl == 0 and len(data) == 4, "malformed empty message")

    pos = 4 + tkl

    options = []

    number = 0

    payload = b""



    def extended(nibble, position):

        if nibble <= 12:

            return nibble, position

        count, bias = (1, 13) if nibble == 13 else (2, 269)

        require(nibble != 15 and position + count <= len(data), "invalid/truncated option extension")

        return bias + int.from_bytes(data[position:position + count], "big"), position + count



    while pos < len(data):

        marker = data[pos]

        pos += 1

        if marker == 255:

            require(pos < len(data), "empty payload marker")

            payload = data[pos:]

            break

        delta, pos = extended(marker >> 4, pos)

        length, pos = extended(marker & 15, pos)

        number += delta

        require(number <= 65535 and pos + length <= len(data), "option number/length outside diagnostic bound")

        options.append((number, data[pos:pos + length]))

        pos += length

    return Packet((first >> 4) & 3, code, int.from_bytes(data[2:4], "big"), data[4:4 + tkl], tuple(options), payload)





def block(value):

    require(value is not None and len(value) <= 3, "missing/oversize Block2")

    encoded = int.from_bytes(value, "big")

    szx = encoded & 7

    require(szx <= 6, "UDP Block2 SZX7 unsupported")

    return encoded >> 4, bool(encoded & 8), szx





def check_pair(request, response, run_id):

    require(request.type == 0 and request.code == 1 and not request.payload, "not the frozen CON GET request")

    require(response.type == 2 and response.code == 69, "not the expected piggybacked 2.05 ACK")

    require(request.mid == response.mid and request.token == response.token, "MID/token mismatch")

    require(response.single(6) is None and response.single(12) is None, "unexpected Observe/Content-Format")

    etags = response.values(4)

    require(len(etags) <= 1 and all(1 <= len(e) <= 8 for e in etags), "invalid/duplicate ETag")

    require(request.single(27) is None and response.single(27) is None, "Block1 outside frozen GET diagnosis")

    path = request.path

    if path in (b"identity", b"test"):

        require(request.single(23) is None and response.single(23) is None, "unexpected Block2 on small resource")

        expected = run_id.encode("ascii") if path == b"identity" else b"coaptic"

        require(response.payload == expected, "small response payload mismatch")

        return path.decode("ascii"), None, etags[0] if etags else None

    require(path == b"large", "request path outside frozen fixture")

    requested = request.single(23)

    number = 0

    if requested is not None:

        number, more, szx = block(requested)

        require(not more and szx == 6, "request Block2 differs from frozen1024B fixture")

    require(number in (0, 1), "unexpected requested block number")

    actual, more, szx = block(response.single(23))

    require(actual == number and szx == 6 and more == (number == 0), "response Block2 mismatch")

    expected_size = 1024 if number == 0 else 976

    require(response.payload == bytes([0x5A]) * expected_size, "large response payload mismatch")

    return "large", number, etags[0] if etags else None





ALIASES = {
 "MCU_SPAN_BEGIN": dict(f="fd",p="local_port",c="context_bytes",g="global_bytes",b="packet_bytes",m="max_rows",n="expected_datagrams",q="quiet_us",s="stack_reserved_bytes"),
 "MCU_SPAN_SOCKET": dict(f="fd",p="local_port"),
 "MCU_SPAN_STARTUP": dict(s="stack_reserved_bytes",i="largest_internal_before_task",a="largest_all8bit_before_task",f="free_all8bit_before_task",w="worker_entered"),
 "MCU_SPAN_RESOURCES": dict(v="metadata_sequence",f="free_bytes",l="largest_free_block_bytes",m="region_min_free_sum_bytes",t="total_bytes",p="phase"),
 "MCU_SPAN_STACK": dict(v="metadata_sequence",s="stack_reserved_bytes",u="stack_observed_used_bytes"),
 "MCU_SPAN_PAIR": dict(i="index",q="rx_sequence",p="rx_present",a="rx_bytes",b="tx_bytes",n="result",e="errno",m="header_match"),
 "MCU_SPAN_PEER": dict(i="index",f="fd",p="local_port",a="rx_ip",b="rx_port",c="tx_ip",d="tx_port"),
 "MCU_SPAN_TIME": dict(i="index",a="recv_entry_us",b="recv_return_us",c="send_entry_us",d="send_return_us"),
 "MCU_SPAN_NATIVE": dict(i="index",q="rx_sequence",w="wait_calls",a="wait_wall_us",y="yield_calls",b="yield_wall_us"),
 "MCU_SPAN_NESTED": dict(i="index",w="nested_wait_calls",y="nested_yield_calls"),
 "MCU_SPAN_END": dict(a="rows",p="pending_rx",f="forced",w="window_closed"),
}
COUNTER_ALIASES = {
 "rx": dict(a="rx",b="would_block",c="peek_calls",d="rx_error",e="rx_refused",f="rx_replaced",h="rx_abandoned"),
 "tx": dict(a="tx",b="success",c="failed",d="partial",e="unmatched",f="refused"),
 "observer": dict(a="rows",b="rows_refused",c="bind_conflict",d="fd_reuse",e="native_refused",s="saturated"),
}

def _legacy_records(rows, run_id=None):
    result = []
    for row in rows:
        text = row.get("line", "")
        if "MCU_SPAN_" not in text:
            continue
        marker, body = text[text.index("MCU_SPAN_"):].split(" ", 1)
        require(marker in MARKERS, "observer refusal/unknown marker")
        try:
            if marker == "MCU_SPAN_WIRE" and not body.startswith("{"):
                parts = body.split()
                require(len(parts) == 5, "truncated wire record")
                data = base64.b64decode(parts[4], validate=True)
                require(0 < len(data) <= WIRE_BYTES, "wire base64 exceeds90B")
                value = dict(run_id=parts[0], index=int(parts[1]), side=parts[2], offset=int(parts[3]), hex=data.hex())
            else:
                value = json.loads(body)
                if "r" in value:
                    mapping = dict(r="run_id")
                    if marker == "MCU_SPAN_COUNTS":
                        group = value["g"]
                        require(group in COUNTER_ALIASES, "unknown counter group")
                        mapping.update(g="group", **COUNTER_ALIASES[group])
                    else:
                        mapping.update(ALIASES[marker])
                    require(set(value) <= set(mapping), "unknown compact observer field")
                    value = {mapping[key]: val for key, val in value.items()}
        except (ValueError, TypeError, KeyError) as error:
            if isinstance(error, Refused): raise
            raise Refused("truncated/malformed observer record") from error
        if run_id is not None:
            require(value.get("run_id") == run_id, "foreign/stale observer record")
        result.append((marker, value))
        require(len(result) <= 8192, "observer record count exceeded bound")
    return result


ROW_FIELDS = ("version", "index", "rx_sequence", "flags", "rx_bytes", "tx_bytes", "result", "errno", "rx_ip", "rx_port", "tx_ip", "tx_port", "recv_entry_us", "recv_return_us", "send_entry_us", "send_return_us", "wait_calls", "wait_wall_us", "yield_calls", "yield_wall_us", "nested_wait_calls", "nested_yield_calls", "fd", "local_port")
TRANSPORT_MARKERS = {"MCU_SPAN_ROW", "MCU_SPAN_FILL", "MCU_SPAN_WIRE"}
META_MARKERS = {"MCU_SPAN_BEGIN", "MCU_SPAN_SOCKET", "MCU_SPAN_STARTUP", "MCU_SPAN_RESOURCES", "MCU_SPAN_STACK", "MCU_SPAN_COUNTS", "MCU_SPAN_END"}


def decode_row(data, run_id, index):
    """Canonical definite CBORv1; preserve signed64/unsigned64 exactly."""
    require(type(data) is bytes and 1 <= len(data) <= 224, "row outside224B bound")
    require(data[:2] == b"\x98\x18", "row must be definite24-element CBORarray")
    position, values = 2, []
    for _ in ROW_FIELDS:
        require(position < len(data), "truncated CBORinteger")
        initial = data[position]; position += 1
        major, additional = initial >> 5, initial & 31
        require(major in (0, 1), "CBORrow contains noninteger")
        if additional < 24:
            value = additional
        else:
            require(additional in (24, 25, 26, 27), "indefinite/reserved CBORinteger")
            count = 1 << (additional - 24)
            require(position + count <= len(data), "truncated CBORinteger extension")
            value = int.from_bytes(data[position:position+count], "big"); position += count
            require(value >= (24 if count == 1 else 1 << ((count//2)*8)), "noncanonical CBORinteger")
        values.append(value if major == 0 else -1-value)
    require(position == len(data), "CBORrow trailing bytes")
    row = dict(zip(ROW_FIELDS, values))
    require(row["version"] == 1 and row["index"] == index, "CBORrow version/index mismatch")
    integer(row["flags"], 0, 3)
    for key in ("rx_sequence", "rx_bytes", "rx_ip", "tx_ip", "wait_calls", "yield_calls", "nested_wait_calls", "nested_yield_calls"):
        integer(row[key], 0, (1 << 32)-1)
    for key in ("rx_port", "tx_port", "local_port"): integer(row[key], 0, 65535)
    for key in ("tx_bytes", "wait_wall_us", "yield_wall_us"): integer(row[key], 0, (1 << 64)-1)
    for key in ("result", "recv_entry_us", "recv_return_us", "send_entry_us", "send_return_us"):
        integer(row[key], -(1 << 63), (1 << 63)-1)
    integer(row["errno"], -(1 << 31), (1 << 31)-1); integer(row["fd"], -(1 << 31), (1 << 31)-1)
    common = dict(run_id=run_id,index=index)
    return [
        ("MCU_SPAN_PAIR", {**common, **{k:row[k] for k in ("rx_sequence","rx_bytes","tx_bytes","result","errno")}, "rx_present":bool(row["flags"]&1), "header_match":bool(row["flags"]&2)}),
        ("MCU_SPAN_PEER", {**common, **{k:row[k] for k in ("fd","local_port","rx_ip","rx_port","tx_ip","tx_port")}}),
        ("MCU_SPAN_TIME", {**common, **{k:row[k] for k in ("recv_entry_us","recv_return_us","send_entry_us","send_return_us")}}),
        ("MCU_SPAN_NATIVE", {**common, **{k:row[k] for k in ("rx_sequence","wait_calls","wait_wall_us","yield_calls","yield_wall_us")}}),
        ("MCU_SPAN_NESTED", {**common, **{k:row[k] for k in ("nested_wait_calls","nested_yield_calls")}})]


def _decode_transport(rows, run_id=None):
    """Normalize bounded lossless V2 fragments; no payload expectations or imputation."""
    require(len(rows) <= 16384, "API record count exceeds bound")
    metadata, fragments, pieces = [], {}, {}
    for record in rows:
        text = record.get("line", "")
        if "MCU_SPAN_" not in text: continue
        try:
            marker, body = text[text.index("MCU_SPAN_"):].split(" ", 1)
            require(marker in TRANSPORT_MARKERS | META_MARKERS, "unknown/V1 packet marker in V2capture")
            if marker in META_MARKERS:
                metadata.append(record); continue
            parts = body.split()
            expected = 5 if marker in ("MCU_SPAN_ROW", "MCU_SPAN_WIRE") else 6
            require(len(parts) == expected, "truncated V2transport record")
            source, index = parts[0], integer(int(parts[1]), 0, MAX_ROWS-1)
            require(len(source)==32 and all(c in "0123456789abcdef" for c in source), "invalid V2runid")
            require(run_id is None or source == run_id, "foreign/stale V2transport")
            if marker == "MCU_SPAN_ROW":
                offset, total = integer(int(parts[2]), 0, 223), integer(int(parts[3]), 1, 224)
                raw = base64.b64decode(parts[4],validate=True)
                require(offset % WIRE_BYTES == 0 and offset < total and len(raw) == min(WIRE_BYTES,total-offset), "invalid ROWfragment bounds")
                key = source,index
                prior_total, table = fragments.setdefault(key, (total,{}))
                require(total == prior_total and offset not in table, "duplicate/conflicting ROWfragment")
                table[offset] = raw
            else:
                side, offset = parts[2], integer(int(parts[3]), 0, PACKET_BYTES-1)
                require(side in ("rx", "tx"), "invalid wire side")
                if marker == "MCU_SPAN_FILL":
                    count, value = integer(int(parts[4]),16,PACKET_BYTES),integer(int(parts[5]),0,255)
                    raw = bytes([value])*count
                else:
                    raw = base64.b64decode(parts[4],validate=True)
                    require(1 <= len(raw) <= WIRE_BYTES, "invalid WIREliteral bound")
                require(offset+len(raw) <= PACKET_BYTES, "wire fragment exceeds1152B")
                table = pieces.setdefault((source,index,side),{})
                for prior, data in table.items():
                    require(offset >= prior+len(data) or prior >= offset+len(raw), "overlapping literal/FILL pieces")
                table[offset] = raw
        except (ValueError, TypeError, KeyError) as error:
            if isinstance(error, Refused): raise
            raise Refused("malformed V2transport") from error
    normalized = _legacy_records(metadata,run_id)
    complete, decoded = True, {}
    for (source,index),(total,table) in fragments.items():
        if set(table) != set(range(0,total,WIRE_BYTES)):
            complete = False; continue
        logical = decode_row(b"".join(table[n] for n in range(0,total,WIRE_BYTES)),source,index)
        decoded[source,index] = logical[0][1];normalized.extend(logical)
    for (source,index,side),table in pieces.items():
        if (source,index) not in decoded:
            complete = False; continue
        size = integer(decoded[source,index][side+"_bytes"],0,PACKET_BYTES)
        cursor, data = 0, bytearray()
        for offset, raw in sorted(table.items()):
            require(offset >= cursor and offset+len(raw)<=size,"wire fragment exceeds declared original size")
            if offset != cursor: complete = False; break
            data.extend(raw);cursor += len(raw)
        if cursor != size: complete = False; continue
        for offset in range(0,size,WIRE_BYTES):
            normalized.append(("MCU_SPAN_WIRE",dict(run_id=source,index=index,side=side,offset=offset,hex=bytes(data[offset:offset+WIRE_BYTES]).hex())))
    for (source,index),row in decoded.items():
        for side in ("rx","tx"):
            size = integer(row[side+"_bytes"],0,PACKET_BYTES)
            if size and (source,index,side) not in pieces: complete = False
    require(len(normalized) <= 8192, "normalized observer bound exceeded")
    return normalized,complete


def _records(rows, run_id=None):
    return _decode_transport(rows,run_id)[0]


def _metadata(records, run_id):
    constant_keys = ("MCU_SPAN_BEGIN", "MCU_SPAN_SOCKET", "MCU_SPAN_STARTUP")
    constants, resources, stacks = {}, {}, {}
    for marker, value in records:
        require(value.get("run_id") == run_id, "foreign/stale observer record")
        if marker in constant_keys:
            require(marker not in constants or constants[marker] == value, "conflicting metadata replay")
            constants[marker] = value
        if marker in ("MCU_SPAN_RESOURCES", "MCU_SPAN_STACK"):
            sequence = integer(value["metadata_sequence"], 1, 9)
            target = resources if marker == "MCU_SPAN_RESOURCES" else stacks
            require(sequence not in target or target[sequence] == value, "conflicting resource replay")
            target[sequence] = value
    shared = set(resources) & set(stacks)
    if len(constants) != 3 or not shared:
        return None
    sequence = max(shared)
    heap, stack = resources[sequence], stacks[sequence]
    running = [n for n in shared if resources[n].get("phase") == "running"]
    live_heap = resources[max(running)] if running else heap
    return {**constants, "MCU_SPAN_RESOURCES": heap, "MCU_SPAN_STACK": stack,
            "running_heap": dict(run_id=run_id, phase=live_heap.get("phase", "running"), caps="all_8bit", free_bytes=live_heap["free_bytes"], total_bytes=live_heap["total_bytes"], largest_free_block_bytes=live_heap["largest_free_block_bytes"], region_min_free_sum_bytes=min(v["region_min_free_sum_bytes"] for v in resources.values()))}


def live_metadata(api_rows, run_id):
    """None until complete; identical startup replays allowed, conflicts refused."""
    return _metadata(_records(api_rows, run_id), run_id)


def publication_complete(api_rows, run_id):
    """Cheap live closure check, without fake footer or body/timing aggregation."""
    records, transport_complete = _decode_transport(api_rows, run_id)
    if not transport_complete:
        return False
    ends = [v for k,v in records if k == "MCU_SPAN_END"]
    if not ends:
        return False
    require(len(ends) == 1 and ends[0]["window_closed"] is True, "invalid observer END")
    count = integer(ends[0]["rows"], 0, MAX_ROWS)
    if _metadata(records, run_id) is None:
        return False
    indexed = {}
    required = ("MCU_SPAN_PAIR", "MCU_SPAN_PEER", "MCU_SPAN_TIME", "MCU_SPAN_NATIVE", "MCU_SPAN_NESTED")
    for marker in required:
        table = {}
        for tag, value in records:
            if tag != marker: continue
            index = integer(value["index"], 0, MAX_ROWS - 1)
            require(index not in table, "duplicate indexed observer row")
            table[index] = value
        if set(table) != set(range(count)):
            return False
        indexed[marker] = table
    chunks = {}
    for marker, value in records:
        if marker != "MCU_SPAN_WIRE": continue
        key = (integer(value["index"], 0, MAX_ROWS-1), value["side"], integer(value["offset"], 0, PACKET_BYTES-1))
        require(key[1] in ("rx", "tx") and key[2] % WIRE_BYTES == 0 and key not in chunks, "invalid/duplicate wire chunk")
        chunks[key] = bytes.fromhex(value["hex"])
    used = set()
    for i, row in indexed["MCU_SPAN_PAIR"].items():
        for side in ("rx", "tx"):
            size = integer(row[side + "_bytes"], 0, PACKET_BYTES)
            for offset in range(0, size, WIRE_BYTES):
                key = (i,side,offset)
                if key not in chunks: return False
                require(len(chunks[key]) == min(WIRE_BYTES,size-offset), "wire chunk size mismatch")
                used.add(key)
    require(used == set(chunks), "unclaimed wire chunks")
    return {v["group"] for k,v in records if k == "MCU_SPAN_COUNTS"} == {"rx", "tx", "observer"}


def extract_api(rows):
    require(rows and rows[-1].get("kind") == "capture_complete", "API capture incomplete")
    require(rows[-1].get("overflow") is False and rows[-1].get("connections", 0) > 0, "API capture overflow/no connection")
    require(not any(row.get("kind") == "disconnected" and row.get("expected") is False for row in rows), "unexpected API disconnect")
    records, complete = _decode_transport(rows)
    require(complete, "incomplete V2ROW/wire publication")
    return records


def check_clients(reports, run_id):

    require(set(reports) == {"sync", "async"}, "both fresh client modes required")

    expected = [(iteration, path, size) for iteration in range(8) for path, size in [("identity", 32), ("test", 7), ("large", 2000)]]

    for mode, rows in reports.items():

        require(rows and rows[-1].get("case") == "timing_campaign", "client campaign missing")

        final = rows[-1]

        require(final.get("passed") is True and final.get("completed") == 24 and final.get("run_id") == run_id and final.get("io_mode") == mode and final.get("security") == "unprotected", "client campaign failed/source mismatch")

        operations = [row for row in rows if row.get("case") == "complete_operation"]

        require(len(operations) == 24, "client operation count mismatch")

        for row, expected_row in zip(operations, expected):

            require(row.get("passed") is True and (row.get("iteration"), row.get("path"), row.get("bytes")) == expected_row, "client body verification or fixed order failed")

    # Client poll_ns/elapsed_ns never enters the MCU span calculation.

    return 48





def analyze(records, run_id, client_reports, expected_stack):

    require(len(records) <= 8192, "observer record count exceeded bound")

    require(type(run_id) is str and len(run_id) == 32 and run_id.isascii(), "run id must be32ASCIIbytes")

    integer(expected_stack, 1)

    verified_operations = check_clients(client_reports, run_id)

    metadata = _metadata(records, run_id)
    require(metadata is not None, "missing idle/startup/resource metadata")
    by_marker = {marker: [] for marker in MARKERS}

    for marker, value in records:

        require(marker in by_marker and value.get("run_id") == run_id, "foreign/stale observer record")

        by_marker[marker].append(value)

    for key in ("MCU_SPAN_BEGIN", "MCU_SPAN_SOCKET", "MCU_SPAN_STARTUP"):
        by_marker[key] = [metadata[key]]
    require(len(by_marker["MCU_SPAN_BEGIN"]) == len(by_marker["MCU_SPAN_SOCKET"]) == len(by_marker["MCU_SPAN_STARTUP"]) == len(by_marker["MCU_SPAN_END"]) == 1, "missing/duplicate observer boundary")

    begin, socket, end = (by_marker[key][0] for key in ("MCU_SPAN_BEGIN", "MCU_SPAN_SOCKET", "MCU_SPAN_END"))

    require(0 < integer(begin["context_bytes"]) <= 3072 and 0 < integer(begin["global_bytes"]) <= 64, "observer storage exceeded bound")

    require(begin["packet_bytes"] == PACKET_BYTES and begin["max_rows"] == MAX_ROWS and begin["expected_datagrams"] == EXPECTED_DATAGRAMS and begin["quiet_us"] == 15000000 and begin["stack_reserved_bytes"] == expected_stack, "observer/protocol configuration mismatch")

    startup = by_marker["MCU_SPAN_STARTUP"][0]

    require(startup["worker_entered"] is True and startup["stack_reserved_bytes"] == expected_stack, "startup worker/reservation mismatch")

    require(integer(startup["largest_internal_before_task"]) >= expected_stack + 4096, "before-task contiguous margin below4096B")

    require(integer(startup["largest_all8bit_before_task"]) >= startup["largest_internal_before_task"] and integer(startup["free_all8bit_before_task"]) >= startup["largest_all8bit_before_task"], "invalid startup memory ownership")

    fd = integer(socket["fd"], 0)

    require(socket["local_port"] == begin["local_port"] == 5683 and begin["fd"] in (-1, fd), "server socket/port mismatch")

    groups = {}

    for counter in by_marker["MCU_SPAN_COUNTS"]:

        group = counter["group"]

        require(group not in groups and group in ("rx", "tx", "observer"), "duplicate/unknown counter group")

        groups[group] = counter

    require(set(groups) == {"rx", "tx", "observer"}, "missing counter group")

    rx, tx, obs = (groups[key] for key in ("rx", "tx", "observer"))

    for group in groups.values():

        for key, value in group.items():

            if key not in ("run_id", "group", "saturated"):

                integer(value, 0, (1 << 32) - 1)

    require(rx["rx"] == tx["tx"] == tx["success"] == obs["rows"] == end["rows"] == EXPECTED_DATAGRAMS, "not all64datagrams accounted")

    require(all(rx[key] == 0 for key in ("rx_error", "rx_refused", "rx_replaced", "rx_abandoned")), "unmatched/refused/failed receive")

    require(all(tx[key] == 0 for key in ("failed", "partial", "unmatched", "refused")), "unmatched/refused/failed send")

    require(obs["rows_refused"] == obs["bind_conflict"] == obs["fd_reuse"] == obs["native_refused"] == 0 and obs["saturated"] is False and end["pending_rx"] is False and end["window_closed"] is True and type(end.get("forced")) is bool, "observer coverage incomplete")

    headers, peers, times, native, nested, chunks = {}, {}, {}, {}, {}, {}

    for marker, target in (("MCU_SPAN_PAIR", headers), ("MCU_SPAN_PEER", peers), ("MCU_SPAN_TIME", times), ("MCU_SPAN_NATIVE", native), ("MCU_SPAN_NESTED", nested)):

        for row in by_marker[marker]:

            index = integer(row["index"], 0, MAX_ROWS - 1)

            require(index not in target, "duplicate pair/time row")

            target[index] = row

    require(set(headers) == set(peers) == set(times) == set(native) == set(nested) == set(range(EXPECTED_DATAGRAMS)), "missing pair/time index")

    for row in by_marker["MCU_SPAN_WIRE"]:

        index = integer(row["index"], 0, MAX_ROWS - 1)

        offset = integer(row["offset"], 0, PACKET_BYTES - 1)

        side = row["side"]

        require(side in ("rx", "tx") and offset % WIRE_BYTES == 0 and index in headers, "unexpected wire chunk")

        try:

            data = bytes.fromhex(row["hex"])

        except (ValueError, TypeError) as error:

            raise Refused("invalid wire hex") from error

        require(type(row["hex"]) is str and len(row["hex"]) == len(data) * 2 and 1 <= len(data) <= WIRE_BYTES, "wire chunk size/encoding mismatch")

        key = index, side, offset

        require(key not in chunks, "duplicate/overlapping wire chunk")

        chunks[key] = data

    used = set()

    seen_mids = {}

    spans = []

    for index in range(EXPECTED_DATAGRAMS):

        h, t = {**headers[index], **peers[index]}, times[index]

        require(h["fd"] == fd and h["local_port"] == 5683 and h["rx_present"] is True and h["header_match"] is True and h["rx_sequence"] == index + 1, "unmatched socket/receive sequence")

        require(h["rx_ip"] == h["tx_ip"] == EXPECTED_IP and h["rx_port"] == h["tx_port"], "full peer mismatch")

        integer(h["rx_port"], 1, 65535)

        wire = {}

        for side in ("rx", "tx"):

            n = integer(h[side + "_bytes"], 4, PACKET_BYTES)

            parts = []

            for offset in range(0, n, WIRE_BYTES):

                key = index, side, offset

                require(key in chunks and len(chunks[key]) == min(WIRE_BYTES, n - offset), "missing/truncated wire chunk")

                parts.append(chunks[key]); used.add(key)

            wire[side] = b"".join(parts)

        require(type(h["result"]) is int and h["result"] == len(wire["tx"]), "failed/partial UDP send result")

        # errno can legitimately retain EAGAIN after a successful POSIX call.

        integer(h["errno"], 0, (1 << 31) - 1)

        request, response = parse_packet(wire["rx"]), parse_packet(wire["tx"])

        key = fd, h["rx_ip"], h["rx_port"], request.mid

        require(key not in seen_mids, "duplicate request/MID collision within peer scope")

        seen_mids[key] = (request.token, wire["rx"])

        path, block_number, etag = check_pair(request, response, run_id)

        r0, r1, s0, s1 = (integer(t[name]) for name in ("recv_entry_us", "recv_return_us", "send_entry_us", "send_return_us"))

        require(r0 <= r1 <= s0 <= s1, "non-monotonic wall timestamps")

        native_row = {**native[index], **nested[index]}

        require(native_row["rx_sequence"] == h["rx_sequence"], "native interval belongs to another receive")

        for key in ("wait_calls", "yield_calls", "nested_wait_calls", "nested_yield_calls"):

            integer(native_row[key], 0, (1 << 32) - 1)

        wait_wall = integer(native_row["wait_wall_us"])

        yield_wall = integer(native_row["yield_wall_us"])

        require((native_row["wait_calls"] > 0 or wait_wall == 0) and (native_row["yield_calls"] > 0 or yield_wall == 0), "native duration without a root call")

        require(not (native_row["nested_wait_calls"] or native_row["nested_yield_calls"]) or native_row["wait_calls"] + native_row["yield_calls"] > 0, "nested native calls without a measured outer call")

        require(wait_wall + yield_wall <= s0 - r1, "native union exceeds packet wall interval")

        if spans:

            require(spans[-1]["send_return_us"] <= r0, "C1 packet spans overlap")

        spans.append({"index": index, "peer_ip": h["rx_ip"], "peer_port": h["rx_port"], "mid": request.mid, "token_hex": request.token.hex(), "path": path, "block": block_number, "etag_hex": etag.hex() if etag is not None else None, "receive_return_to_send_entry_wall_us": s0 - r1, "receive_call_wall_us": r1 - r0, "send_call_wall_us": s1 - s0, "send_return_us": s1, "native_select_calls": native_row["wait_calls"], "native_select_call_wall_us": wait_wall, "native_delay_calls": native_row["yield_calls"], "native_delay_call_wall_us": yield_wall, "nested_native_select_calls": native_row["nested_wait_calls"], "nested_native_delay_calls": native_row["nested_yield_calls"], "residual_wall_us": s0 - r1 - wait_wall - yield_wall})

    require(used == set(chunks), "unclaimed extra wire chunks")

    require(Counter(row["path"] for row in spans) == {"identity": 16, "test": 16, "large": 32}, "wrong full-fixture packet mix")

    operations = []

    for index in range(0, EXPECTED_DATAGRAMS, 4):

        group = spans[index:index + 4]

        require([(row["path"], row["block"]) for row in group] == [("identity", None), ("test", None), ("large", 0), ("large", 1)], "frozen C1/Block2 order mismatch")

        require(len({(row["peer_ip"], row["peer_port"]) for row in group}) == 1, "peer changed within logical operation group")

        require(group[2]["etag_hex"] == group[3]["etag_hex"], "Block2 representation ETag changed")

        for path, rows in (("identity", group[:1]), ("test", group[1:2]), ("large", group[2:])):

            operations.append({"path": path, "receive_return_to_send_entry_sum_wall_us": sum(row["receive_return_to_send_entry_wall_us"] for row in rows), "datagrams": len(rows), "native_select_call_sum_wall_us": sum(row["native_select_call_wall_us"] for row in rows), "native_delay_call_sum_wall_us": sum(row["native_delay_call_wall_us"] for row in rows), "residual_sum_wall_us": sum(row["residual_wall_us"] for row in rows)})

    summaries = []

    for path in ("identity", "test", "large"):

        values = [row["receive_return_to_send_entry_sum_wall_us"] for row in operations if row["path"] == path]

        summaries.append({"path": path, "operations": len(values), "median_wall_us": statistics.median(values), "min_wall_us": min(values), "max_wall_us": max(values), "median_native_select_call_sum_wall_us": statistics.median(row["native_select_call_sum_wall_us"] for row in operations if row["path"] == path), "median_native_delay_call_sum_wall_us": statistics.median(row["native_delay_call_sum_wall_us"] for row in operations if row["path"] == path), "median_residual_sum_wall_us": statistics.median(row["residual_sum_wall_us"] for row in operations if row["path"] == path)})

    heap = metadata["running_heap"]
    require(heap["phase"] == "running" and 8192 <= integer(heap["free_bytes"]) <= integer(heap["total_bytes"]) and integer(heap["largest_free_block_bytes"]) >= 8192 and integer(heap["region_min_free_sum_bytes"]) >= 12288, "running heap guards failed")
    stack = metadata["MCU_SPAN_STACK"]
    require(stack["stack_reserved_bytes"] == expected_stack and 0 <= integer(stack["stack_observed_used_bytes"]) <= expected_stack, "running stack guard failed")
    return {"verified_complete": True, "run_id": run_id, "body_verified_operations": verified_operations, "datagrams": len(spans), "spans": spans, "operations": operations, "summary": summaries, "counters": groups, "startup": startup, "forced_window_close": end.get("forced"), "scope": "MCU global esp_timer wall from UDP receive-return to send-entry, including preemption and RX observer work. Full packet/peer/MID/token/Block2/body checks and 48total read closure across both client modes. Logging follows send-return. Native outer select/delay wall intervals counted once, with nested counts separate; residual remains wall+preemption+observer work, never CPU. No taskCPU, RTT residual, clean-speed, cache-miss or peakRAM claim; no success-only subset on failure."}





def main():

    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("api", type=Path)

    parser.add_argument("sync_client", type=Path)

    parser.add_argument("async_client", type=Path)

    parser.add_argument("run_id")

    parser.add_argument("stack_bytes", type=int)

    parser.add_argument("output", type=Path)

    args = parser.parse_args()

    def load_rows(path):

        require(path.stat().st_size <= 4 * 1024 * 1024, "input exceeds bounded4MiB log allowance")

        return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]

    try:

        report = analyze(extract_api(load_rows(args.api)), args.run_id, {"sync": load_rows(args.sync_client), "async": load_rows(args.async_client)}, args.stack_bytes)

    except (Refused, KeyError, ValueError, TypeError) as error:

        report = {"verified_complete": False, "error": {"type": type(error).__name__, "reason": str(error)}, "scope": "All raw data retained; complete diagnosis withheld, no success-only subset."}

    with args.output.open("x", encoding="utf-8") as stream:

        json.dump(report, stream, indent=2)

    print(json.dumps({key: report.get(key) for key in ("verified_complete", "body_verified_operations", "datagrams", "summary", "error")}))

    return 0 if report["verified_complete"] else 1



if __name__ == "__main__":

    raise SystemExit(main())

