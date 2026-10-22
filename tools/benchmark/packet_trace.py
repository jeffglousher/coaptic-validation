"""Bounded socket-boundary UDP capture, never part of timed benchmark runs.

PCAP DLT_USER0 records contain only received UDP payloads, not invented headers.
Synthetic credentials are retained privately to permit independent OSCORE grading.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import threading
import time

import campaign

MAX_BYTES = 14 * 1024 * 1024  # Reserve 2 MiB of the case budget for metadata/logs.
MAX_FRAMES = 10000
MAX_PACKET = 65507
HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, MAX_PACKET, 147)
SECURITY = 'OSCORE-AES-CCM-16-64-128'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def dependencies():
    sys.path.insert(0, str(Path(__file__).parent / 'protected'))
    import aiocoap
    from aiocoap.message import Direction
    from context import Context
    from load import check_body
    return aiocoap, Direction, Context, check_body


class Writer:
    def __init__(self, directory):
        self.pcap = (directory / 'datagrams.pcap').open('xb')
        self.meta = (directory / 'frames.jsonl').open('xb')
        self.pcap.write(HEADER)
        self.size, self.count = len(HEADER), 0

    def record(self, payload, direction, client, local, remote):
        now = time.time_ns()
        row = dict(index=self.count, direction=direction, client=list(client),
                   local=list(local), remote=list(remote), time_ns=now,
                   sha256=hashlib.sha256(payload).hexdigest())
        encoded = (json.dumps(row, separators=(',', ':')) + '\n').encode()
        require(0 < len(payload) <= MAX_PACKET, 'invalid UDP payload size')
        require(self.count < MAX_FRAMES and self.size + 16 + len(payload) + len(encoded) <= MAX_BYTES,
                'capture budget exceeded; incomplete capture')
        seconds, micros = divmod(now // 1000, 1000000)
        self.pcap.write(struct.pack('<IIII', seconds, micros, len(payload), len(payload)))
        self.pcap.write(payload)
        self.meta.write(encoded)
        self.size += 16 + len(payload) + len(encoded)
        self.count += 1

    def close(self):
        for stream in (self.pcap, self.meta):
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()


class Relay:
    def __init__(self, directory, server):
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(('127.0.0.1', 0))
        self.address = self.front.getsockname()
        self.server = server
        self.upstream = {}
        self.writer = Writer(directory)
        self.stop = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def run(self):
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.front, *self.upstream.values()], [], [], .02)
                for sock in ready:
                    data, source = sock.recvfrom(MAX_PACKET + 1)
                    if sock is self.front:
                        require(source[0] == '127.0.0.1', 'nonloopback client')
                        if source not in self.upstream:
                            require(len(self.upstream) < 16, 'endpoint budget exceeded')
                            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            upstream.bind(('127.0.0.1', 0))
                            upstream.connect(self.server)
                            self.upstream[source] = upstream
                        self.writer.record(data, 'request', source, self.address, source)
                        require(self.upstream[source].send(data) == len(data), 'short forward')
                    else:
                        client = next(k for k, v in self.upstream.items() if v is sock)
                        require(source == self.server, 'foreign server')
                        self.writer.record(data, 'response', client, sock.getsockname(), source)
                        require(self.front.sendto(data, client) == len(data), 'short forward')
        except Exception as error:
            self.error = repr(error)

    def __exit__(self, *_):
        # Bounded drain catches trailing controls; this is validation, not timing.
        time.sleep(.05)
        self.stop.set()
        self.thread.join(2)
        require(not self.thread.is_alive(), 'relay did not stop')
        for sock in [self.front, *self.upstream.values()]:
            sock.close()
        self.writer.close()


def records(directory, receipt):
    paths = [directory / n for n in ('datagrams.pcap', 'frames.jsonl')]
    require(sum(p.stat().st_size for p in paths) <= MAX_BYTES, 'oversize capture')
    for path in paths:
        require(campaign.digest(path) == receipt['hashes'][path.name], 'capture digest mismatch')
    rows = [json.loads(line) for line in paths[1].read_bytes().splitlines()]
    require(len(rows) <= MAX_FRAMES and len(rows) == receipt['frames'], 'frame count')
    wire = paths[0].read_bytes()
    require(wire[:24] == HEADER, 'not the declared DLT_USER0 payload capture')
    offset = 24
    for index, row in enumerate(rows):
        require(offset + 16 <= len(wire), 'truncated PCAP record')
        sec, usec, incl, orig = struct.unpack_from('<IIII', wire, offset)
        offset += 16
        require(0 < incl <= MAX_PACKET and incl == orig and offset + incl <= len(wire), 'truncated packet')
        payload = wire[offset:offset + incl]
        offset += incl
        require(row['index'] == index and row['direction'] in ('request', 'response'), 'sidecar order/direction')
        require((sec * 1000000 + usec) == row['time_ns'] // 1000, 'timestamp mismatch')
        require(hashlib.sha256(payload).hexdigest() == row['sha256'], 'packet digest mismatch')
        require(len(row['client']) == 2 and row['client'][0] == '127.0.0.1', 'client endpoint')
        yield row, payload
    require(offset == len(wire), 'unindexed PCAP tail')


def grade_dtls(frames):
    encrypted = set()
    count = 0
    for row, data in frames:
        offset = 0
        while offset < len(data):
            require(offset + 13 <= len(data), 'truncated DTLS record')
            kind, version, epoch = data[offset], data[offset+1:offset+3], int.from_bytes(data[offset+3:offset+5], 'big')
            length = int.from_bytes(data[offset+11:offset+13], 'big')
            require(kind in (20, 21, 22, 23) and version in (b'\xfe\xfd', b'\xfe\xff'), 'DTLS record framing')
            require(length > 0 and offset + 13 + length <= len(data), 'truncated DTLS payload')
            if kind == 23:
                require(epoch > 0, 'unencrypted DTLS application epoch')
                encrypted.add(row['direction'])
            count += 1
            offset += 13 + length
    require(encrypted == {'request', 'response'}, 'missing encrypted DTLS application traffic')
    return dict(offline_scope='DTLS record framing only; no session secrets, authentication or decrypted body proof',
                records=count, authenticated=False)


def grade_coap(directory, case, frames):
    coap, Direction, Context, check_body = dependencies()
    protected = case['security'] == SECURITY
    require(protected or case['security'] == 'unprotected', 'unsupported security')
    server = Context(directory / 'synthetic-credentials.bin', server=True) if protected else None
    client = Context(directory / 'synthetic-credentials.bin') if protected else None
    states, mids, outstanding, con_acks, request_acks = {}, set(), {}, set(), set()
    completed = 0
    echo_challenges = 0
    for row, wire in frames:
        endpoint = tuple(row['client'])
        msg = coap.Message.decode(wire)
        msg.direction = Direction.OUTGOING
        require(msg.encode() == wire, 'noncanonical/truncated CoAP frame')
        msg.direction = Direction.INCOMING
        if msg.code == coap.EMPTY:
            require(wire == bytes([0x60, 0, msg.mid >> 8, msg.mid & 255]), 'invalid empty control')
            if row['direction'] == 'request':
                key = (endpoint, msg.mid)
                require(key in con_acks, 'unmatched response ACK')
                con_acks.remove(key)
            else:
                key = (endpoint, msg.mid)
                require(key in request_acks, 'unmatched request ACK')
                request_acks.remove(key)
            continue
        key = (endpoint, msg.token)
        if row['direction'] == 'request':
            require(msg.mtype == (coap.CON if case['mode'] == 'con' else coap.NON), 'request type')
            require((endpoint, msg.mid) not in mids, 'reused request MID')
            mids.add((endpoint, msg.mid))
            require(key not in outstanding, 'overlapping request')
            binding = None
            if protected:
                require(msg.opt.oscore is not None, 'unprotected request')
                msg.direction = Direction.INCOMING
                plain, binding = server.unprotect(msg)
            else:
                require(msg.opt.oscore is None, 'unexpected OSCORE')
                plain = msg
            require(plain.code == coap.GET and plain.opt.uri_path == ('bench',) and not plain.opt.uri_query and not plain.payload, 'request identity')
            state = states.setdefault(key, dict(offset=0, etag=None, block=(0, False, 6) if case['bytes'] > 1024 else None, complete=False, echo=None, challenged=False))
            require(not state['complete'], 'reused completed token')
            require(plain.opt.echo == state['echo'], 'Echo retry identity')
            state['echo'] = None
            require(plain.opt.block2 == state['block'], 'request Block2 identity')
            outstanding[key] = dict(mid=msg.mid, type=msg.mtype, binding=binding)
            if msg.mtype == coap.CON:
                request_acks.add((endpoint, msg.mid))
        else:
            require(key in outstanding, 'response token/endpoint without request')
            request = outstanding.pop(key)
            require(msg.mtype in (coap.ACK, coap.CON, coap.NON), 'response type')
            if msg.mtype == coap.ACK:
                require(request['type'] == coap.CON and request['mid'] == msg.mid, 'ACK request MID')
                require((endpoint, msg.mid) in request_acks, 'duplicate request ACK')
                request_acks.remove((endpoint, msg.mid))
            if protected:
                require(msg.opt.oscore is not None, 'unprotected response')
                msg.direction = Direction.INCOMING
                plain, _ = client.unprotect(msg, request['binding'])
            else:
                require(msg.opt.oscore is None, 'unexpected OSCORE')
                plain = msg
            state = states[key]
            if msg.mtype == coap.CON:
                con_acks.add((endpoint, msg.mid))
            if plain.code == coap.UNAUTHORIZED:
                require(protected and case.get('bootstrap_completed') == 1 and
                        msg.token == bytes(8) and state['offset'] == 0 and
                        not state['challenged'] and completed == 0,
                        'unexpected Echo challenge')
                options = list(plain.opt.option_list())
                require(len(options) == 1 and int(options[0].number) == 252 and
                        plain.opt.echo is not None and 1 <= len(plain.opt.echo) <= 40 and
                        not plain.payload, 'invalid authenticated Echo control')
                state['echo'] = plain.opt.echo
                state['challenged'] = True
                echo_challenges += 1
                continue
            state['offset'], state['block'], state['etag'] = check_body(plain, state['offset'], case['bytes'], state['etag'], state['block'])
            if state['block'] is None:
                state['complete'] = True
                completed += 1
    require(not outstanding and not con_acks and not request_acks, 'partial exchange/control capture')
    require(completed == case['operations'] + case['warmup'] + case.get('bootstrap_completed', 0) and len(states) == completed, 'partial representation/operation capture')
    require(echo_challenges == case.get('bootstrap_echo_challenges', 0), 'Echo control accounting')
    return dict(bootstrap_completed=case.get('bootstrap_completed', 0), authenticated_echo_challenges=echo_challenges,
                offline_scope='complete CoAP representations and exchange identity',
                authenticated=protected, completed_including_warmup=completed,
                count_scope='all complete bodies including bootstrap and warmup; Echo controls excluded',
                verified_bytes_including_warmup=completed * case['bytes'])


def grade(directory):
    directory = Path(directory)
    receipt = campaign.read(directory / 'capture.json')
    require(receipt.get('schema') == 'coaptic-packet-trace/1' and receipt.get('capture_complete'), 'incomplete/failed capture')
    case = receipt['case']
    require(case['bytes'] in (64, 65536), 'capture body bound')
    require(case['concurrency'] == 1 and case['operations'] == 3 and case['warmup'] == 1, 'capture workload')
    campaign.validate_sample(receipt['online_sample'], case)
    require(receipt['online_sample']['completed'] == 3 and receipt['online_sample']['failed'] == 0 and receipt['online_sample']['warmup_failed'] == 0, 'online validation failed')
    if case['security'] == SECURITY:
        require(campaign.digest(directory / 'synthetic-credentials.bin') == receipt['credential_sha256'], 'credential digest mismatch')
    frames = list(records(directory, receipt))
    require(frames, 'empty capture')
    if case['security'].startswith('DTLS'):
        result = grade_dtls(frames)
    else:
        sample = receipt['online_sample']
        require(sample.get('bootstrap_completed') == 1 and sample.get('bootstrap_echo_challenges') in (0, 1), 'bootstrap accounting')
        result = grade_coap(directory, dict(case, bootstrap_completed=1, bootstrap_echo_challenges=sample['bootstrap_echo_challenges']), frames)
    return dict(result, passed=True, frames=len(frames), grader_sha256=campaign.digest(__file__),
                capture_boundary='UDP socket receive, DLT_USER0; no IP/Ethernet/kernel capture', timing_valid=False)


def capture_case(peer, case, output, manifest_hash):
    output.mkdir()
    credential = output / 'synthetic-credentials.bin'
    with credential.open('xb') as stream:
        stream.write(os.urandom(24))
    os.chmod(credential, 0o600)
    values = dict(case, port=campaign.reserve_port(), host='127.0.0.1', sequence=0,
                  credentials=str(credential.resolve()), certificate=str((output / 'server.pem').resolve()),
                  operations=1, warmup=0)
    receipt = dict(schema='coaptic-packet-trace/1', case=case, peer=peer['id'],
                   manifest_sha256=manifest_hash, capture_complete=False,
                   capture_tool_sha256=campaign.digest(__file__),
                   private_credentials='fresh synthetic only; do not publish this directory',
                   command_identity=campaign.peer_identity(peer))
    captured = relay = None
    try:
        captured = campaign.CapturedProcess(campaign.render(peer['server'], values))
        health = lambda: captured.process.poll() is None and not captured.overflow.is_set() and len(captured.output) <= 65536 and len(captured.errors) <= 65536
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            require(health(), 'server exited during readiness')
            try:
                code, probe = campaign.execute(campaign.render(peer['driver'], values), 3, health)
                campaign.validate_sample(probe, dict(case, operations=1, warmup=0))
                if code == 0 and probe['completed'] == 1:
                    break
            except ValueError:
                pass
            values['sequence'] += 65536
        else:
            raise ValueError('readiness deadline')
        with Relay(output, ('127.0.0.1', values['port'])) as relay:
            values.update(case, port=relay.address[1], sequence=1 << 32)
            code, sample = campaign.execute(campaign.render(peer['driver'], values), 45,
                                           lambda: health() and relay.error is None)
            require(health(), 'server exited during validation')
            receipt['online_sample'] = sample
            campaign.validate_sample(sample, case)
            require(code == 0 and sample['failed'] == 0 and sample['warmup_failed'] == 0, 'online validation failed')
        require(relay.error is None, relay.error)
        receipt['capture_complete'] = True
        receipt['credential_sha256'] = campaign.digest(credential)
    except Exception as error:
        receipt['error'] = repr(error)
    finally:
        if captured is not None:
            captured.close()
            (output / 'server.stdout').write_bytes(captured.output[:65536])
            (output / 'server.stderr').write_bytes(captured.errors[:65536])
            if len(captured.output) > 65536 or len(captured.errors) > 65536:
                receipt.update(capture_complete=False, error='server log budget exceeded; tails truncated')
        if relay is not None:
            receipt['frames'] = relay.writer.count
            receipt['hashes'] = {name: campaign.digest(output / name) for name in ('datagrams.pcap', 'frames.jsonl')}
        campaign.write_new(output / 'capture.json', receipt)
    try:
        result = grade(output)
    except Exception as error:
        result = dict(passed=False, error=repr(error))
    campaign.write_new(output / 'grade.json', result)
    return result


def capture(manifest, output):
    manifest = Path(manifest)
    data = campaign.validate_manifest(campaign.read(manifest))
    output = Path(output)
    output.mkdir(exist_ok=False)
    campaign.write_new(output / 'OWNER.json', dict(owner='Coaptic benchmark validation',
        budget='16MiB per case: 14MiB packet/sidecar, 2MiB metadata/log allowance', release='retain failures and receipts; private synthetic secrets required for offline grading',
        boundary='socket capture only; never use latency/throughput from this relay'))
    results = []
    for peer in data['peers']:
        if peer['protocol'] != 'coap':
            continue
        for size in (64, 65536):
            for mode in ('con', 'non'):
                case = dict(id=f"{peer['id']}-{mode}-{size}", protocol='coap', security=peer['security'], bytes=size,
                            mode=mode, operations=3, warmup=1, concurrency=1, timeout_ms=5000)
                result = capture_case(peer, case, output / case['id'], campaign.digest(manifest))
                results.append(dict(id=case['id'], **result))
    campaign.write_new(output / 'results.json', results)
    return all(r['passed'] for r in results) and bool(results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('capture'); p.add_argument('--manifest', required=True); p.add_argument('--output', required=True)
    p = sub.add_parser('grade'); p.add_argument('--directory', required=True)
    args = parser.parse_args()
    if args.command == 'capture':
        return 0 if capture(args.manifest, args.output) else 1
    result = grade(args.directory)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())



