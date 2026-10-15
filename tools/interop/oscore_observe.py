"""Finite independent protected Observe duplicate refusal; fixture keys only."""
import json
import select
import subprocess
import threading
import time
from aiocoap import oscore
from oscore_qblock1 import require, request_plain, response_plain, incoming
from oscore_qblock2 import loopback_endpoint, relay_endpoints, require_relay_family
from run import Proxy, Server, request, command, expect, decode, decoded_options, packet_token


def opts(plain):
    out = {}
    for option in plain.opt.option_list():
        out.setdefault(int(option.number), []).append(option.encode())
    return out


class ObserveRelay(Proxy):
    """One observer; intact replay sends from the original client-facing socket."""
    def __init__(self, number, family="ipv4"):
        self.lock = threading.Lock()
        self.client = None
        super().__init__(number, "pass", family=family)

    def record_send(self, direction, action, wire, source, target, address):
        require(len(self.trace) < 128 and 4 <= len(wire) <= 4096, "relay bounded trace/datagram limit")
        require(target.sendto(wire, address) == len(wire), "incomplete relay send")
        self.trace.append(dict(direction=direction, action=action, hex=wire.hex(), forwarded_hex=wire.hex(),
                               time_ns=time.perf_counter_ns(), source=list(source), destination=list(address if direction == "response" else self.dest),
                               relay=list(target.getsockname())))

    def run(self):
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.front, self.back], [], [], .02)
                for sock in ready:
                    wire, source = sock.recvfrom(4097)
                    with self.lock:
                        if sock is self.front:
                            require(self.client is None or self.client == source, "observer endpoint changed")
                            self.client = source
                            self.record_send("request", "forward", wire, source, self.back, self.dest)
                        else:
                            require(source == self.dest and self.client is not None, "unexpected upstream owner")
                            self.record_send("response", "forward", wire, source, self.front, self.client)
        except Exception as error:
            self.error = str(error)

    def snapshot(self):
        with self.lock:
            return list(self.trace)

    def replay(self, wire):
        with self.lock:
            require(self.client is not None, "no observer to replay")
            self.record_send("response", "replay", wire, self.dest, self.front, self.client)


def authenticated_notifications(trace):
    """Read-only readiness helper; final grading additionally verifies every owner/control."""
    latest = None
    values = []
    for row in trace:
        wire = bytes.fromhex(row["hex"])
        if row["direction"] == "request" and wire[1] == 5:
            latest = wire
        elif row["direction"] == "response" and wire[1] == 69 and latest is not None and row["action"] == "forward":
            plain = response_plain(wire, latest)
            if int(plain.code) == 69 and plain.opt.observe is not None:
                values.append((wire, plain.payload))
    return values


def observer_grade(trace, result, endpoints, start, replay, count=3, *, family="ipv4"):
    require(type(count) is int and count in (2,3), "unsupported observation count")
    expected = [str(n).encode() for n in range(start,start+count)]
    expect(result, 69, b",".join(expected))
    require(4 <= len(trace) <= 128, "observer trace outside bound")
    require_relay_family(endpoints, family)
    endpoint = lambda x: loopback_endpoint(x,family)
    front,back,server=(endpoint(endpoints[k]) for k in ("front","back","server"))
    client=endpoint(trace[0]["source"])
    require(len({front,back,server,client})==4,"overlapping owners")
    registration=None
    waiting=False
    pending=None
    optional_replay_ack=None
    bodies=[]; wire_responses=[]; sequences=[]; pivs=[]; response_mids=set(); notification_times=[]
    previous=-1; replay_at=None; final_at=None
    for row in trace:
        direction=row["direction"]
        require(direction in ("request","response"),"invalid direction")
        require(tuple(endpoint(row[k]) for k in ("source","destination","relay"))==
                ((client,server,back) if direction=="request" else (server,client,front)),"endpoint owner mismatch")
        at=row["time_ns"]
        require(type(at) is int and at>previous and at>=0,"invalid trace clock")
        previous=at
        require(at-trace[0]["time_ns"]<20_000_000_000,"observer trace exceeds finite duration")
        wire=bytes.fromhex(row["hex"])
        require(row["hex"]==row["forwarded_hex"] and 4<=len(wire)<=4096 and wire[0]>>6==1,"changed/bad wire")
        mid,ty=wire[2:4],wire[0]>>4&3
        if row["action"]=="replay":
            require(replay and direction=="response" and replay_at is None and len(bodies)==2
                    and pending is None and wire==wire_responses[0],"not intact stale notification after newer value")
            replay_at=at
            optional_replay_ack=mid if ty==0 else None
            continue
        require(row["action"]=="forward","unexpected relay fault")
        if direction=="request":
            if wire[1]==0:
                require(wire==b"\x60\x00"+mid and (mid==pending or mid==optional_replay_ack),"client ACK owner mismatch")
                if mid==pending:pending=None
                if mid==optional_replay_ack:optional_replay_ack=None
                continue
            require(registration is None and ty==0 and wire[1]==5 and set(decoded_options(wire))<={6,9}
                    and 9 in decoded_options(wire),"unexpected registration")
            plain,binding=request_plain(wire)
            require(int(plain.code)==1 and not plain.payload and opts(plain)=={6:[b""],11:[b"counter"]},"wrong authenticated registration")
            require(packet_token(wire),"missing registration token")
            registration=wire;waiting=True
            continue
        require(registration is not None,"response before registration")
        if wire[1]==0:
            require(waiting and wire==b"\x60\x00"+registration[2:4],"wrong registration ACK")
            waiting=False
            continue
        require(wire[1]==69 and packet_token(wire)==packet_token(registration)
                and set(decoded_options(wire))<={6,9} and 9 in decoded_options(wire),"unprotected/wrong-token notification")
        require(pending is None,"overlapping server CON")
        if ty==2:
            require(waiting and not bodies and mid==registration[2:4],"invalid piggyback owner")
            waiting=False
        else:
            require(ty in (0,1) and not waiting,"notification before registration settlement")
            require(mid not in response_mids,"reused server MID")
            response_mids.add(mid)
            if ty==0:pending=mid
        plain=response_plain(wire,registration)
        options=opts(plain)
        require(int(plain.code)==69 and set(options)<={4,6,12,14} and len(options.get(6,[]))==1
                and len(bodies)<count and plain.payload==expected[len(bodies)],"wrong complete authenticated observation")
        sequence=plain.opt.observe
        require(type(sequence) is int and 0<=sequence<2**24,"invalid Observe serial")
        if sequences:require(0<(sequence-sequences[-1])%(2**24)<2**23,"notification not newer")
        _,_,cose,_=oscore.CanUnprotect._extract_encrypted0(incoming(wire))
        piv=cose.get(oscore.COSE_PIV)
        if bodies:require(isinstance(piv,bytes) and 1<=len(piv)<=5,"later notification missing explicit PIV")
        if piv is not None:
            require(piv not in pivs,"distinct notification reused PIV")
            pivs.append(piv)
        bodies.append(plain.payload);sequences.append(sequence);wire_responses.append(wire);notification_times.append(at)
        if len(bodies)==count:final_at=at
    require(len(bodies)==count and not waiting and pending is None and bool(replay_at is not None)==replay,"incomplete observer/replay evidence")
    if replay:require(replay_at<final_at,"replay was after client completion")
    _,binding=request_plain(registration)
    return {"bodies":[b.decode() for b in bodies],"request_piv":bytes(binding.partial_iv).hex(),
            "response_pivs":[p.hex() for p in pivs],"observe_values":sequences,"notification_times_ns":notification_times,"replay_time_ns":replay_at,
            "final_notification_time_ns":final_at,"scope":"intact stale datagram not delivered twice; no attribution to a specific duplicate/replay mechanism"}


def exchange_grade(record, method, body, server_endpoint, *, family="ipv4"):
    """Authenticate bounded ordinary writer/readback exchanges, including ACK controls."""
    expect(record["result"],68 if method==2 else 69,body)
    trace=record["trace"];endpoints=record["endpoints"]
    require(tuple(endpoints["server"])==server_endpoint and 2<=len(trace)<=4,"writer/readback server or trace changed")
    require_relay_family(endpoints, family)
    client=loopback_endpoint(trace[0]["source"],family)
    front,back,server=(loopback_endpoint(endpoints[k],family) for k in ("front","back","server"))
    require(len({client,front,back,server})==4,"overlapping writer/readback owners")
    req=None;response=None;waiting=False;pending=None;previous=-1
    for row in trace:
        direction=row["direction"];wire=bytes.fromhex(row["hex"])
        require(direction in ("request","response") and row["action"]=="forward" and row["hex"]==row["forwarded_hex"],"writer relay fault")
        require(tuple(loopback_endpoint(row[k],family) for k in ("source","destination","relay"))==
                ((client,server,back) if direction=="request" else (server,client,front)),"writer endpoint mismatch")
        require(type(row["time_ns"]) is int and row["time_ns"]>previous,"writer clock mismatch");previous=row["time_ns"]
        require(4<=len(wire)<=4096,"invalid writer datagram")
        ty=wire[0]>>4&3
        if direction=="request":
            if wire[1]==0:
                require(pending is not None and wire==b"\x60\x00"+pending,"wrong writer client ACK");pending=None
            else:
                require(req is None and ty==0 and wire[1]==2,"unexpected writer request")
                plain,_=request_plain(wire)
                require(int(plain.code)==method and not plain.payload and opts(plain)=={11:[b"counter"]},"wrong writer request")
                req=wire;waiting=True
        else:
            require(req is not None,"writer reply before request")
            if wire[1]==0:
                require(waiting and wire==b"\x60\x00"+req[2:4],"writer empty ACK mismatch");waiting=False
            else:
                require(response is None and wire[1]==68 and packet_token(wire)==packet_token(req),"writer response owner")
                if ty==2:require(waiting and wire[2:4]==req[2:4],"writer piggyback owner");waiting=False
                else:require(ty==0 and not waiting,"writer separate owner");pending=wire[2:4]
                response=response_plain(wire,req)
                require(int(response.code)==(68 if method==2 else 69) and response.payload==body,"wrong authenticated effect/readback")
    require(response is not None and not waiting and pending is None,"incomplete writer exchange")
    _,binding=request_plain(req)
    return bytes(binding.partial_iv).hex()


def explicit_server_pivs(trace):
    """Extract new explicit response nonces after the exchange authenticates.

    The one intact stale replay is a repeated delivery, not new generation.
    Ordinary implicit-response nonces remain tied to distinct request bindings.
    """
    for row in trace:
        wire=bytes.fromhex(row["hex"])
        if row["direction"]=="response" and row["action"]=="forward" and wire[1]!=0:
            _,_,cose,_=oscore.CanUnprotect._extract_encrypted0(incoming(wire))
            piv=cose.get(oscore.COSE_PIV)
            if piv is not None:
                require(isinstance(piv,bytes) and 1<=len(piv)<=5
                        and (len(piv)==1 or piv[0]!=0),"noncanonical/invalid explicit server response PIV")
                yield piv


def campaign_review(record,patch,*,family="ipv4"):
    require(family in ("ipv4","ipv6") and record.get("family","ipv4")==family,"campaign family mismatch")
    expect(record["setup"],69,b"0")
    ready=record["server_ready"]
    require(ready.get("transport")=="oscore" and ready.get("libcoap_patch_sha256")==patch["patch_sha256"],"peer provenance changed")
    server=loopback_endpoint(("::1",ready["port"],0,0) if family=="ipv6" else ("127.0.0.1",ready["port"]),family)
    require(len(record["sessions"])==3,"missing campaign session")
    request_pivs=set();response_pivs=set();proofs=[];previous_end=-1
    for index,case in enumerate(record["sessions"]):
        require(case["mode"]==("stale" if index==1 else "baseline" if index==0 else "fresh") and tuple(case["endpoints"]["server"])==server,"session order/server changed")
        proof=observer_grade(case["trace"],case["result"],case["endpoints"],index*2,index==1,family=family)
        require(proof==case["proof"] and len(case["writes"])==2,"retained proof/writer count changed")
        require(case["trace"][0]["time_ns"]>previous_end,"sessions overlap/reorder")
        pivs=[proof["request_piv"]]
        for number,write in enumerate(case["writes"]):
            pivs.append(exchange_grade(write,2,b"",server,family=family))
            require(proof["notification_times_ns"][number]<write["trace"][0]["time_ns"]<proof["notification_times_ns"][number+1],"update outside exact notification interval")
        pivs.append(exchange_grade(case["readback"],1,str(index*2+2).encode(),server,family=family))
        require(case["readback"]["trace"][0]["time_ns"]>case["trace"][-1]["time_ns"],"readback before observer completion")
        previous_end=case["readback"]["trace"][-1]["time_ns"]
        require(len(set(pivs))==4 and not request_pivs.intersection(pivs),"request binding reused")
        request_pivs.update(pivs)
        for trace in [case["trace"],*(w["trace"] for w in case["writes"]),case["readback"]["trace"]]:
            for piv in explicit_server_pivs(trace):
                require(piv not in response_pivs,"server response PIV reused across campaign")
                response_pivs.add(piv)
        if index==1:
            require(case["writes"][0]["trace"][0]["time_ns"]<proof["replay_time_ns"]<case["writes"][1]["trace"][0]["time_ns"],"replay outside authenticated update interval")
            require(case.get("pending_after_replay") is True,"client prematurely completed at replay")
        proofs.append(proof)
    return {"same_server":list(server),"complete_bodies":[p["bodies"] for p in proofs],"intact_stale_replays":1,
            "scope":f"finite {'IPv6' if family=='ipv6' else 'IPv4'} loopback fixture, fresh client per session; no enrollment, cancellation, sustained availability or isolated replay-mechanism claim"}


def campaign(client,server,record,patch,*,family="ipv4"):
    require(family in ("ipv4","ipv6"),"unsupported protected address family")
    record.update(family=family,sessions=[])
    with Server(server,"oscore",family=family) as service:
        record["server_ready"]=service.ready
        require(service.ready.get("libcoap_patch_sha256")==patch["patch_sha256"],"peer patch mismatch")
        record["setup"]=request(client,"oscore",service.number,sequence=0,path="counter",family=family)
        expect(record["setup"],69,b"0")
        for index,mode in enumerate(("baseline","stale","fresh")):
            base=100+index*400
            case={"mode":mode,"writes":[]};record["sessions"].append(case)
            relay=ObserveRelay(service.number,family=family)
            proc=None
            def wait_count(count):
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    values=authenticated_notifications(relay.snapshot())
                    if len(values)>=count:return values
                    require(proc.poll() is None,"observer exited before required update")
                    time.sleep(.01)
                raise AssertionError("notification wait exceeded finite deadline")
            def ordinary(exchange,method,sequence):
                r=Proxy(service.number,"pass",family=family)
                try:
                    with r:
                        exchange["endpoints"]=relay_endpoints(r,family)
                        exchange["result"]=request(client,"oscore",r.number,path="counter",method=method,sequence=sequence,family=family)
                finally:exchange["trace"]=r.trace
                return exchange
            try:
                with relay:
                    case["endpoints"]=relay_endpoints(relay,family)
                    proc=subprocess.Popen(command(client,"client","oscore",relay.number,path="counter",sequence=base,timeout=15000,observe=True,family=family),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    initial=wait_count(1)
                    case["writes"].append({})
                    ordinary(case["writes"][-1],"POST",base+100)
                    wait_count(2)
                    if mode=="stale":
                        # Wait for any current CON ACK before inserting the old datagram.
                        time.sleep(.1)
                        relay.replay(initial[0][0])
                        time.sleep(.15)
                        case["pending_after_replay"]=proc.poll() is None
                        require(case["pending_after_replay"],"stale notification prematurely completed client")
                    case["writes"].append({})
                    ordinary(case["writes"][-1],"POST",base+200)
                    out,err=proc.communicate(timeout=17)
                    lines=out.splitlines()
                    require(len(lines)==1,"observer must report exactly one outcome")
                    case["result"]=decode(lines[0]);case["result"]["exit_code"]=proc.returncode
                    case["stderr_tail"]=err[-2000:].decode(errors="replace")
            finally:
                if proc is not None and proc.poll() is None:proc.kill();proc.communicate()
                case["trace"]=relay.snapshot()
            case["proof"]=observer_grade(case["trace"],case["result"],case["endpoints"],index*2,index==1,family=family)
            case["readback"]={}
            ordinary(case["readback"],"GET",base+300)
    record["proof"]=campaign_review(record,patch,family=family);record["complete"]=True


def main():
    import argparse,hashlib,platform
    from pathlib import Path
    from run import source_identity
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("coaptic","libcoap","libcoap-patch-manifest","output"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--family",choices=("ipv4","ipv6"),default="ipv4")
    args=parser.parse_args();patch=json.loads(args.libcoap_patch_manifest.read_text())
    report={"schema":"coaptic-protected-observe/1",**source_identity(),"platform":platform.platform(),"libcoap_patch":patch,
            "libcoap_source":"851533c3cf63d16984d370ce39d586ecb3694971","executables":{name:{"sha256":hashlib.sha256(path.read_bytes()).hexdigest()} for name,path in (("coaptic",args.coaptic),("libcoap",args.libcoap))},"family":args.family,"qualification_complete":False,"campaign":{}}
    try:campaign(args.coaptic.resolve(),args.libcoap.resolve(),report["campaign"],patch,family=args.family);report["qualification_complete"]=True
    except Exception as error:report["error"]=f"{type(error).__name__}: {error}"
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes((json.dumps(report,indent=2)+"\n").encode())
    print(json.dumps({"qualification_complete":report["qualification_complete"],"report":str(args.output)}))
    return 0 if report["qualification_complete"] else 1


if __name__=="__main__":raise SystemExit(main())
