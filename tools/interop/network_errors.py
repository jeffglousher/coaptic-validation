"""Two finite follow-on cases using the already reviewed owned topology."""
from contextlib import contextmanager
from pathlib import Path
import queue
import subprocess
import sys
import threading

from scoped_topology import command, records, require, success, OUTPUT_LIMIT


@contextmanager
def peer(topology, role, argv, evidence):
    full = ["ip","netns","exec",topology.names[role],*argv]
    process = subprocess.Popen(full,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    evidence.update(argv=full,pid=process.pid)
    first = queue.Queue(maxsize=1)
    threading.Thread(target=lambda:first.put(process.stdout.readline(8193)),daemon=True).start()
    line = ""
    try:
        line = first.get(timeout=3)
        ready = records(line)
        require(len(ready) == 1 and ready[0].get("event") == "ready", "peer did not become ready")
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            rest, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            rest, stderr = process.communicate(timeout=2)
        require(len(stderr) <= OUTPUT_LIMIT, "peer error output exceeded evidence limit")
        evidence.update(exit=process.returncode,records=records(line+rest),stderr=stderr)


def invoke(topology, role, argv, timeout):
    full = ["ip","netns","exec",topology.names[role],*argv]
    result = subprocess.run(full,capture_output=True,text=True,timeout=timeout)
    require(len(result.stderr) <= OUTPUT_LIMIT, "client error output exceeded evidence limit")
    return dict(argv=full,exit=result.returncode,records=records(result.stdout),stderr=result.stderr)


def pmtu(args, topology):
    result = {"name":"host-pmtu-icmp6","server":{},"status":"failed"}
    # These are exclusively created interfaces, with their original ownership
    # ledger retained. There is no host route, host sysctl or App pool change.
    for role, name in (("r","r1"),("s","s0")):
        topology.verify_namespace(topology.names[role],topology.created[topology.names[role]],set())
        topology.command("ip","-n",topology.names[role],"link","set","dev",name,"mtu","1280")
    try:
        with peer(topology,"s",command(args,"coaptic",True,"fd42:c0a:2::2",0),result["server"]):
            result["client"] = invoke(topology,"c",[sys.executable,str(Path(__file__).with_name("pmtu_peer.py")),
                "--local","fd42:c0a:1::2","--remote","fd42:c0a:2::2","--router","fd42:c0a:1::1"],8)
        rows = result["client"]["records"]
        require(result["client"]["exit"] == 0 and len(rows) == 1 and rows[0]["status"] == "passed",
                "host PMTU witness failed")
        incoming = [row for row in result["server"]["records"] if row.get("event") == "receive"]
        require(len(incoming) == 1 and incoming[0]["hex"] == rows[0]["fresh"]["request_hex"],
                "server did not receive exactly the fresh small request")
        result["status"] = "passed"
    except Exception as error:
        result["error"] = repr(error)
    return result


def compound(args, topology):
    result = {"name":"routed-loss-malformed-fresh","server":{},"relay":{},"clients":[],"status":"failed"}
    server = command(args,"python",True,"fd42:c0a:2::2",0)
    server[-1] = "20"
    relay = [sys.executable,str(Path(__file__).with_name("compound_relay.py")),
             "--front","fd42:c0a:1::1","--back","fd42:c0a:2::1","--remote","fd42:c0a:2::2"]
    try:
        with peer(topology,"s",server,result["server"]):
            with peer(topology,"r",relay,result["relay"]) as running:
                for _ in range(2):
                    value = invoke(topology,"c",[str(args.rust_peer),"client","[fd42:c0a:1::2]:0",
                                   "[fd42:c0a:1::1]:56831","8000"],10)
                    result["clients"].append(value)
                    require(value["exit"] == 0, "compound client did not recover")
                running.wait(timeout=2)
        complete = [row for row in result["relay"]["records"] if row.get("event") == "complete"]
        require(result["relay"]["exit"] == 0 and len(complete) == 1, "relay schedule not completed")
        from compound_relay import grade
        trace = complete[0]["trace"]
        require(grade(trace) == complete[0]["result"], "relay summary differs from exact trace")
        requests = [row["hex"] for row in trace if row["event"] == "request"]
        received = [row["hex"] for row in result["server"]["records"] if row.get("event") == "receive"]
        require(received == requests, "independent server capture differs from relayed requests")
        injected = [row["hex"] for row in trace if row["event"] == "inject"]
        forwarded = [row["hex"] for row in trace if row["event"] == "response" and row["action"] == "forward"]
        first_received = [row["hex"] for row in result["clients"][0]["records"] if row.get("event") == "receive"]
        require(first_received == injected + forwarded[:1], "client did not receive exact malformed/unmatched/recovered sequence")
        # The first client intentionally receives malformed/unmatched packets;
        # its App validates the final response. The fresh call has one packet.
        success(result["clients"][1],0)
        result["status"] = "passed"
    except Exception as error:
        result["error"] = repr(error)
    return result
