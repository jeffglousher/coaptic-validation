"""Manual Linux-only addressing proof in freshly owned network namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import secrets
import subprocess
import sys
import threading

BODY = b"coaptic-scoped-addressing".hex()
OUTPUT_LIMIT = 256 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def namespace_identity(name):
    value = (Path("/var/run/netns") / name).stat()
    return [value.st_dev, value.st_ino]


class Topology:
    def __init__(self, report):
        self.report = report
        self.token = "cq3-" + secrets.token_hex(4)
        self.names = {role: self.token + "-" + role for role in ("c", "r", "s")}
        self.created = {}
        self.interfaces = {}
        report["ownership"] = {"token": self.token, "namespaces": self.names,
                               "created": self.created, "interfaces": self.interfaces}
        self.links = {}

    def command(self, *argv):
        # The finite ip/sysctl inventory runs on an isolated runner. This check
        # bounds retained evidence after capture; it is not a streaming memory
        # limit for an arbitrary subprocess. Peer traces have producer limits.
        result = subprocess.run(argv, capture_output=True, timeout=10, text=True)
        require(len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT, "command output exceeded bound")
        self.report.setdefault("commands", []).append({"argv": list(argv), "exit": result.returncode,
                                                        "stdout": result.stdout, "stderr": result.stderr})
        require(result.returncode == 0, "command failed: " + repr(argv))
        return result.stdout

    def ns(self, role, *argv):
        return self.command("ip", "netns", "exec", self.names[role], *argv)

    def pair(self, left_role, left_name, right_role, right_name, label):
        left, right = "q3" + self.token[-8:] + label + "a", "q3" + self.token[-8:] + label + "b"
        self.command("ip", "link", "add", left, "type", "veth", "peer", "name", right)
        for name, peer in ((left, right), (right, left)):
            self.interfaces[name] = {"namespace": None, "name": name,
                                     "ifindex": None, "alias": None, "peer": peer}
        for name in (left, right):
            row = json.loads(self.command("ip", "-j", "link", "show", "dev", name))[0]
            self.interfaces[name]["ifindex"] = row["ifindex"]
        for name in (left, right):
            self.command("ip", "link", "set", "dev", name, "alias", self.token)
            self.interfaces[name]["alias"] = self.token
        for original, role, name in ((left, left_role, left_name), (right, right_role, right_name)):
            self.command("ip", "link", "set", original, "netns", self.names[role])
            entry = self.interfaces[original]
            entry.update(namespace=self.names[role], ifindex=None)
            row = json.loads(self.command("ip", "-n", self.names[role], "-j", "link", "show", "dev", original))[0]
            require(row.get("ifalias") == entry["alias"], "moved interface alias changed")
            entry["ifindex"] = row["ifindex"]
            self.command("ip", "-n", self.names[role], "link", "set", original, "name", name)
            entry["name"] = name
            self.command("ip", "-n", self.names[role], "link", "set", "dev", name, "addrgenmode", "none")
            self.command("ip", "-n", self.names[role], "link", "set", "dev", name, "mtu", "1500", "up")

    def create(self):
        require(platform.system() == "Linux" and os.geteuid() == 0, "requires isolated Linux runner with CAP_NET_ADMIN/root")
        existing = {row.split()[0] for row in self.command("ip", "netns", "list").splitlines() if row.strip()}
        require(not existing.intersection(self.names.values()), "namespace name already exists; refusing adoption")
        for name in self.names.values():
            self.command("ip", "netns", "add", name)
            self.created[name] = None
            self.created[name] = namespace_identity(name)
            self.command("ip", "-n", name, "link", "set", "lo", "up")
        self.pair("c", "c0", "r", "r0", "l")
        self.pair("r", "r1", "s", "s0", "r")
        for role, interface, global_ip, local_ip in (
                ("c", "c0", "fd42:c0a:1::2", "fe80::c"),
                ("r", "r0", "fd42:c0a:1::1", "fe80::1"),
                ("r", "r1", "fd42:c0a:2::1", "fe80::2"),
                ("s", "s0", "fd42:c0a:2::2", "fe80::5")):
            for address in (global_ip, local_ip):
                self.command("ip", "-n", self.names[role], "-6", "addr", "add", address + "/64", "dev", interface, "nodad")
        self.ns("r", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
        self.command("ip", "-n", self.names["c"], "-6", "route", "add", "fd42:c0a:2::/64", "via", "fd42:c0a:1::1", "dev", "c0")
        self.command("ip", "-n", self.names["s"], "-6", "route", "add", "fd42:c0a:1::/64", "via", "fd42:c0a:2::1", "dev", "s0")
        self.report["topology"] = {}
        for role, name in self.names.items():
            links = json.loads(self.command("ip", "-n", name, "-j", "link"))
            self.links[role] = {row["ifname"]: row["ifindex"] for row in links}
            self.report["topology"][role] = {"links": links,
                "addresses": json.loads(self.command("ip", "-n", name, "-j", "-6", "addr")),
                "routes": json.loads(self.command("ip", "-n", name, "-j", "-6", "route"))}

    def verify_interfaces(self, namespace, removed):
        prefix = ("ip", "-n", namespace) if namespace else ("ip",)
        current = {row["ifname"]: row for row in json.loads(self.command(*prefix, "-j", "link"))}
        expected = {entry["name"]: (key, entry) for key, entry in self.interfaces.items()
                    if entry["namespace"] == namespace}
        if namespace:
            require(set(current) - {"lo"} <= set(expected), "unknown interface in namespace: " + namespace)
        for name, (key, entry) in expected.items():
            row = current.get(name)
            if row is None:
                require(key in removed, "owned interface missing before cleanup: " + name)
                continue
            # Namespace destruction can release a veth peer asynchronously.
            # A still-present member must retain its exact owned identity;
            # its absence is permitted only after recorded peer cleanup.
            require(entry["ifindex"] is not None and row["ifindex"] == entry["ifindex"]
                    and row.get("ifalias") == entry["alias"], "interface ownership changed: " + name)
            peer = self.interfaces[entry["peer"]]
            if "link_index" in row:
                require(peer["ifindex"] is not None and row["link_index"] == peer["ifindex"],
                        "interface peer changed: " + name)

    def verify_namespace(self, name, identity, removed):
        require((Path("/var/run/netns") / name).exists(), "owned namespace disappeared: " + name)
        require(namespace_identity(name) == identity, "namespace ownership changed: " + name)
        require(not self.command("ip", "netns", "pids", name).strip(), "unknown process remains in owned namespace: " + name)
        self.verify_interfaces(name, removed)

    def cleanup(self):
        removed = set()
        try:
            # Preflight every namespace and both ends before deleting any pair.
            # A foreign member anywhere retains the topology for inspection.
            for name, identity in self.created.items():
                self.verify_namespace(name, identity, removed)
            if self.interfaces:
                self.verify_interfaces(None, removed)
            for name, identity in reversed(list(self.created.items())):
                self.verify_namespace(name, identity, removed)
                self.command("ip", "netns", "delete", name)
                for key, entry in self.interfaces.items():
                    if entry["namespace"] == name:
                        removed.update((key, entry["peer"]))
            for key, entry in self.interfaces.items():
                if entry["namespace"] is not None or key in removed:
                    continue
                # Query again for each deletion: deleting one veth removes its peer.
                self.verify_interfaces(None, removed)
                self.command("ip", "link", "delete", "dev", entry["name"])
                removed.update((key, entry["peer"]))
            self.report["cleanup"] = {"complete": True, "retained_reasons": []}
        except Exception as error:
            self.report["cleanup"] = {"complete": False, "retained_reasons": [str(error)]}


def records(output):
    require(len(output) <= OUTPUT_LIMIT, "peer output exceeded bound")
    result = [json.loads(line) for line in output.splitlines() if line.strip()]
    require(len(result) <= 68 and all(isinstance(row, dict) for row in result), "invalid peer records")
    return result


def command(args, implementation, server, bind_host, bind_scope, remote_host=None, remote_scope=0):
    if implementation == "coaptic":
        bind = f"[{bind_host}{'%' + str(bind_scope) if bind_scope else ''}]:{56830 if server else 0}"
        if server:
            return [str(args.rust_peer), "server", bind, "10000"]
        remote = f"[{remote_host}{'%' + str(remote_scope) if remote_scope else ''}]:56830"
        return [str(args.rust_peer), "client", bind, remote, "1000"]
    argv = [sys.executable, str(args.independent), "server" if server else "client",
            "--bind-host", bind_host, "--bind-port", "56830" if server else "0",
            "--bind-scope", str(bind_scope), "--timeout", "10" if server else "1"]
    if not server:
        argv += ["--remote-host", remote_host, "--remote-port", "56830", "--remote-scope", str(remote_scope)]
    return argv


def client_run(topology, argv):
    full = ["ip", "netns", "exec", topology.names["c"], *argv]
    result = subprocess.run(full, capture_output=True, timeout=5, text=True)
    require(len(result.stderr) <= OUTPUT_LIMIT, "client stderr exceeded bound")
    return {"argv": full, "exit": result.returncode, "records": records(result.stdout), "stderr": result.stderr}


def success(result, expected_scope):
    require(result["exit"] == 0, "client failed")
    rows = result["records"]
    require(any(row.get("event") == "complete" and row.get("hex") == BODY and row.get("code") == 69 for row in rows), "missing exact successful application response")
    incoming = [row for row in rows if row.get("event") == "receive"]
    require(len(incoming) == 1, "unexpected received packet count")
    row = incoming[0]
    scope = row.get("scope_id") if "scope_id" in row else row["peer"][3]
    require(scope == expected_scope, "actual received scope differs")


def scenario(args, topology, client_impl, scoped):
    record = {"client": client_impl, "scoped": scoped, "clients": []}
    server_impl = "python" if client_impl == "coaptic" else "coaptic"
    server_role, server_if = ("r", "r0") if scoped else ("s", "s0")
    client_host, server_host = ("fe80::c", "fe80::1") if scoped else ("fd42:c0a:1::2", "fd42:c0a:2::2")
    client_scope = topology.links["c"]["c0"] if scoped else 0
    server_scope = topology.links[server_role][server_if] if scoped else 0
    argv = ["ip", "netns", "exec", topology.names[server_role],
            *command(args, server_impl, True, server_host, server_scope)]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    record["server"] = {"argv": argv, "pid": process.pid}
    first = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: first.put(process.stdout.readline(8193)), daemon=True).start()
    ready_line = ""
    try:
        ready_line = first.get(timeout=3)
        ready = records(ready_line)
        require(len(ready) == 1 and ready[0].get("event") == "ready", "server did not become ready")
        for wrong in ((False, True, False) if scoped else (False,)):
            target_scope = topology.links["c"]["lo"] if wrong else client_scope
            result = client_run(topology, command(args, client_impl, False, client_host, client_scope, server_host, target_scope))
            record["clients"].append(result)
            if not wrong:
                success(result, client_scope)
            else:
                require(result["exit"] == 1 and not any(row.get("event") == "complete" for row in result["records"]), "wrong zone accepted")
                io_errors = [row for row in result["records"] if row.get("event") == "io-error" or row.get("errno") is not None]
                record["wrong_zone"] = {"scope": target_scope, "io_error": io_errors,
                    "disposition": "actual caller I/O error" if io_errors else "bounded failure; no actual socket-error claim"}
        record["status"] = "passed"
    except Exception as error:
        record["status"], record["error"] = "failed", repr(error)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            rest, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            rest, stderr = process.communicate(timeout=2)
        record["server"].update(exit=process.returncode, records=records(ready_line + rest), stderr=stderr)
    if record["status"] == "passed":
        received = [row for row in record["server"]["records"] if row.get("event") == "receive"]
        expected = 2 if scoped else 1
        if len(received) != expected:
            record["status"], record["error"] = "failed", "server admitted unexpected traffic during wrong-zone sequence"
        else:
            successful = [record["clients"][0], record["clients"][-1]] if scoped else record["clients"]
            sent = [next(row["hex"] for row in value["records"] if row.get("event") == "send-attempt") for value in successful]
            if [row["hex"] for row in received] != sent:
                record["status"], record["error"] = "failed", "independent server capture differs from sent bytes"
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="create only newly owned Linux namespaces for this finite run")
    parser.add_argument("--rust-peer", required=True, type=Path)
    parser.add_argument("--independent", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--build-record", required=True, type=Path)
    parser.add_argument("--mode", choices=("addressing", "network-errors"), default="addressing")
    args = parser.parse_args()
    args.rust_peer = args.rust_peer.resolve(strict=True)
    args.independent = args.independent.resolve(strict=True)
    report = {"schema":"coaptic-scoped-routed/1", "platform":platform.platform(), "applied":args.apply,
              "files":{str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in (args.rust_peer,args.independent)},
              "cases":[], "mode":args.mode, "pmtu":"see host-pmtu-icmp6 case" if args.mode == "network-errors" else "not executed by this scoped/routed fixture"}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    def save():
        args.report.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    if not args.apply:
        report["plan"] = "Three new owned Linux namespaces; addressing mode runs four directions; network-errors mode runs two separate compound/PMTU cases. No runtime change without --apply."
        save()
        return 0
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from source_identity import source_identity
    identity = source_identity()
    require(not identity["dirty"] and not identity["suite_dirty"], "clean committed runner/core source required")
    build = json.loads(args.build_record.read_text(encoding="utf-8"))
    require(build["source"] == identity["source"] and build["suite_source"] == identity["suite_source"], "build source identity mismatch")
    require(build["executable_sha256"] == report["files"][str(args.rust_peer)], "binary build identity mismatch")
    report["source_identity"] = identity
    report["build_record"] = build
    topology = Topology(report)
    try:
        topology.create()
        save()
        if args.mode == "network-errors":
            from network_errors import compound, pmtu
            for case in (compound, pmtu):
                report["cases"].append(case(args,topology))
                save()
        else:
            for scoped in (True,False):
                for implementation in ("coaptic","python"):
                    report["cases"].append(scenario(args,topology,implementation,scoped))
                    save()
    except Exception as error:
        report["error"] = repr(error)
    finally:
        try:
            topology.cleanup()
        except Exception as error:
            report["cleanup"] = {"complete": False, "retained_reasons": [repr(error)]}
        save()
    report["source_identity_after"] = source_identity()
    if report["source_identity_after"] != identity:
        report["error"] = "sources changed during qualification"
    save()
    passed = len(report["cases"]) == (2 if args.mode == "network-errors" else 4) and all(row["status"] == "passed" for row in report["cases"])
    return not(passed and report.get("cleanup",{}).get("complete") and "error" not in report)


if __name__ == "__main__":
    raise SystemExit(main())
