"""Explicit release builds and manifest creation; never part of timed execution."""
import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from campaign import SCHEMA, digest, host, write_new

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def invoke(command, cwd=ROOT, env=None):
    subprocess.run([str(item) for item in command], cwd=cwd, env=env, check=True)


def source_identity(directory):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(directory), *args], text=True).strip()
    return {"revision": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "status": git("status", "--porcelain")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, default=ROOT / "target" / "benchmark-native")
    parser.add_argument("--go", default="go")
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--libcoap-source", type=Path)
    parser.add_argument("--libcoap-bin", type=Path)
    parser.add_argument("--libcoap-build", type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--peers", default="coaptic,coap-rs,coap-lite-codec,aiocoap,libcoap,go-coap,http3")
    parser.add_argument("--uvloop", action="store_true")
    parser.add_argument("--coaptic-rx-bytes", type=int, choices=(1472, 2048), default=1472)
    parser.add_argument("--matched-oscore", action="store_true",
                        help="matched Python UDP driver for plaintext and supported OSCORE servers")
    args = parser.parse_args()
    selected = args.peers.split(",")
    allowed = {"coaptic", "coaptic-reusable", "coap-rs", "coap-lite-codec", "aiocoap", "libcoap", "go-coap", "http3"}
    if not set(selected) <= allowed or len(set(selected)) != len(selected):
        parser.error("unknown or repeated peer")
    target = args.build_root.resolve()
    target.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), GOCACHE=str(target / "go-build"), GOMODCACHE=str(target / "go-mod"))
    suffix = ".exe" if os.name == "nt" else ""
    invoke(["cargo", "build", "--release", "--locked", "--manifest-path", HERE / "native" / "Cargo.toml"], env=env)
    driver = [str(target / "release" / ("bench-load" + suffix)), "{host}", "{port}", "{bytes}", "{concurrency}", "{operations}", "{warmup}", "{timeout_ms}", "{mode}"]
    rust = target / "release" / ("bench-rust-server" + suffix)
    peers = []
    rust_version = subprocess.check_output(["rustc", "--version"], text=True).strip()
    for name in selected:
        if name in ("coaptic", "coaptic-reusable", "coap-rs", "coap-lite-codec"):
            is_coaptic = name in ("coaptic", "coaptic-reusable")
            server = [str(rust), name, "{host}", "{port}", "{bytes}"]
            if is_coaptic:
                server.append(str(args.coaptic_rx_bytes))
            peers.append({"id": name, "protocol": "coap", "server": server, "driver": driver,
                          "identity": {"implementation": name, "compiler": rust_version, "profile": "release thin-LTO; no per-request logs", "runtime": "two Tokio workers" if name == "coap-rs" else "one socket thread", "scope": "codec fixture" if name == "coap-lite-codec" else "App/server library",
                                       "coaptic_transport": {"adapter": "UdpSocketIo" if name == "coaptic-reusable" else "UdpSocket", "reusable_scratch_bytes": 2049 if name == "coaptic-reusable" else 0} if is_coaptic else None,
                                       "coaptic_capacities": {"rx_datagrams": 4, "tx_datagrams": 4, "rx_datagram_bytes": args.coaptic_rx_bytes, "tx_datagram_bytes": 1472, "dedup": 8, "rx_bodies": 1, "tx_bodies": 2, "body_bytes": "representation rounded up to 1024"} if is_coaptic else None}})
    if "aiocoap" in selected:
        identity_code = "import aiocoap,importlib.metadata,json,pathlib; print(json.dumps({'version':importlib.metadata.version('aiocoap'),'tree':str(pathlib.Path(aiocoap.__file__).parent),'python':__import__('platform').python_version()}))"
        details = json.loads(subprocess.check_output([args.python, "-I", "-c", identity_code], text=True))
        command = [args.python, "-I", str(HERE / "peers" / "aiocoap.py"), "--host", "{host}", "--port", "{port}", "--bytes", "{bytes}"]
        trees = [details.pop("tree")]
        if args.uvloop:
            if os.name == "nt":
                parser.error("uvloop is unsupported on Windows; use the labelled asyncio configuration")
            module = json.loads(subprocess.check_output([args.python, "-I", "-c", "import uvloop,json,pathlib; print(json.dumps({'tree':str(pathlib.Path(uvloop.__file__).parent),'version':uvloop.__version__}))"], text=True))
            trees.append(module["tree"])
            details["uvloop"] = module["version"]
            command.append("--uvloop")
        details["event_loop"] = "uvloop" if args.uvloop else "asyncio"
        peers.append({"id": "aiocoap", "protocol": "coap", "server": command, "driver": driver, "identity": details, "dependency_trees": trees})
    if {"go-coap", "http3"} & set(selected):
        go_dir = HERE / "peers" / "go"
        invoke([args.go, "build", "-mod=readonly", "-trimpath", "-o", target / ("bench-go" + suffix), "."], cwd=go_dir, env=env)
        version = subprocess.check_output([args.go, "version"], text=True).strip()
        for name, protocol in (("go-coap", "coap"), ("http3", "http3")):
            if name not in selected:
                continue
            binary = str(target / ("bench-go" + suffix))
            server = [binary, "server", protocol, "{host}", "{port}", "{bytes}", "{certificate}"]
            client = driver if protocol == "coap" else [binary, "load", "{host}", "{port}", "{bytes}", "{concurrency}", "{operations}", "{warmup}", "{timeout_ms}", "{mode}", "{certificate}"]
            peers.append({"id": name, "protocol": protocol, "server": server, "driver": client,
                          "identity": {"compiler": version, "library": "plgd/go-coap v3.5.4" if protocol == "coap" else "quic-go v0.63.0; HTTP3 only; TLS1.3 certificate verified", "GOMAXPROCS": os.environ.get("GOMAXPROCS", "runtime default")}})
    if "libcoap" in selected:
        if args.libcoap_source is None:
            parser.error("--libcoap-source must name clean pinned 851533c3 source")
        revision = subprocess.check_output(["git", "-C", str(args.libcoap_source), "rev-parse", "HEAD"], text=True).strip()
        if revision != "851533c3cf63d16984d370ce39d586ecb3694971":
            parser.error("unqualified libcoap source")
        invoke(["git", "-C", args.libcoap_source, "diff", "--exit-code", "HEAD"])
        if args.libcoap_bin:
            binary = args.libcoap_bin.resolve()
        else:
            build = args.libcoap_build.resolve() if args.libcoap_build else target / "libcoap"
            # libcoap's own git-describe probe inherits CMake's working directory.
            # Run it in that dependency, not in the companion repository.
            invoke([args.cmake, "-S", HERE / "peers" / "libcoap", "-B", build, "-DCMAKE_BUILD_TYPE=Release", "-DLIBCOAP_SOURCE=" + str(args.libcoap_source.resolve())], cwd=args.libcoap_source.resolve())
            invoke([args.cmake, "--build", build, "--config", "Release", "--parallel", "2"])
            binary = build / "Release" / ("bench-libcoap" + suffix) if os.name == "nt" else build / "bench-libcoap"
        peers.append({"id": "libcoap", "protocol": "coap", "server": [str(binary), "{host}", "{port}", "{bytes}"], "driver": driver,
                      "identity": {"source": "851533c3cf63d16984d370ce39d586ecb3694971", "binary_source_verified": not bool(args.libcoap_bin),
                                   "build": "Release; UDP; library-managed blockwise; no per-request logging" if not args.libcoap_bin else "externally supplied binary; source/build association asserted by caller"}})
    for peer in peers:
        peer["security"] = "plaintext" if peer["protocol"] == "coap" else "TLS1.3"
    unsupported = []
    if args.matched_oscore:
        code = "import aiocoap,cryptography,cbor2,importlib.metadata,json,pathlib; import cryptography.hazmat.bindings._rust as rust; import cbor2._cbor2 as cbor; print(json.dumps({'versions':{n:importlib.metadata.version(n) for n in ('aiocoap','cryptography','cbor2')},'trees':[str(pathlib.Path(m.__file__).parent) for m in (aiocoap,cryptography,cbor2)],'files':[rust.__file__,cbor.__file__]}))"
        crypto = json.loads(subprocess.check_output([args.python, "-I", "-c", code], text=True))
        protected = HERE / "protected"
        # -I removes the script directory; explicitly execute in an isolated
        # interpreter with only the owned helper directory added to sys.path.
        launcher = "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_path(sys.argv.pop(1),run_name='__main__')"
        matched_driver = [args.python, "-I", "-c", launcher, str(protected), str(protected / "load.py")]
        for key in ("host", "port", "bytes", "concurrency", "operations", "warmup", "timeout_ms", "mode", "security", "credentials", "sequence"):
            matched_driver.extend(["--" + key.replace("_", "-"), "{" + key + "}"])
        for peer in list(peers):
            if peer["protocol"] != "coap":
                continue
            peer["driver"] = matched_driver
            peer["dependency_trees"] = list(dict.fromkeys(peer.get("dependency_trees", []) + crypto["trees"] + [str(protected)]))
            peer["dependency_files"] = crypto["files"]
            peer["identity"]["driver_crypto"] = crypto["versions"]
            peer["identity"]["driver_scope"] = "Python/GIL closed-loop including authentication and byte validation; separate from native Rust driver"
            if peer["id"] not in ("coaptic", "coaptic-reusable", "aiocoap"):
                unsupported.append({"peer": peer["id"], "security": "OSCORE-AES-CCM-16-64-128", "reason": "no native OSCORE benchmark fixture supplied"})
                continue
            secure = json.loads(json.dumps(peer))
            secure["id"] += "-oscore"
            secure["security"] = "OSCORE-AES-CCM-16-64-128"
            if peer["id"] == "aiocoap":
                server = [args.python, "-I", "-c", launcher, str(protected), str(protected / "aiocoap_server.py"),
                          "--host", "{host}", "--port", "{port}", "--bytes", "{bytes}"]
                if args.uvloop:
                    server.append("--uvloop")
                peer["server"] = server
                secure["server"] = server + ["--credentials", "{credentials}"]
            else:
                secure["server"].append("{credentials}")
            secure["identity"]["security_profile"] = "RFC 8613 AES-CCM-16-64-128 / HKDF-SHA-256; fresh 24-byte process-lifetime secret/salt; no enrollment or persistence"
            peers.append(secure)
        unsupported.append({"peer": "all", "security": "DTLS", "reason": "no matched DTLS driver/fixture in this matrix; HTTP3 TLS is a separate protocol and cannot substitute"})
    cases = []
    for size, operations in ((64, 256), (1024, 128), (65536, 16)):
        for concurrency in (1, 4, 16):
            strata = sorted({(p["protocol"], p["security"]) for p in peers})
            for protocol, security in strata:
                modes = ("con", "non") if protocol == "coap" else ("warm", "cold")
                if not any(p["protocol"] == protocol and p["security"] == security for p in peers):
                    continue
                for mode in modes:
                    label = "oscore-" if security.startswith("OSCORE") else ""
                    cases.append({"id": f"{protocol}-{label}{mode}-{size}-{concurrency}", "protocol": protocol, "security": security, "bytes": size,
                                  "concurrency": concurrency, "operations": max(operations, concurrency), "warmup": 1, "timeout_ms": 1000, "mode": mode})
    write_new(args.output, {"schema": SCHEMA, "peers": peers, "cases": cases,
                            "unsupported": unsupported,
                            "sources": {"library": source_identity(ROOT / "coaptic"), "suite": source_identity(ROOT),
                                        "native_lock_sha256": digest(HERE / "native" / "Cargo.lock")},
                            "campaign_policy": {"minimum_session_gap_seconds": 60}, "created_on": platform.platform(),
                            "runtime_environment": host()["runtime_environment"],
                            "build_environment": {key: os.environ.get(key) for key in
                                ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "GOFLAGS", "CGO_ENABLED", "GOTOOLCHAIN")},
                            "scope": "server implementation comparison; closed-loop GET/complete-body transfer; HTTP3 separate secure stratum"})


if __name__ == "__main__":
    main()
