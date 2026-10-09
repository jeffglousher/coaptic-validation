"""Explicit release builds and manifest creation; never part of timed execution."""
import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from campaign import SCHEMA, host, write_new

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def invoke(command, cwd=ROOT, env=None):
    subprocess.run([str(item) for item in command], cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, default=ROOT / "target" / "benchmark-native")
    parser.add_argument("--go", default="go")
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--libcoap-source", type=Path)
    parser.add_argument("--libcoap-bin", type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--peers", default="coaptic,coap-rs,coap-lite-codec,aiocoap,libcoap,go-coap,http3")
    parser.add_argument("--uvloop", action="store_true")
    parser.add_argument("--coaptic-rx-bytes", type=int, choices=(1472, 2048), default=1472)
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
            build = target / "libcoap"
            invoke([args.cmake, "-S", HERE / "peers" / "libcoap", "-B", build, "-DCMAKE_BUILD_TYPE=Release", "-DLIBCOAP_SOURCE=" + str(args.libcoap_source.resolve())])
            invoke([args.cmake, "--build", build, "--config", "Release", "--parallel", "2"])
            binary = build / "Release" / ("bench-libcoap" + suffix) if os.name == "nt" else build / "bench-libcoap"
        peers.append({"id": "libcoap", "protocol": "coap", "server": [str(binary), "{host}", "{port}", "{bytes}"], "driver": driver,
                      "identity": {"source": "851533c3cf63d16984d370ce39d586ecb3694971", "binary_source_verified": not bool(args.libcoap_bin),
                                   "build": "Release; UDP; library-managed blockwise; no per-request logging" if not args.libcoap_bin else "externally supplied binary; source/build association asserted by caller"}})
    for peer in peers:
        peer["security"] = "plaintext" if peer["protocol"] == "coap" else "TLS1.3"
    cases = []
    for size, operations in ((64, 256), (1024, 128), (65536, 16)):
        for concurrency in (1, 4, 16):
            for protocol, modes, security in (("coap", ("con", "non"), "plaintext"), ("http3", ("warm", "cold"), "TLS1.3")):
                if not any(p["protocol"] == protocol for p in peers):
                    continue
                for mode in modes:
                    cases.append({"id": f"{protocol}-{mode}-{size}-{concurrency}", "protocol": protocol, "security": security, "bytes": size,
                                  "concurrency": concurrency, "operations": max(operations, concurrency), "warmup": 1, "timeout_ms": 1000, "mode": mode})
    write_new(args.output, {"schema": SCHEMA, "peers": peers, "cases": cases,
                            "campaign_policy": {"minimum_session_gap_seconds": 60}, "created_on": platform.platform(),
                            "runtime_environment": host()["runtime_environment"],
                            "build_environment": {key: os.environ.get(key) for key in
                                ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "GOFLAGS", "CGO_ENABLED", "GOTOOLCHAIN")},
                            "scope": "server implementation comparison; closed-loop GET/complete-body transfer; HTTP3 separate secure stratum"})


if __name__ == "__main__":
    main()
