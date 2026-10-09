import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys


REVISION = "0363bd3af02265e919e888b60ccffb4606b68f16"
REMOTE = "https://github.com/kamil-kielbasa/libedhoc.git"
SUBMODULES = {
    "externals/Unity": "73237c5d224169c7b4d2ec8321f9ac92e8071708",
    "externals/compact25519": "1ed9c87ab6ed3bcbbb783289ea14e077a40ef127",
    "externals/mbedtls": "0fe989b6b514192783c469039edd325fd0989806",
    "externals/mbedtls/framework": "dff9da04438d712f7647fd995bc90fadd0c0e2ce",
    "externals/mbedtls/tf-psa-crypto": "29160dd877d29658279fd683b2ae57b320ddcf09",
    "externals/mbedtls/tf-psa-crypto/drivers/pqcp/mldsa-native": "5772b4f4a0105694b1203abb582273f78fa951b7",
    "externals/mbedtls/tf-psa-crypto/framework": "dff9da04438d712f7647fd995bc90fadd0c0e2ce",
    "externals/zcbor": "d3093b5684f62268c7f27f8a5079f166772619de",
}
TIMESTAMP_HEADER = "backends/log/include/edhoc_backend_log.h"
ORIGINAL_TIME = "\ttm_info = localtime(&tv.tv_sec);"
FIXED_TIME = "\tconst time_t timestamp = (time_t)tv.tv_sec;\n\ttm_info = localtime(&timestamp);"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(arguments):
    fixture = Path(__file__).resolve().parent
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    evidence = arguments.build / "evidence" / timestamp
    evidence.mkdir(parents=True)
    report = {
        "schema": "coaptic-libedhoc-build/1",
        "source": str(arguments.source),
        "build": str(arguments.build),
        "revision": REVISION,
        "network_preparation_requested": arguments.prepare,
        "mingw_time_fix_requested": arguments.apply_mingw_time_fix,
        "python": sys.version,
        "commands": [],
        "source_revisions": {},
        "fixture_sha256": {path.name: digest(path) for path in fixture.iterdir() if path.is_file()},
    }
    output = evidence / "manifest.json"

    def save():
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    def run(phase, command):
        record = {"phase": phase, "argv": list(map(str, command))}
        report["commands"].append(record)
        save()
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        try:
            result = subprocess.run(record["argv"], capture_output=True, timeout=arguments.timeout, **options)
            record["exit_code"] = result.returncode
            record["stdout"] = result.stdout.decode("utf-8", errors="replace")
            record["stderr"] = result.stderr.decode("utf-8", errors="replace")
            save()
            require(result.returncode == 0, f"{phase} failed with exit {result.returncode}")
            return record["stdout"]
        except subprocess.TimeoutExpired as error:
            record["timed_out"] = True
            record["stdout"] = (error.stdout or b"").decode("utf-8", errors="replace")
            record["stderr"] = (error.stderr or b"").decode("utf-8", errors="replace")
            save()
            raise

    try:
        if arguments.prepare:
            if not (arguments.source / ".git").exists():
                require(not arguments.source.exists() or not any(arguments.source.iterdir()), "source must be absent or an empty directory for preparation")
                arguments.source.mkdir(parents=True, exist_ok=True)
                run("git-init", ["git", "init", str(arguments.source)])
            run("git-fetch-pinned", ["git", "-C", str(arguments.source), "fetch", "--depth=1", REMOTE, REVISION])
            run("git-checkout-pinned", ["git", "-C", str(arguments.source), "checkout", "--detach", REVISION])
            run("git-submodules-pinned", ["git", "-C", str(arguments.source), "submodule", "update", "--init", "--recursive", "--depth=1", "externals/mbedtls", "externals/zcbor", "externals/compact25519", "externals/Unity"])
        revision = run("git-revision", ["git", "-C", str(arguments.source), "rev-parse", "HEAD"]).strip()
        require(revision == REVISION, "unexpected libedhoc revision")
        report["source_revisions"]["libedhoc"] = revision
        initial_status = run("git-status-before", ["git", "-C", str(arguments.source), "status", "--porcelain", "--untracked-files=no"])
        allowed = {" M " + TIMESTAMP_HEADER}
        require(all(line in allowed for line in initial_status.splitlines()), "libedhoc has unexpected tracked modifications")
        original = subprocess.check_output(["git", "-C", str(arguments.source), "show", "HEAD:" + TIMESTAMP_HEADER]).decode("utf-8").replace("\r\n", "\n")
        require(original.count(ORIGINAL_TIME) == 1, "unexpected logging header timestamp code")
        fixed = original.replace(ORIGINAL_TIME, FIXED_TIME)
        header = arguments.source / TIMESTAMP_HEADER
        current = header.read_text(encoding="utf-8-sig")
        require(current.rstrip("\n") in (original.rstrip("\n"), fixed.rstrip("\n")), "logging header has unexpected changes")
        if arguments.apply_mingw_time_fix:
            header.write_bytes(fixed.encode("utf-8"))
        else:
            require(current.rstrip("\n") == original.rstrip("\n"), "existing MinGW patch requires explicit --apply-mingw-time-fix")
        report["logging_header_sha256"] = digest(header)
        report["applied_patch"] = str(fixture / "mingw-time.patch") if arguments.apply_mingw_time_fix else None
        run("git-source-diff", ["git", "-C", str(arguments.source), "diff", "--", TIMESTAMP_HEADER])
        for relative, expected in SUBMODULES.items():
            source = arguments.source / relative
            actual = run("revision-" + relative, ["git", "-C", str(source), "rev-parse", "HEAD"]).strip()
            require(actual == expected, "unexpected dependency revision: " + relative)
            require(not run("status-" + relative, ["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"]).strip(), "modified dependency: " + relative)
            report["source_revisions"][relative] = actual
        report["python_packages"] = {}
        for name in ("Jinja2", "jsonschema", "blake3"):
            report["python_packages"][name] = importlib.metadata.version(name)
        run("cmake-version", [arguments.cmake, "--version"])
        compiler = arguments.compiler or ("clang" if os.name == "nt" else "cc")
        run("compiler-version", [compiler, "--version"])
        command = [arguments.cmake, "-S", fixture, "-B", arguments.build, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release", "-DLIBEDHOC_SOURCE=" + str(arguments.source), "-DCMAKE_C_COMPILER=" + str(compiler), "-DPython3_EXECUTABLE=" + sys.executable]
        if arguments.ninja:
            command.append("-DCMAKE_MAKE_PROGRAM=" + str(arguments.ninja))
        if arguments.perl:
            command.append("-DPERL_EXECUTABLE=" + str(arguments.perl))
        run("configure", command)
        run("build", [arguments.cmake, "--build", arguments.build, "--target", "libedhoc-peer", "--parallel", "2"])
        executable = arguments.build / ("libedhoc-peer.exe" if os.name == "nt" else "libedhoc-peer")
        require(executable.is_file(), "peer executable was not built")
        report["executable"] = {"path": str(executable), "sha256": digest(executable)}
        cache = (arguments.build / "CMakeCache.txt").read_text(encoding="utf-8")
        report["configuration"] = {
            line.split("=", 1)[0]: line.split("=", 1)[1]
            for line in cache.splitlines()
            if "=" in line and line.startswith(("CONFIG_LIBEDHOC_", "CMAKE_C_COMPILER:", "CMAKE_BUILD_TYPE:", "GEN_FILES:", "ENABLE_TESTING:", "ENABLE_PROGRAMS:", "Python3_EXECUTABLE:", "PERL_EXECUTABLE:", "LIBEDHOC_ENABLE_"))
        }
        report["result"] = "passed"
    except BaseException as error:
        report["result"] = "failed"
        report["error"] = repr(error)
    save()
    print(json.dumps({"result": report["result"], "manifest": str(output), "executable": report.get("executable")}))
    return 0 if report["result"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description="Build the pinned host-only independent EDHOC peer; archive all commands and source revisions.", epilog="Install tool dependencies explicitly: python -m pip install -r tools/interop/libedhoc/requirements.txt. Existing source builds never perform network operations without --prepare.")
    parser.add_argument("--source", required=True, type=Path, help="libedhoc checkout; exact pinned revision is required")
    parser.add_argument("--build", required=True, type=Path, help="separate host build and timestamped evidence directory")
    parser.add_argument("--cmake", default="cmake", help="CMake executable")
    parser.add_argument("--compiler", help="GCC/Clang C compiler executable")
    parser.add_argument("--ninja", type=Path, help="Ninja executable when absent from PATH")
    parser.add_argument("--perl", type=Path, help="Perl executable when absent from PATH")
    parser.add_argument("--prepare", action="store_true", help="explicitly allow fetching the pinned libedhoc revision and recorded submodules")
    parser.add_argument("--apply-mingw-time-fix", action="store_true", help="explicitly apply the reviewed logging-only time_t conversion in mingw-time.patch")
    parser.add_argument("--timeout", type=float, default=300, help="per-command timeout in seconds; timeouts fail qualification")
    arguments = parser.parse_args()
    arguments.source = arguments.source.resolve()
    arguments.build = arguments.build.resolve()
    require(arguments.timeout > 0, "timeout must be positive")
    return build(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
