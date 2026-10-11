"""Reproduce the narrow source-bound entropy footprint/work comparison.

Each input is a clean validation suite with its clean core checkout at coaptic/.
Build targets are separated by source: sharing a direct-root Cargo target can
reuse a prior checkout's relative-source artifact. No network throughput claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
EXPECTED = {
    "baseline": "9a74f2362040fde40d3b869229b4abf9c319bd35",
    "candidate": "05fd33d6d24888443a4130e83a6c9b5ec7e90c32",
}
SUITE = "fa0db679aae244ecf96dfe3122cdddf94ffbb1ac"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def library_artifact(output, manifest, features):
    """Use the exact emitted artifact, not a guessed fingerprint or relative dep-info."""
    matches = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("reason") != "compiler-artifact" or row.get("target", {}).get("name") != "coaptic":
            continue
        if Path(row["manifest_path"]).resolve() != manifest.resolve():
            raise ValueError("wrong core manifest in compiler artifact")
        if sorted(row["features"]) != sorted(features):
            raise ValueError("wrong core features in compiler artifact")
        matches.extend(Path(name) for name in row["filenames"] if name.endswith(".rlib"))
    if len(matches) != 1:
        raise ValueError("expected exactly one core rlib artifact")
    return matches[0]


def measure(baseline, candidate, output, build_root):
    output.mkdir(parents=True, exist_ok=False)
    if os.environ.get("RUSTFLAGS") or os.environ.get("CARGO_ENCODED_RUSTFLAGS"):
        raise ValueError("remove external Rust flags for this fixed recipe")
    env = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="1")
    commands, rows, sources = [], [], []

    def run(args, cwd, label):
        result = subprocess.run(args, cwd=cwd, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        (output / (label + ".log")).write_text(result.stdout, encoding="utf-8")
        commands.append(dict(args=args, cwd=str(cwd), log=label + ".log", exit_code=result.returncode))
        (output / "commands.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
        if result.returncode:
            raise RuntimeError(f"{label} refused; inspect its retained log")
        return result.stdout

    compiler = run(["rustc", "-Vv"], HERE, "compiler")
    cargo = run(["cargo", "-V"], HERE, "cargo")
    for variant, suite in (("baseline", baseline), ("candidate", candidate)):
        suite = suite.resolve()
        core = suite / "coaptic"
        target = build_root.resolve() / ("measure-" + variant + "-" + EXPECTED[variant])
        env["CARGO_TARGET_DIR"] = str(target)
        for name, path, expected in (("suite", suite, SUITE), ("core", core, EXPECTED[variant])):
            if run(["git", "status", "--porcelain"], path, variant + "-clean-" + name).strip():
                raise ValueError("dirty measurement source")
            if run(["git", "rev-parse", "HEAD"], path, variant + "-revision-" + name).strip() != expected:
                raise ValueError("unexpected measurement revision")
        sources.append(dict(variant=variant, core=EXPECTED[variant], suite=SUITE,
                            core_lock_sha256=sha256(core / "Cargo.lock"),
                            profile_lock_sha256=sha256(suite / "tools/benchmark/native/Cargo.lock")))
        for features in ([], ["std"], ["alloc"], ["std", "alloc"]):
            label = variant + "-" + ("-".join(features) or "none")
            args = ["cargo", "build", "--locked", "--release", "--no-default-features", "--lib", "--message-format=json"]
            if features:
                args += ["--features", ",".join(features)]
            library = library_artifact(run(args, core, label + "-build"), core / "Cargo.toml", features)
            suffix = ".exe" if os.name == "nt" else ""
            binary = output / (label + "-layout" + suffix)
            args = ["rustc", "--edition=2024", "-C", "opt-level=3", str(HERE / "entropy_layout_probe.rs"),
                    "--extern", "coaptic=" + str(library), "-L", "dependency=" + str(target / "release/deps"), "-o", str(binary)]
            for feature in features:
                args += ["--cfg", 'feature="' + feature + '"']
            if variant == "candidate":
                args += ["--cfg", "candidate"]
            run(args, core, label + "-layout-build")
            measurements = [json.loads(line) for line in run([str(binary)], core, label + "-layout").splitlines()]
            row = dict(variant=variant, features=features, library_sha256=sha256(library),
                       binary_sha256=sha256(binary), measurements=measurements)
            if features == ["std", "alloc"]:
                binary = output / (variant + "-exact-size" + suffix)
                run(["rustc", "--edition=2024", "-C", "opt-level=3", str(HERE / "app_size_probe.rs"),
                     "--extern", "coaptic=" + str(library), "-L", "dependency=" + str(target / "release/deps"), "-o", str(binary)], core, variant + "-exact-size-build")
                row["exact_previous_recipe"] = json.loads(run([str(binary)], core, variant + "-exact-size"))
            rows.append(row)
            (output / "sizes.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
        run(["cargo", "build", "--locked", "--release", "--manifest-path", "tools/benchmark/native/Cargo.toml", "-p", "bench-profile"], suite, variant + "-profile-build")
        binary = output / (variant + "-bench-profile" + suffix)
        binary.write_bytes((target / ("release/bench-profile" + suffix)).read_bytes())
        binary.chmod(0o700)
        for size in (64, 65536):
            run([str(binary), str(size), "3"], suite, variant + "-profile-" + str(size))
    provenance = dict(compiler=compiler, cargo=cargo, sources=sources,
                      probes={name: sha256(HERE / name) for name in ("app_size_probe.rs", "entropy_layout_probe.rs")})
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-suite", type=Path, required=True)
    parser.add_argument("--candidate-suite", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    args = parser.parse_args()
    measure(args.baseline_suite, args.candidate_suite, args.output.resolve(), args.build_root)


if __name__ == "__main__":
    main()
