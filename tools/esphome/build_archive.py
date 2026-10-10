"""Build a local ESP32-S3 archive with exact two-repository provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qualification"))
from build_source import build_source

ROOT = Path(__file__).resolve().parents[2]
TARGET = "xtensa-esp32s3-none-elf"
FEATURES = ["network", "standalone"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain", default="coaptic-esp-1.97")
    parser.add_argument("--expected-library-revision", required=True)
    parser.add_argument("--oscore", action="store_true")
    args = parser.parse_args()
    features = FEATURES + (["oscore"] if args.oscore else [])
    try:
        source = build_source(args.expected_library_revision)
    except ValueError as error:
        parser.error(str(error))
    manifest = ROOT / "tools/esphome/rust/Cargo.toml"
    command = ["cargo", "+" + args.toolchain, "rustc", "-Zbuild-std=core", "--locked",
               "--release", "--target", TARGET, "--no-default-features",
               "--features", ",".join(features), "--manifest-path", str(manifest),
               "--crate-type", "staticlib"]
    subprocess.run(command, check=True, cwd=ROOT)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "+" + args.toolchain, "metadata", "--format-version", "1", "--no-deps",
         "--manifest-path", str(manifest)], cwd=ROOT, text=True))
    archive = Path(metadata["target_directory"]) / TARGET / "release/libcoaptic_esphome_probe.a"
    if build_source(args.expected_library_revision) != source:
        raise ValueError("source identity changed during archive compilation")
    files = [ROOT / "coaptic/Cargo.toml", manifest, manifest.with_name("Cargo.lock"),
             ROOT / "crates/qualification-no-std/Cargo.toml"]
    for directory in [ROOT / "coaptic/src", manifest.parent / "src", ROOT / "crates/qualification-no-std/src"]:
        files.extend(sorted(directory.rglob("*.rs")))
    report = {"schema": "coaptic-esphome-archive/2", "target": TARGET,
              "features": features, **source,
              "compiler": subprocess.check_output(["rustc", "+" + args.toolchain, "-Vv"], text=True),
              "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
              "sources": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
    destination = ROOT / "tools/esphome/components/coaptic_network/lib"
    destination.mkdir(exist_ok=True)
    shutil.copyfile(archive, destination / archive.name)
    # Publish the provenance marker last. An interrupted copy fails checksum validation.
    (destination / "build.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ["source", "suite_source", "archive_sha256"]}))


if __name__ == "__main__":
    main()
