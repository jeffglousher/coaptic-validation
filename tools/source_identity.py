"""Record both repositories and the exact prepared lockfiles."""
import hashlib
from pathlib import Path
import subprocess

SUITE = Path(__file__).resolve().parents[1]
LIBRARY = SUITE / "coaptic"
LOCKS = ("Cargo.lock", "tools/benchmark/native/Cargo.lock", "tools/security-interop/Cargo.lock", "tools/security-profile/Cargo.lock",
         "tools/esphome/rust/Cargo.lock", "tools/qualification/esp32/Cargo.lock", "tools/durable-host/Cargo.lock")

def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()

def source_identity():
    return {
        "source": git(LIBRARY, "rev-parse", "HEAD"),
        "dirty": bool(git(LIBRARY, "status", "--porcelain")),
        "suite_source": git(SUITE, "rev-parse", "HEAD"),
        "suite_dirty": bool(git(SUITE, "status", "--porcelain")),
        "suite_locks": {name: hashlib.sha256((SUITE / name).read_bytes()).hexdigest() for name in LOCKS},
    }
