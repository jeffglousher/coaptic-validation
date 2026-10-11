"""Apply/verify only the reviewed patch to the exact independent peer source."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "oscore-qblock2-continuation.json"


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def verify(root, manifest):
    if git(root, "rev-parse", "HEAD").decode().strip() != manifest["upstream"]:
        raise ValueError("unexpected upstream source")
    changed = set(git(root, "diff", "--name-only", "HEAD").decode().splitlines())
    if changed != set(manifest["files"]):
        raise ValueError("missing patch or unrelated tracked source changes")
    if git(root, "ls-files", "--others", "--exclude-standard").strip():
        raise ValueError("untracked files in dependency source")
    for name, expected in manifest["files"].items():
        data = (root / name).read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"patched source mismatch: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    patch = HERE / manifest["patch"]
    if hashlib.sha256(patch.read_bytes()).hexdigest() != manifest["patch_sha256"]:
        raise ValueError("patch identity mismatch")
    if git(args.source, "rev-parse", "HEAD").decode().strip() != manifest["upstream"]:
        raise ValueError("unexpected upstream source")
    if args.apply and not git(args.source, "status", "--porcelain").strip():
        git(args.source, "apply", "--check", str(patch.resolve()))
        git(args.source, "apply", str(patch.resolve()))
    verify(args.source, manifest)
    print(manifest["patch_sha256"])


if __name__ == "__main__":
    main()
