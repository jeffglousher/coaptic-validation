"""Reproduce the private Lakers production subset from its pinned Git objects."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


PIN = "462b30f5b3e9cfab96c05fe65f36d19eaa7002ad"
BASE = "32d09af75d44c771582c21a82831ee3a5dc8aecc"
FILES = {
    "core.rs": "lib/src/lib.rs",
    "edhoc.rs": "lib/src/edhoc.rs",
    "shared/mod.rs": "shared/src/lib.rs",
    "shared/cred.rs": "shared/src/cred.rs",
    "shared/buffer.rs": "shared/src/buffer.rs",
    "shared/crypto.rs": "shared/src/crypto.rs",
}
FACADE = '''//! Private production subset of [Lakers v0.8.0](https://github.com/lake-rs/lakers).
//!
//! Source is pinned to [462b30f](https://github.com/jeffglousher/lakers/commit/462b30f5b3e9cfab96c05fe65f36d19eaa7002ad).
//! The BSD-3-Clause notice is retained in `LICENSE-BSD`; source transformations,
//! including local connection-ID bounds hardening, and hashes are recorded in
//! `provenance.json`.
#![allow(dead_code, deprecated, unexpected_cfgs, unused_imports, missing_docs)]
#![allow(clippy::all, clippy::pedantic)]

mod core;
mod edhoc;
mod shared;

pub use self::core::*;
'''


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(repository, relative):
    return subprocess.run(
        ["git", "-C", str(repository), "show", f"{PIN}:{relative}"],
        check=True,
        capture_output=True,
    ).stdout


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Expected one namespace/attribute match: {old!r}")
    return text.replace(old, new, 1)


def production_prefix(text, relative):
    marker = "\nmod test {" if relative == "shared/src/buffer.rs" else "\n#[cfg(test)]\nmod "
    if relative == "shared/src/crypto.rs":
        return text
    index = text.find(marker)
    if index < 0:
        raise ValueError(f"Missing trailing upstream test module in {relative}")
    return text[:index] + "\n"


def text_examples(text):
    lines = text.splitlines(keepends=True)
    inside_fence = False
    for index, line in enumerate(lines):
        match = re.match(r"(\s*///\s+)```([^\r\n]*)", line)
        if match:
            if not inside_fence:
                lines[index] = match.group(1) + "```text\n"
            inside_fence = not inside_fence
    if inside_fence:
        raise ValueError("Unclosed upstream documentation fence")
    return "".join(lines)


def transform(blob, relative):
    original = blob.decode("utf-8").replace("\r\n", "\n")
    prefix = production_prefix(original, relative)
    text = prefix
    if relative == "lib/src/lib.rs":
        text = replace_once(text, '#![cfg_attr(not(test), no_std)]\n', "")
        text = replace_once(
            text,
            "pub use {lakers_shared::Crypto as CryptoTrait, lakers_shared::*};",
            "pub use super::shared::{Crypto as CryptoTrait, *};",
        )
        text = replace_once(
            text,
            '#[cfg(all(feature = "ead-authz", test))]\npub use lakers_ead_authz::*;\n',
            "",
        )
        text = replace_once(text, "mod edhoc;\npub use edhoc::*;", "pub use super::edhoc::*;")
    elif relative == "lib/src/edhoc.rs":
        text = replace_once(
            text,
            "use lakers_shared::{Crypto as CryptoTrait, *};",
            "use super::shared::{Crypto as CryptoTrait, *};",
        )
    elif relative == "shared/src/lib.rs":
        text = replace_once(
            text,
            "        s[..len].copy_from_slice(decoder.read_slice(len)?);",
            "        if len > s.len() {\n"
            "            return Err(CBORError::DecodingError);\n"
            "        }\n"
            "        s[..len].copy_from_slice(decoder.read_slice(len)?);",
        )
        text = replace_once(text, '#![cfg_attr(not(feature = "python-bindings"), no_std)]\n', "")
        text = replace_once(
            text,
            '#[cfg(feature = "python-bindings")]\nuse pyo3::prelude::*;\n#[cfg(feature = "python-bindings")]\nmod python_bindings;\n',
            "",
        )
        for visibility, name, value in [
            ("pub ", "MAX_MESSAGE_SIZE_LEN", 192),
            ("pub ", "MAX_KDF_CONTEXT_LEN", 256),
            ("pub ", "MAX_BUFFER_LEN", 320),
            ("", "MAX_CONNID_ENCODED_LEN", 8),
        ]:
            pattern = rf"{visibility}const {name}: usize = if cfg!\(.*?\n\}};"
            text, count = re.subn(pattern, f"{visibility}const {name}: usize = {value};", text, count=1, flags=re.DOTALL)
            if count != 1:
                raise ValueError(f"Missing configurable upstream buffer {name}")
    text = re.sub(r'^#\[cfg_attr\(feature = "python-bindings", [^\n]+\)\]\n', "", text, flags=re.MULTILINE)
    text = text_examples(text)
    if "cfg!(feature" in text or "#[cfg" in text:
        raise ValueError(f"Unexpected upstream conditional feature remains in {relative}")
    return text.encode("utf-8"), sha256(prefix.encode("utf-8"))


def build(repository, destination):
    actual_pin = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", f"{PIN}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual_pin != PIN:
        raise ValueError("Upstream commit pin mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    source_entries = []
    output_paths = []
    for output, relative in FILES.items():
        blob = git_blob(repository, relative)
        transformed, prefix_hash = transform(blob, relative)
        path = destination / output
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(transformed)
        output_paths.append(path)
        source_entries.append({
            "source": relative,
            "source_sha256": sha256(blob),
            "source_git_blob": hashlib.sha1(b"blob " + str(len(blob)).encode() + b"\0" + blob).hexdigest(),
            "production_prefix_sha256": prefix_hash,
            "output": output,
            "pre_format_output_sha256": sha256(transformed),
        })
    facade = destination / "mod.rs"
    facade.write_text(FACADE, encoding="utf-8", newline="\n")
    output_paths.append(facade)
    formatter = ["rustup", "run", "1.99.0", "rustfmt", "--edition", "2024", "--config", "skip_children=true"]
    subprocess.run(formatter + [str(path) for path in output_paths], check=True)
    for entry in source_entries:
        entry["output_sha256"] = sha256((destination / entry["output"]).read_bytes())
    license_blob = git_blob(repository, "LICENSE.md")
    (destination / "LICENSE-BSD").write_bytes(license_blob)
    provenance = {
        "upstream_repository": "https://github.com/lake-rs/lakers",
        "hardened_repository": "https://github.com/jeffglousher/lakers",
        "upstream_release": "v0.8.0",
        "upstream_release_commit": BASE,
        "hardened_commit": PIN,
        "license": "BSD-3-Clause",
        "license_source": "LICENSE.md",
        "license_sha256": sha256(license_blob),
        "formatter": "rustup run 1.99.0 rustfmt --edition 2024 --config skip_children=true",
        "transformations": [
            "Remove trailing upstream test modules; original tests are validated separately against exact source",
            "Adapt lakers_shared and edhoc imports to private sibling modules",
            "Remove crate-only no_std attributes; the enclosing Coaptic crate supplies no_std",
            "Remove Python binding attributes/imports and test-only EAD re-export",
            "Freeze four upstream buffer constants to default values: 192, 256, 320, 8",
            "Render upstream external-crate documentation examples as text for private vendoring",
            "Reject connection identifiers exceeding fixed storage before slicing or consuming input in ConnId::from_decoder",
            "Format source with the specified rustfmt; preserve original comments",
            "Add private facade with scope-limited unused/deprecated/cfg/documentation/Clippy lint caps",
        ],
        "source_files": source_entries,
        "facade_sha256": sha256(facade.read_bytes()),
    }
    (destination / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8", newline="\n")
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--check-work-root", type=Path)
    args = parser.parse_args()
    if args.check:
        if args.check_work_root is None:
            parser.error("--check requires --check-work-root for preserved reproduction evidence")
        generated = args.check_work_root.resolve()
        actual = args.output.resolve()
        if generated == actual or generated in actual.parents or actual in generated.parents:
            raise ValueError("Check evidence and checked output must be disjoint")
        build(args.source_repo.resolve(), generated)
        mismatches = [relative for relative in [*FILES, "mod.rs", "LICENSE-BSD", "provenance.json"] if not (actual / relative).is_file() or (actual / relative).read_bytes() != (generated / relative).read_bytes()]
        if mismatches:
            raise ValueError(f"Vendored reproduction mismatch: {mismatches}")
        print(json.dumps({"commit": PIN, "verified_files": len(FILES) + 3, "result": "byte-identical"}))
    else:
        build(args.source_repo.resolve(), args.output.resolve())
        print(json.dumps({"commit": PIN, "generated_files": len(FILES) + 3, "output": str(args.output.resolve())}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
