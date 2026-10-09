import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_identity import source_identity

"""Reproduce finite seeded campaigns; retain source, commands and explicit test results."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2] / "coaptic"
TOOLCHAIN = "1.97.1"
CAMPAIGNS = (
    (["--lib", "storage::tests::seeded_body_backends_match_results_state_and_reclamation"], ["storage::tests::seeded_body_backends_match_results_state_and_reclamation"]),
    (["--test", "seeded_qualification"], ["seeded_datagram_mutations_preserve_views_and_reject_invalid_headers", "seeded_cbor_mutations_keep_bounds_and_known_values"]),
    (["--lib", "oscore::tests::seeded_replay_window_matches_set_model"], ["oscore::tests::seeded_replay_window_matches_set_model"]),
    (["--lib", "oscore::tests::corrupted_requests_do_not_poison_replay_acceptance_campaign"], ["oscore::tests::corrupted_requests_do_not_poison_replay_acceptance_campaign"]),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.chdir(ROOT)
    report = {"schema": "coaptic-seeded-qualification/1",
              **source_identity(),
              "compiler": subprocess.check_output(["rustc", "+" + TOOLCHAIN, "--version", "--verbose"], text=True),
              "scope": "Finite seeded fixed/allocated body parity, parser mutations, set-model replay states and authenticated corruption/replay checks",
              "unqualified": ["coverage-guided fuzzing", "line/branch coverage", "exhaustive input space", "network fault/lifecycle soak", "device execution"],
              "campaigns": []}
    for flags, names in CAMPAIGNS:
        command = ["cargo", "+" + TOOLCHAIN, "test", "--locked", "-p", "coaptic", "--all-features", *flags, "--", "--nocapture", "--test-threads=1"]
        result = subprocess.run(command, capture_output=True, text=True)
        # A renamed/deleted test must not turn a zero-test invocation into a pass.
        passed = result.returncode == 0 and all("test " + name + " ..." in result.stdout for name in names) and (str(len(names)) + " passed; 0 failed;") in result.stdout
        report["campaigns"].append({"tests": names, "command": command, "passed": passed,
                                    "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        print(("PASS" if passed else "FAIL") + " " + ", ".join(names), flush=True)
    report["passed"] = len(report["campaigns"]) == len(CAMPAIGNS) and all(campaign["passed"] for campaign in report["campaigns"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
