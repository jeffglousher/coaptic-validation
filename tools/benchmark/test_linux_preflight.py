"""Linux regressions for bounded command output and read-only source checks."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import linux_cpu as cpu


class PreflightEvidenceTests(unittest.TestCase):
    def test_identity_failure_retains_request_and_failure_before_any_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / 'suite'
            lane = root / 'lane'
            suite.mkdir()
            lane.mkdir()
            output = root / 'evidence'
            args = argparse.Namespace(sizes='64', rates='1', seconds=2, repeats=2,
                                      server_kind='coaptic-reusable', perf=False, concurrency=1, message_type='con',
                                      baseline_sha='a' * 40, candidate_sha='b' * 40,
                                      build_lane=lane, output=output)
            with patch.object(cpu.sys, 'platform', 'linux'), patch.object(cpu, 'SUITE', suite), \
                    patch.object(cpu.os, 'sysconf', return_value=100, create=True), \
                    patch.object(cpu, 'identity', side_effect=RuntimeError('identity refused')), \
                    patch.object(cpu, 'build') as build:
                with self.assertRaisesRegex(RuntimeError, 'identity refused'):
                    cpu.run(args)
            build.assert_not_called()
            request = json.loads((output / 'request.json').read_bytes())
            failure = json.loads((output / 'failure.json').read_bytes())
            summary = json.loads((output / 'summary.json').read_bytes())
            self.assertEqual(request['baseline_sha'], args.baseline_sha)
            self.assertEqual(failure, dict(type='RuntimeError', reason='identity refused'))
            self.assertEqual(summary['windows_recorded'], 0)
            self.assertFalse(summary['campaign_complete'])
            self.assertEqual(summary['comparisons'], [])

    def test_wrong_release_or_missing_commit_retains_versions_and_stops_before_build(self):
        host = 'x86_64-unknown-linux-gnu'
        rustc = f'rustc 1.99.0\nhost: {host}\nrelease: 1.99.0\ncommit-hash: {"1" * 40}'
        cargo = f'cargo 1.99.0\nrelease: 1.99.0\ncommit-hash: {"2" * 40}'
        for tool in ('rustc', 'cargo'):
            for problem in ('release', 'commit'):
                with self.subTest(tool=tool, problem=problem), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    suite, lane, output = root / 'suite', root / 'lane', root / 'evidence'
                    suite.mkdir()
                    lane.mkdir()
                    args = argparse.Namespace(sizes='64', rates='1', seconds=2, repeats=2,
                                              server_kind='coaptic-reusable', perf=False, concurrency=1, message_type='con',
                                              baseline_sha='a' * 40, candidate_sha='b' * 40,
                                              build_lane=lane, output=output)
                    versions = dict(rustc=rustc, cargo=cargo)
                    if problem == 'release':
                        versions[tool] = versions[tool].replace('1.99.0', '1.99.1')
                    else:
                        versions[tool] = versions[tool].split('\ncommit-hash:')[0]
                    with patch.object(cpu.sys, 'platform', 'linux'), patch.object(cpu, 'SUITE', suite), \
                            patch.object(cpu.os, 'sysconf', return_value=100, create=True), \
                            patch.object(cpu, 'identity', return_value=dict(status='')), \
                            patch.object(cpu, 'hardware', return_value={}), \
                            patch.object(cpu, 'digest', return_value='hash'), \
                            patch.object(cpu.importlib.metadata, 'version', return_value='7.0.0'), \
                            patch.object(cpu, 'command', side_effect=[versions['rustc'], versions['cargo']]), \
                            patch.object(cpu, 'run_logged') as logged, patch.object(cpu, 'window') as window:
                        with self.assertRaisesRegex(ValueError, tool):
                            cpu.run(args)
                    logged.assert_not_called()  # No fetch, checkout or Cargo build for either revision.
                    window.assert_not_called()
                    request = json.loads((output / 'request.json').read_bytes())
                    actual = json.loads((output / 'build-baseline.json').read_bytes())
                    failure = json.loads((output / 'failure.json').read_bytes())
                    summary = json.loads((output / 'summary.json').read_bytes())
                    self.assertEqual(request['RUSTUP_TOOLCHAIN'], '1.99.0')
                    self.assertEqual(actual, dict(RUSTUP_TOOLCHAIN='1.99.0', **versions))
                    self.assertEqual(failure['type'], 'ValueError')
                    self.assertIn(tool, failure['reason'])
                    self.assertEqual(summary['windows_recorded'], 0)
                    self.assertFalse(summary['campaign_complete'])
                    self.assertEqual(summary['comparisons'], [])
                    self.assertFalse((output / 'binaries').exists())


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux process groups and file limits')
class CommandBoundsTests(unittest.TestCase):
    def test_small_output_does_not_limit_other_child_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'child-artifact'
            source = ('from pathlib import Path; import sys; '
                      'Path(sys.argv[1]).write_bytes(b"x" * 131072); print("complete")')
            with patch.object(cpu, 'SUMMARY_LIMIT', 1024):
                self.assertEqual(cpu.command([sys.executable, '-c', source, str(output)]), 'complete')
            self.assertEqual(output.stat().st_size, 131072)

    def test_excessive_output_is_still_refused(self):
        with patch.object(cpu, 'SUMMARY_LIMIT', 1024), self.assertRaises(ValueError):
            cpu.command([sys.executable, '-c', 'print("x" * 8192)'])

    def test_identity_does_not_refresh_a_large_git_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)

            def git(*args):
                subprocess.run(['git', *args], cwd=repo, check=True, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            git('init')
            for index in range(512):
                (repo / f'file-{index:04}-{"x" * 100}').write_bytes(b'x')
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture')
            index_path = repo / '.git/index'
            before = index_path.read_bytes()
            self.assertGreater(len(before), 65536)
            # Force a clean content recheck that ordinary status may write back.
            path = next(repo.glob('file-*'))
            stat = path.stat()
            os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 3_000_000_000))
            identity = cpu.identity(repo)
            self.assertEqual(identity['status'], '')
            self.assertEqual(index_path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
