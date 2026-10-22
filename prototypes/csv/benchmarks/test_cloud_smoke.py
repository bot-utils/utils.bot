import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import bundle
import cloud_smoke


class CloudSmokeTests(unittest.TestCase):
    def scratch(self):
        root = Path(tempfile.mkdtemp(prefix='utils-csv-smoke-test-'))
        root.chmod(0o700)
        self.addCleanup(lambda: subprocess.run(['trash', str(root)], check=True, capture_output=True))
        return root

    def test_real_supervisor_checks_all_operations_and_marks_provider_cleanup_pending(self):
        root = self.scratch()
        env = dict(os.environ, AWS_SECRET_ACCESS_KEY='synthetic_secret_must_not_appear')
        script = Path(cloud_smoke.__file__).resolve()
        p = subprocess.run([sys.executable, str(script), '--provider', 'local',
                            '--work-root', str(root)], env=env, capture_output=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(b'synthetic_secret_must_not_appear', p.stdout)
        self.assertNotIn(b'repeat,', p.stdout)
        self.assertTrue(p.stdout.startswith(cloud_smoke.MARKER.encode()))
        value = json.loads(p.stdout[len(cloud_smoke.MARKER):])
        self.assertTrue(value['provider_storage_cleanup_required'])
        self.assertTrue(value['provider_evidence_required'])
        self.assertEqual([r['operation'] for r in value['results']], ['dedupe', 'join', 'aggregate'])
        self.assertTrue(all(n <= 1 << 20 for n in value['input_bytes'].values()))
        self.assertTrue(all(r['encoded_bytes'] < r['logical_bytes'] for r in value['results']))
        private = next(root.iterdir())
        self.assertEqual(private.stat().st_mode & 0o777, 0o700)
        self.assertTrue((private / 'fixtures/left.csv').exists())
        self.assertLess(len(p.stdout), cloud_smoke.MAX_STDOUT)

    def test_watchdog_rejects_timeout_oversized_output_and_nonzero_exit(self):
        tests = [
            ('import time; time.sleep(10)', .05, 256, 'deadline_exceeded'),
            ('import sys; sys.stdout.write("x"*10000)', 5, 256, 'metrics_limit'),
            ('import sys; sys.exit(3)', 5, 256, 'worker_failed'),
        ]
        for code, timeout, limit, expected in tests:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(cloud_smoke.SmokeFailure, '^' + expected + '$'):
                    cloud_smoke.run_child([sys.executable, '-c', code], {}, timeout, limit)

    def test_unknown_or_bad_metrics_fail_without_echoing_child_content(self):
        for raw in (b'credential=do_not_print', b'{"status":"ok","secret":"do_not_print"}'):
            with self.assertRaises(cloud_smoke.SmokeFailure):
                cloud_smoke.validate_metrics(raw)
        output = io.StringIO()
        with patch.object(cloud_smoke, 'run_child', return_value=b'credential=do_not_print'), \
             contextlib.redirect_stdout(output):
            code = cloud_smoke.main(['--work-root', str(self.scratch()), '--provider', 'local'])
        self.assertEqual(code, 1)
        self.assertNotIn('do_not_print', output.getvalue())
        self.assertIn('invalid_metrics', output.getvalue())

    def test_bundle_is_reproducible_and_installed_runner_uses_same_sources(self):
        root = self.scratch()
        first = bundle.build(root / 'one')
        second = bundle.build(root / 'two')
        self.assertEqual(first, second)
        wheel = next((root / 'one').glob('*.whl'))
        with zipfile.ZipFile(wheel) as archive:
            self.assertEqual(archive.read('utils_bot_csv_trial/worker.py'),
                             Path(cloud_smoke.worker.__file__).read_bytes())
            self.assertNotIn(b'Requires-Dist:', archive.read(
                'utils_bot_csv_trial-0.1.0.dist-info/METADATA'))
        target = root / 'installed'
        p = subprocess.run([sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
                            '--no-index', '--no-deps', '--no-compile', '--no-cache-dir',
                            '--target', str(target), str(wheel)],
                           capture_output=True, timeout=20)
        self.assertEqual(p.returncode, 0, p.stderr)
        work = root / 'work'; work.mkdir()
        env = dict(os.environ, PYTHONPATH=str(target))
        p = subprocess.run([sys.executable, '-m', 'utils_bot_csv_trial.cloud_smoke',
                            '--provider', 'local', '--work-root', str(work)],
                           cwd=root, env=env, capture_output=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr)
        value = json.loads(p.stdout[len(cloud_smoke.MARKER):])
        self.assertEqual(value['worker_sha256'], cloud_smoke._digest(cloud_smoke.worker.__file__))
        self.assertEqual(value['fixtures_sha256'], cloud_smoke._digest(cloud_smoke.fixtures.__file__))

    def test_oracle_mismatch_and_nonprivate_scratch_fail(self):
        root = self.scratch()
        root.chmod(0o755)
        with self.assertRaisesRegex(cloud_smoke.SmokeFailure, 'invalid_scratch'):
            cloud_smoke.smoke(root)
        root.chmod(0o700)
        original = cloud_smoke.worker.execute
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            result['logical_sha256'] = '0' * 64
            return result
        with patch.object(cloud_smoke.worker, 'execute', side_effect=changed):
            with self.assertRaisesRegex(cloud_smoke.SmokeFailure, 'oracle_mismatch'):
                cloud_smoke.smoke(root)


if __name__ == '__main__':
    unittest.main()
