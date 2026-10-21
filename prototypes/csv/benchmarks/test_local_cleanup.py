import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import local_trial


class LocalCleanupTests(unittest.TestCase):
    def test_private_scratch_is_cleaned_on_create_json_and_assertion_failure(self):
        real_run = subprocess.run
        for failure in ('create', 'json', 'assertion'):
            with self.subTest(failure=failure):
                root = Path(tempfile.mkdtemp(prefix='utils-csv-cleanup-test-'))
                self.addCleanup(lambda p=root: real_run(['trash', str(p)], check=True, capture_output=True))
                fixture = root / 'fixture'; fixture.mkdir()
                files = {}
                for name in ('left.csv', 'right.csv'):
                    raw = b'key,group,amount,payload\n'
                    (fixture / name).write_bytes(raw)
                    files[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                manifest = dict(files=files, expected_dedupe_rows=0, expected_join_rows=0,
                                expected_aggregate_groups=0,
                                expected_logical_sha256={k: '' for k in ('dedupe', 'join', 'aggregate')})
                (fixture / 'manifest.json').write_text(json.dumps(manifest))
                output = root / 'output'
                observed = []
                def fake_docker(args, timeout=60):
                    if args[0] == 'image':
                        return SimpleNamespace(stdout='sha256:' + '1'*64)
                    if args[0] == 'create':
                        self.assertIn('--user=' + str(os.getuid()) + ':' + str(os.getgid()), args)
                        work = next(p for p in output.iterdir() if p.is_dir())
                        observed.append(work)
                        self.assertEqual(stat.S_IMODE(work.stat().st_mode), 0o700)
                        (work / 'partial-result').write_text('synthetic scratch')
                        if failure == 'create':
                            raise RuntimeError('simulated create failure')
                    if args[0] == 'start':
                        if failure == 'json':
                            return SimpleNamespace(stdout='not-json')
                        return SimpleNamespace(stdout=json.dumps(dict(output_rows=999, logical_sha256='wrong', status='ok')))
                    return SimpleNamespace(stdout='')
                def fake_run(args, **kwargs):
                    if args[0] == 'trash':
                        return real_run(args, **kwargs)
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                argv = ['local_trial.py', '--fixtures', str(fixture), '--output', str(output), '--repeats', '1']
                with patch.object(local_trial, 'local_endpoint', return_value='unix:///not-contacted.sock'), \
                     patch.object(local_trial, 'docker', side_effect=fake_docker), \
                     patch.object(local_trial.subprocess, 'run', side_effect=fake_run), \
                     patch.object(sys, 'argv', argv), patch.object(local_trial, '_endpoint', None):
                    with self.assertRaises((RuntimeError, ValueError, AssertionError)):
                        local_trial.main()
                self.assertTrue(observed)
                self.assertTrue(all(not p.exists() for p in observed))
                proof = json.loads((output / 'cleanup.json').read_text())
                self.assertEqual(proof['owned_containers_remaining'], 0)
                self.assertEqual(proof['scratch_paths_remaining'], 0)


if __name__ == '__main__':
    unittest.main()
