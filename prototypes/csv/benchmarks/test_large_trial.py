import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cloud_smoke
import large_plan
import large_trial
import large_local


class LargeTrialTests(unittest.TestCase):
    def scratch(self):
        root = Path(tempfile.mkdtemp(prefix='utils-csv-large-test-'))
        root.chmod(0o700)
        self.addCleanup(lambda: subprocess.run(['trash', str(root)], check=True, capture_output=True))
        return root

    def test_real_artifacts_match_independent_oracle_all_operations(self):
        for operation in large_trial.OPERATIONS:
            with self.subTest(operation=operation):
                root = self.scratch()
                value = large_trial.evaluate(root, 1, operation)
                self.assertEqual(large_trial.validate(json.dumps(value), 1, operation), value)
                self.assertTrue(value['synthetic'])
                self.assertLess(value['result']['encoded_bytes'], value['result']['logical_bytes'])
                self.assertNotIn('repeat,', json.dumps(value))
                self.assertTrue((root / 'result/result.csv.gz').exists())

    def test_oracle_tampering_rejected(self):
        original = large_trial.fixtures.generate
        def changed(*args, **kwargs):
            value = original(*args, **kwargs)
            value['expected_logical_sha256']['dedupe'] = '0' * 64
            return value
        with patch.object(large_trial.fixtures, 'generate', side_effect=changed):
            with self.assertRaisesRegex(cloud_smoke.SmokeFailure, '^oracle_mismatch$'):
                large_trial.evaluate(self.scratch(), 1, 'dedupe')

    def test_invalid_metrics_never_echo_content(self):
        good = large_trial.evaluate(self.scratch(), 1, 'dedupe')
        bad_values = [None, [], {'secret': 'synthetic_private_marker'}]
        for key, value in [('operation', 'join'), ('scope', 'synthetic_private_marker'),
                           ('fixture_seconds', float('nan')), ('mib_per_input', 1024),
                           ('fixture_bytes', {'left.csv': 1 << 21, 'right.csv': 5}),
                           ('source_sha256', {})]:
            changed = dict(good); changed[key] = value; bad_values.append(changed)
        for value in bad_values:
            with self.assertRaisesRegex(cloud_smoke.SmokeFailure, '^invalid_metrics$'):
                large_trial.validate(json.dumps(value), 1, 'dedupe')

    def test_private_empty_scratch_required(self):
        root = self.scratch()
        root.chmod(0o755)
        with self.assertRaises(cloud_smoke.SmokeFailure):
            large_trial.evaluate(root, 1, 'dedupe')
        root.chmod(0o700)
        (root / 'unexpected').write_text('synthetic')
        with self.assertRaises(cloud_smoke.SmokeFailure):
            large_trial.evaluate(root, 1, 'dedupe')
        root = self.scratch()
        for mib, op in [(2, 'dedupe'), (1, 'transform')]:
            with self.assertRaises(cloud_smoke.SmokeFailure):
                large_trial.evaluate(root, mib, op)

    def test_supervisor_sanitizes_failure_and_drops_inherited_credentials(self):
        observed = []
        def fail(command, env):
            observed.append(env)
            raise cloud_smoke.SmokeFailure('deadline_exceeded')
        output = io.StringIO()
        with patch.dict(os.environ, AWS_SECRET_ACCESS_KEY='synthetic_secret_marker'), \
             patch.object(large_trial.cloud_smoke, 'run_child', side_effect=fail), \
             contextlib.redirect_stdout(output):
            result = large_trial.main(['--mib', '16', '--operation', 'join', '--work-root', str(self.scratch())])
        self.assertEqual(result, 1)
        self.assertNotIn('synthetic_secret_marker', output.getvalue())
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', observed[0])
        self.assertIn('deadline_exceeded', output.getvalue())

    def test_local_plan_rejects_unknown_or_duplicate_cases_before_docker(self):
        with patch.object(large_local.local_trial, 'local_endpoint') as endpoint:
            for sizes, ops in [([], ['join']), ([1], ['join']), ([16,16], ['join']),
                               ([16], ['join','join']), ([16], ['transform'])]:
                with self.assertRaises(ValueError):
                    large_local.run_cases(sizes, ops)
            endpoint.assert_not_called()

    def test_local_create_and_decode_failures_cleanup_only_owned_resources(self):
        from types import SimpleNamespace
        for failure in ('create', 'decode'):
            commands = []
            def docker(args, timeout=60):
                commands.append(args)
                if args[:2] == ['image', 'inspect']:
                    return SimpleNamespace(stdout='sha256:' + 'a'*64)
                if args[0] == 'create' and failure == 'create':
                    raise RuntimeError('simulated create failure')
                if args[0] == 'start':
                    return SimpleNamespace(stdout='invalid_synthetic_metrics')
                return SimpleNamespace(stdout='')
            with patch.object(large_local.local_trial, 'local_endpoint', return_value='unix:///not-contacted.sock'), \
                 patch.object(large_local.local_trial, 'docker', side_effect=docker), \
                 patch.object(large_local.subprocess, 'run') as kill, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, 'failure|metrics'):
                    large_local.run_cases([16], ['join'])
            self.assertEqual(kill.call_count, 1)
            for resource in ('container', 'volume'):
                prune = next(c for c in commands if c[:2] == [resource, 'prune'])
                self.assertTrue(any(c.startswith('label=' + large_local.LABEL + '=') for c in prune))
            self.assertTrue(any(c[:2] == ['ps', '--all'] for c in commands))
            self.assertTrue(any(c[:2] == ['volume', 'ls'] for c in commands))
            self.assertEqual(sum(c[0] == 'create' for c in commands), 1)


class LargePlanTests(unittest.TestCase):
    def plan(self):
        return large_plan.build('123456789012', 'subnet-' + '1'*17, 'sg-' + '2'*17, 'a'*64)

    def test_pure_plan_is_three_serial_arm_tasks_without_application_role(self):
        plan = self.plan()
        self.assertEqual(plan['max_jobs'], 3)
        self.assertEqual(plan['max_concurrency'], 1)
        task = plan['task_definition']
        self.assertEqual(task['runtimePlatform']['cpuArchitecture'], 'ARM64')
        self.assertNotIn('taskRoleArn', task)
        self.assertEqual((task['cpu'], task['memory']), ('1024', '2048'))
        worker = task['containerDefinitions'][0]
        self.assertTrue(worker['readonlyRootFilesystem'])
        self.assertEqual(worker['user'], '10001:10001')
        self.assertEqual(worker['linuxParameters']['capabilities']['drop'], ['ALL'])
        self.assertNotIn('environment', worker)
        self.assertEqual(plan['run_network']['awsvpcConfiguration']['assignPublicIp'], 'DISABLED')
        self.assertEqual([x['containerOverrides'][0]['command'] for x in plan['overrides']],
                         [['--mib','1024','--operation',op] for op in large_trial.OPERATIONS])
        self.assertIn('never reset', plan['requires'][0])

    def test_unpinned_images_and_invalid_networks_rejected(self):
        for args in [('000000000000','subnet-'+'1'*17,'sg-'+'2'*17,'a'*64),
                     ('123456789012','subnet-public','sg-'+'2'*17,'a'*64),
                     ('123456789012','subnet-'+'1'*17,'sg-'+'2'*17,'latest')]:
            with self.assertRaises(ValueError):
                large_plan.build(*args)



if __name__ == '__main__':
    unittest.main()
