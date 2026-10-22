import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import cloud_control as control
import cloud_smoke
import runtime_plan


class FakeAWS:
    def __init__(self):
        self.etag = None
        self.calls = []
        self.saved = []

    def call(self, service, action, *args):
        self.calls.append((service, action, args))
        if (service, action) == ('s3api', 'get-object'):
            Path(args[-1]).write_text(json.dumps(self.saved[-1]))
            return {'ETag': self.etag}
        if (service, action) == ('s3api', 'put-object'):
            options = dict(zip(args[::2], args[1::2]))
            if '--if-none-match' in options:
                if self.etag is not None:
                    raise control.TrialFailure('already_claimed')
            elif options.get('--if-match') != self.etag:
                raise control.TrialFailure('lost_lease')
            self.saved.append(json.loads(Path(options['--body']).read_text()))
            self.etag = '"' + str(len(self.saved)) + '"'
            return {'ETag': self.etag}
        raise control.TrialFailure('uncertain_provider_response')


class SuccessController(control.Controller):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, admission=lambda: None, emit=lambda _: None, **kwargs)
        self.submitted = []
        self.stopped = False

    def submit(self, job, wanted):
        self.submitted.append(job['token'])
        self.assert_reserved_before_start = self.ledger.aws.saved[-1]['jobs'][-1]['state'] == 'submission_reserved'
        job.update(id='synthetic', state='submitted')
        self.ledger.save()

    def wait(self, job, wanted, timeout=1200):
        job['provider_terminal'] = 'STOPPED' if job['provider'] == 'fargate' else 'SUCCEEDED'

    def metrics(self, job, wanted):
        return {'synthetic_test_result': True}

    def workers_absent(self):
        return True

    def stop_owned(self):
        self.stopped = True


class ControlTests(unittest.TestCase):
    def root(self):
        root = Path(tempfile.mkdtemp(prefix='utils-csv-control-test-'))
        root.chmod(0o700)
        self.addCleanup(lambda: subprocess.run(['trash', str(root)], check=True, capture_output=True))
        return root

    def plan(self):
        return runtime_plan.build(control.ACCOUNT, 'subnet-'+'1'*17, 'sg-'+'2'*17,
                                  'sg-'+'3'*17, '4'*64, '5'*64, '6'*64)

    def test_serial_six_prewrite_reservations_and_replay_guard(self):
        aws = FakeAWS()
        ledger = control.Ledger(aws, self.root())
        runner = SuccessController(aws, ledger, self.plan(), {})
        runner.run()
        self.assertEqual(len(runner.submitted), 6)
        self.assertEqual(len(set(runner.submitted)), 6)
        self.assertTrue(runner.assert_reserved_before_start)
        self.assertEqual(ledger.state['phase'], 'workers_verified')
        self.assertFalse(ledger.state['cleanup_confirmed'])
        self.assertFalse(ledger.state['billing_confirmed'])
        with self.assertRaises(control.TrialFailure):
            control.Ledger(aws, self.root()).claim(self.plan())
        with self.assertRaises(control.TrialFailure):
            runner.reserve('seventh', 'glue')
        with self.assertRaises(control.TrialFailure):
            runner.run()
        self.assertEqual(len(runner.submitted), 6)

    def test_uncertain_start_is_never_repeated_and_reservation_is_retained(self):
        aws = FakeAWS()
        ledger = control.Ledger(aws, self.root())
        runner = SuccessController(aws, ledger, self.plan(), {})
        def uncertain(job, wanted):
            runner.submitted.append(job['token'])
            raise control.TrialFailure('uncertain_start')
        runner.submit = uncertain
        with self.assertRaises(control.TrialFailure):
            runner.run()
        self.assertEqual(len(runner.submitted), 1)
        self.assertEqual(ledger.state['phase'], 'failed_or_uncertain')
        self.assertEqual(ledger.state['jobs'][0]['state'], 'submission_reserved')
        self.assertEqual(ledger.state['reservation']['jobs'], 6)
        self.assertTrue(runner.stopped)

    def test_lost_ledger_lease_prevents_next_dispatch(self):
        aws = FakeAWS()
        ledger = control.Ledger(aws, self.root())
        ledger.claim(self.plan())
        aws.etag = '"another_owner"'
        runner = SuccessController(aws, ledger, self.plan(), {})
        with self.assertRaises(control.TrialFailure):
            runner.reserve('first', 'fargate')
        self.assertEqual(runner.submitted, [])

    def test_image_role_env_and_disk_drift_are_denied(self):
        wanted = self.plan()['task_definitions'][0]
        actual = copy.deepcopy(wanted)
        actual.pop('tags')
        actual.update(taskDefinitionArn='synthetic', status='ACTIVE')
        actual['containerDefinitions'][0]['linuxParameters']['capabilities']['add'] = []
        control.check_definition(wanted, actual)
        for mutate in (
                lambda d: d.update(taskRoleArn='credential-role'),
                lambda d: d['containerDefinitions'][0]['linuxParameters']['capabilities'].update(add=['SYS_PTRACE']),
                lambda d: d['volumes'][0].update(host={'sourcePath':'/host'}),
                lambda d: d.update(ephemeralStorage={'sizeInGiB': 200}),
                lambda d: d['containerDefinitions'][0].update(environment=[{'name':'AWS_SECRET_ACCESS_KEY','value':'secret'}]),
                lambda d: d['containerDefinitions'][0].update(entryPoint=['sh','-c']),
                lambda d: d['containerDefinitions'][0].update(image='other/image:latest')):
            value = copy.deepcopy(actual); mutate(value)
            with self.assertRaises(control.TrialFailure):
                control.check_definition(wanted, value)

    def test_real_metrics_check_oracle_compression_and_no_untrusted_echo(self):
        root = self.root()
        value = cloud_smoke.smoke(root)
        value.update(provider_label='local', supervisor_seconds=1,
                     provider_evidence_required=True, provider_storage_cleanup_required=True)
        line = cloud_smoke.MARKER + json.dumps(value)
        self.assertEqual(control.validated_message([line], 'local')['status'], 'ok')
        with self.assertRaises(control.TrialFailure):
            control.validated_message([line, line], 'local')
        value['results'][0]['logical_sha256'] = '1'*64
        with self.assertRaises(control.TrialFailure):
            control.validated_message([cloud_smoke.MARKER+json.dumps(value)], 'local')
        with self.assertRaises(control.TrialFailure) as caught:
            control.validated_message([cloud_smoke.MARKER+'secret=never_echo'], 'local')
        self.assertNotIn('never_echo', str(caught.exception))

    def test_glue_submit_is_one_call_and_uses_no_retry_token_claim(self):
        aws = FakeAWS()
        ledger = control.Ledger(aws, self.root()); ledger.claim(self.plan())
        runner = control.Controller(aws, ledger, self.plan(), {}, emit=lambda _: None)
        job = runner.reserve('glue', 'glue')
        with self.assertRaises(control.TrialFailure):
            runner.submit(job, self.plan()['glue_jobs'][0])
        starts = [call for call in aws.calls if call[:2] == ('glue','start-job-run')]
        self.assertEqual(len(starts), 1)
        self.assertNotIn('JobRunId', job)

    def test_unresolved_submission_never_claims_cleanup_from_empty_listings(self):
        aws = FakeAWS(); ledger = control.Ledger(aws, self.root()); ledger.claim(self.plan())
        original = aws.call
        def provider(service, action, *args):
            if service == 's3api': return original(service, action, *args)
            if action == 'list-tasks': return {'taskArns': []}
            if action == 'get-job-runs': return {'JobRuns': []}
            raise AssertionError('unexpected action')
        aws.call = provider
        clock = [0]
        runner = control.Controller(aws, ledger, self.plan(), {}, clock=lambda: clock[0],
                                    sleep=lambda _: clock.__setitem__(0, clock[0]+100), emit=lambda _: None)
        runner.reserve('uncertain', 'fargate')
        runner.workers_absent = lambda: True
        with self.assertRaisesRegex(control.TrialFailure, 'cleanup_unconfirmed'):
            runner.stop_owned()
        self.assertFalse(ledger.state['workers_termination_confirmed'])
        self.assertTrue(ledger.state['submission_reconciliation_required'])

    def test_unknown_response_is_reconciled_by_exact_token_before_stop(self):
        aws = FakeAWS(); ledger = control.Ledger(aws, self.root()); ledger.claim(self.plan())
        runner = control.Controller(aws, ledger, self.plan(), {}, emit=lambda _: None)
        job = runner.reserve('uncertain', 'fargate')
        original = aws.call; stopped = []
        task = control.TASK_PREFIX + '1'*32
        def provider(service, action, *args):
            if service == 's3api': return original(service, action, *args)
            if action == 'list-tasks': return {'taskArns': [] if '--desired-status' in args else [task]}
            if action == 'describe-tasks': return {'tasks':[{'taskArn':task,'tags':[{'key':'TrialJobToken','value':job['token']}]}]}
            if action == 'stop-task': stopped.append(task); return {}
            if action == 'get-job-runs': return {'JobRuns': []}
            raise AssertionError('unexpected action')
        aws.call = provider; runner.workers_absent = lambda: True
        runner.stop_owned()
        self.assertEqual(job['id'], task)
        self.assertEqual(stopped, [task])
        self.assertTrue(ledger.state['workers_termination_confirmed'])

    def dns_failed_ledger(self):
        aws = FakeAWS(); ledger = control.Ledger(aws, self.root()); plan = self.plan()
        ledger.claim(plan)
        task = control.TASK_PREFIX + '1'*32
        ledger.state.update(phase='failed_or_uncertain', workers_termination_confirmed=True)
        ledger.state['jobs'] = [{'label':control.NAME+'-arm-small','provider':'fargate',
                                 'token':'old-token','id':task,'state':'submitted'}]
        ledger.save()
        proof = {'taskArn':task,'lastStatus':'STOPPED','stopCode':'TaskFailedToStart',
                 'stoppedReason':'lookup prod-us-east-2-starport-layer-bucket.s3.us-east-2.amazonaws.com: no such host'}
        return aws, plan, proof

    def test_reviewed_dns_recovery_runs_only_five_unattempted_tiers(self):
        aws, plan, proof = self.dns_failed_ledger()
        lease = aws.saved[-1]['trial_id']
        ledger = control.Ledger(aws, self.root())
        original = copy.deepcopy(plan)
        for task in plan['task_definitions']:
            task['containerDefinitions'][0]['image'] = '818416606421.dkr.ecr.us-east-2.amazonaws.com/utils-bot-csv-trial@sha256:'+'a'*64
        ledger.review_stopped_dns_failure(plan, proof, 'a'*40, previous_plan=original)
        self.assertTrue(ledger.state['recovery_review']['immutable_images_repinned'])
        runner = SuccessController(aws, ledger, plan, {})
        runner.run()
        self.assertEqual(len(runner.submitted), 5)
        self.assertEqual(len(ledger.state['jobs']), 6)
        self.assertEqual(ledger.state['trial_id'], lease)
        self.assertEqual(ledger.state['jobs'][0]['state'], 'failed_terminal_reviewed')
        self.assertEqual(ledger.state['phase'], 'attempts_complete')
        self.assertEqual(ledger.state['reservation']['jobs'], 6)
        with self.assertRaises(control.TrialFailure):
            control.Ledger(aws, self.root()).claim(plan)

    def test_recovery_rejects_unknown_changed_or_nonterminal_failure(self):
        for changed in ('unknown', 'different_task', 'running', 'different_failure', 'different_plan'):
            with self.subTest(changed=changed):
                aws, plan, proof = self.dns_failed_ledger()
                if changed == 'unknown':
                    aws.saved[-1]['jobs'][0].pop('id')
                elif changed == 'different_task': proof['taskArn'] += '2'
                elif changed == 'running': proof['lastStatus'] = 'RUNNING'
                elif changed == 'different_failure': proof['stoppedReason'] = 'other failure'
                else: plan['scope'] = 'changed scope'
                ledger = control.Ledger(aws, self.root())
                with self.assertRaises(control.TrialFailure):
                    ledger.review_stopped_dns_failure(plan, proof, 'a'*40)

    def test_code_readback_rejects_changed_bytes_before_dispatch(self):
        aws = FakeAWS(); ledger = control.Ledger(aws, self.root())
        artifacts = {name: {'bytes': 1, 'sha256': '1'*64} for name in
                     ('glue_smoke.py', 'utils_bot_csv_trial-0.1.0-py3-none-any.whl')}
        def changed(service, action, *args):
            self.assertEqual((service, action), ('s3api', 'get-object'))
            Path(args[-1]).write_bytes(b'changed')
            return {}
        aws.call = changed
        runner = control.Controller(aws, ledger, self.plan(), {}, artifacts=artifacts)
        with self.assertRaisesRegex(control.TrialFailure, 'code_content_drift'):
            runner.verify_code()
        self.assertFalse(any(ledger.directory.glob('code-readback-*')))

    def test_cli_disables_sdk_retries_and_rejects_nonprivate_evidence(self):
        aws = control.AWS({'AWS_PROFILE':'synthetic'})
        self.assertEqual(aws.env['AWS_MAX_ATTEMPTS'], '1')
        root = self.root(); root.chmod(0o755)
        with self.assertRaises(control.TrialFailure):
            control.Ledger(FakeAWS(), root)


if __name__ == '__main__':
    unittest.main()
