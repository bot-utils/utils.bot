"""Serial, one-shot synthetic trial controller. Never provisions infrastructure.

The S3 ledger is a replay guard, not an AWS spending cap. Unknown submissions
consume their reservation and stop dispatch; there is no automatic takeover.
"""
import hashlib
import json
import os
import subprocess
import signal
import tempfile
import re
import time
import uuid
from pathlib import Path

import cloud_network
import cloud_smoke
import network_costs
import runtime_plan

NAME = runtime_plan.NAME
ACCOUNT = '818416606421'
BUCKET = NAME + '-' + ACCOUNT + '-us-east-2'
KEY = 'trial/control/first-six-v1.json'
BOUNDARY = 'arn:aws:iam::' + ACCOUNT + ':policy/' + NAME + '-runtime-boundary'
BOUNDARY_HASH = '9c067c110a812a7ed833327b52942cd46097a29c95592c8054b940a3facf5d0e'
GLUE_POLICY_HASH = '9bd02fa650c5a05480e49cfcf8267eb4d72de5ddf183c31bbf515763a5deafde'
TASK_PREFIX = 'arn:aws:ecs:us-east-2:' + ACCOUNT + ':task/' + NAME + '/'

def document_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
TERMINAL = {'SUCCEEDED', 'FAILED', 'STOPPED', 'TIMEOUT', 'ERROR', 'EXPIRED'}


class TrialFailure(Exception):
    pass


class AWS:
    def __init__(self, env):
        self.env = dict(env, AWS_REGION='us-east-2', AWS_DEFAULT_REGION='us-east-2',
                        AWS_PAGER='', AWS_MAX_ATTEMPTS='1', AWS_RETRY_MODE='standard')

    def call(self, service, action, *args):
        try:
            p = subprocess.run(['aws', service, action, *args, '--region', 'us-east-2',
                                '--output', 'json'], env=self.env, capture_output=True,
                               text=True, timeout=45)
        except subprocess.TimeoutExpired:
            raise TrialFailure('aws_request_uncertain') from None
        if p.returncode:
            # Do not echo provider diagnostics or arbitrary log content.
            raise TrialFailure(service + '_' + action + '_failed')
        try:
            return json.loads(p.stdout) if p.stdout.strip() else {}
        except ValueError:
            raise TrialFailure('invalid_provider_response') from None


class Ledger:
    def __init__(self, aws, directory):
        self.aws = aws
        self.directory = Path(directory)
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise TrialFailure('invalid_evidence_directory')
        if self.directory.stat().st_uid != os.getuid() or self.directory.stat().st_mode & 0o077:
            raise TrialFailure('invalid_evidence_directory')
        self.path = self.directory / 'ledger.json'
        self.etag = None
        self.state = None

    def claim(self, plan):
        if self.state is not None or self.path.exists():
            raise TrialFailure('ledger_reuse')
        reservation = network_costs.estimate()
        if not network_costs.reservation_fits_reviewed_scope(
                reservation, 0, 0, 5, True, True, True, 6):
            raise TrialFailure('cost_reservation')
        self.state = {'schema_version': 1, 'trial_id': uuid.uuid4().hex,
                      'plan_sha256': hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest(),
                      'reservation': reservation, 'phase': 'claimed', 'jobs': [],
                      'billing_confirmed': False, 'cleanup_confirmed': False,
                      'controller_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      'network_collector_sha256': hashlib.sha256(Path(cloud_network.__file__).read_bytes()).hexdigest()}
        self.save(first=True)

    def save(self, first=False):
        self.path.write_text(json.dumps(self.state, sort_keys=True))
        self.path.chmod(0o600)
        conditional = ['--if-none-match', '*'] if first else ['--if-match', self.etag]
        result = self.aws.call('s3api', 'put-object', '--bucket', BUCKET, '--key', KEY,
                               '--body', str(self.path), '--server-side-encryption', 'AES256',
                               *conditional)
        self.etag = result['ETag']


def subset(expected, actual):
    """Compare planned fields and leave provider metadata to separate checks."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and subset(value, actual[key]) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(expected) == len(actual) and all(
            subset(left, right) for left, right in zip(expected, actual))
    return expected == actual


def check_definition(wanted, actual):
    planned = {key: value for key, value in wanted.items() if key != 'tags'}
    if not subset(planned, actual) or actual.get('taskRoleArn'):
        raise TrialFailure('task_definition_drift')
    if actual.get('pidMode') or actual.get('ipcMode') or actual.get('proxyConfiguration'):
        raise TrialFailure('task_definition_drift')
    if actual.get('ephemeralStorage', {'sizeInGiB': 20}) != {'sizeInGiB': 20}:
        raise TrialFailure('task_definition_drift')
    if any(v.get('host', {}) != {} or v.get('dockerVolumeConfiguration') or
           v.get('efsVolumeConfiguration') for v in actual['volumes']):
        raise TrialFailure('task_volume_drift')
    container = actual['containerDefinitions'][0]
    linux = dict(container.get('linuxParameters', {}))
    capabilities = dict(linux.get('capabilities', {}))
    if capabilities.get('add') == []:
        capabilities.pop('add')
    linux['capabilities'] = capabilities
    if linux != wanted['containerDefinitions'][0]['linuxParameters']:
        raise TrialFailure('container_configuration_drift')
    defaults = {'cpu': 0, 'portMappings': [], 'environment': [], 'environmentFiles': [],
                'secrets': [], 'volumesFrom': [], 'systemControls': [],
                'resourceRequirements': [], 'dependsOn': [], 'disableNetworking': False}
    for key in set(container) - set(wanted['containerDefinitions'][0]):
        if key not in defaults or container[key] != defaults[key]:
            raise TrialFailure('container_configuration_drift')


def validated_message(messages, provider, architecture=None):
    candidates = [line[len(cloud_smoke.MARKER):] for message in messages
                  for line in message.splitlines() if line.startswith(cloud_smoke.MARKER)]
    if len(candidates) != 1 or len(candidates[0]) > cloud_smoke.MAX_STDOUT:
        raise TrialFailure('missing_or_duplicate_metrics')
    try:
        value = json.loads(candidates[0])
        if value.get('status') != 'ok':
            raise TrialFailure('worker_failed')
        extras = {'provider_label', 'supervisor_seconds', 'provider_evidence_required',
                  'provider_storage_cleanup_required'}
        if value.get('provider_label') != provider or any(
                value.get(key) is not True for key in extras if key.endswith('_required')):
            raise TrialFailure('invalid_supervisor_metrics')
        seconds = value['supervisor_seconds']
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 <= seconds <= 910:
            raise TrialFailure('invalid_supervisor_metrics')
        checked = cloud_smoke.validate_metrics(json.dumps(
            {key: item for key, item in value.items() if key not in extras}))
        expected_hashes = (
            'd4968c90466534c6d969f3a8b78f747ed1e7e0e3a29444bfd4a95ecf1ad361b2',
            'a2c4e2354ec44b36efbbd4c13049676776c48b97c10bf3ff7af12fe66457e343',
            '7fafab77ab8a8f0c3950bebf3b5c2d2566a7a0e8cc01ce81022b623bfdc9c5fc')
        for row, digest, count in zip(checked['results'], expected_hashes, (528, 528, 97)):
            if (row['logical_sha256'] != digest or row['output_rows'] != count or
                    not 0 < row['encoded_bytes'] < row['logical_bytes']):
                raise TrialFailure('oracle_or_compression_mismatch')
        if architecture and checked['architecture'] != architecture:
            raise TrialFailure('architecture_mismatch')
        return value
    except (ValueError, TypeError, KeyError, AttributeError, cloud_smoke.SmokeFailure):
        raise TrialFailure('invalid_metrics') from None


class Controller:
    def __init__(self, aws, ledger, plan, definitions, admission=None, clock=time.monotonic,
                 sleep=time.sleep, emit=None, artifacts=None):
        self.aws, self.ledger, self.plan = aws, ledger, plan
        self.definitions = definitions
        self.artifacts = artifacts
        self.clock, self.sleep = clock, sleep
        self.admission = admission or self.live_admission
        self.emit = emit or (lambda event: print(json.dumps(event, sort_keys=True), flush=True))

    def verify_code(self):
        names = {'glue_smoke.py', 'utils_bot_csv_trial-0.1.0-py3-none-any.whl'}
        if not isinstance(self.artifacts, dict) or set(self.artifacts) != names:
            raise TrialFailure('code_manifest_missing')
        script = self.plan['glue_jobs'][0]['Command']['ScriptLocation']
        pattern = 's3://' + BUCKET + r'/trial/code/[a-f0-9]{64}/glue_smoke[.]py'
        if not re.fullmatch(pattern, script):
            raise TrialFailure('code_namespace_drift')
        prefix = script.removeprefix('s3://' + BUCKET + '/').removesuffix('glue_smoke.py')
        root = Path(tempfile.mkdtemp(prefix='code-readback-', dir=self.ledger.directory))
        root.chmod(0o700)
        try:
            for name in sorted(names):
                path = root / name
                self.aws.call('s3api', 'get-object', '--bucket', BUCKET,
                              '--key', prefix + name, str(path))
                if (path.stat().st_size != self.artifacts[name]['bytes'] or
                        hashlib.sha256(path.read_bytes()).hexdigest() != self.artifacts[name]['sha256']):
                    raise TrialFailure('code_content_drift')
        finally:
            subprocess.run(['trash', str(root)], check=True, capture_output=True)

    def live_admission(self):
        self.verify_code()
        for suffix in ('glue', 'ecs-execution'):
            role = self.aws.call('iam', 'get-role', '--role-name', NAME + '-' + suffix)['Role']
            if role.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn') != BOUNDARY:
                raise TrialFailure('runtime_boundary_drift')
        version = self.aws.call('iam', 'get-policy', '--policy-arn', BOUNDARY)['Policy']['DefaultVersionId']
        document = self.aws.call('iam', 'get-policy-version', '--policy-arn', BOUNDARY,
                                 '--version-id', version)['PolicyVersion']['Document']
        if document_hash(document) != BOUNDARY_HASH:
            raise TrialFailure('runtime_boundary_drift')
        inline = self.aws.call('iam', 'get-role-policy', '--role-name', NAME + '-glue',
                               '--policy-name', 'CsvTrialOnly')['PolicyDocument']
        if document_hash(inline) != GLUE_POLICY_HASH:
            raise TrialFailure('glue_role_drift')
        data = cloud_network.read(self.aws.call)
        if data['failures']:
            raise TrialFailure('network_admission_failed')
        for wanted in self.plan['task_definitions']:
            actual = self.aws.call('ecs', 'describe-task-definition', '--task-definition',
                                   self.definitions[wanted['family']])['taskDefinition']
            check_definition(wanted, actual)
        for wanted in self.plan['glue_jobs']:
            actual = self.aws.call('glue', 'get-job', '--job-name', wanted['Name'])['Job']
            if not subset({k: v for k, v in wanted.items() if k != 'Tags'}, actual):
                raise TrialFailure('glue_job_drift')
            if actual.get('NonOverridableArguments') or actual.get('ExecutionClass', 'STANDARD') != 'STANDARD':
                raise TrialFailure('glue_job_drift')
        actual = self.aws.call('glue', 'get-connection', '--name', NAME,
                               '--hide-password')['Connection']
        if (not subset(self.plan['glue_connection'], actual) or
                actual.get('ConnectionProperties') != {} or actual.get('AuthenticationConfiguration')):
            raise TrialFailure('glue_connection_drift')

    def reserve(self, label, provider):
        state = self.ledger.state
        if state['phase'] not in ('claimed', 'running') or len(state['jobs']) >= 6:
            raise TrialFailure('dispatch_limit')
        if state['jobs'] and state['jobs'][-1].get('state') != 'verified':
            raise TrialFailure('previous_job_unconfirmed')
        job = {'label': label, 'provider': provider, 'token': uuid.uuid4().hex,
               'state': 'submission_reserved', 'reserved_at_epoch': time.time()}
        state['jobs'].append(job)
        state['phase'] = 'running'
        self.ledger.save()  # Persist before the single start request, including uncertain starts.
        self.emit({'event': 'submission_reserved', 'tier': label})
        return job

    def submit(self, job, wanted):
        if job['provider'] == 'fargate':
            request = {'cluster': NAME, 'taskDefinition': self.definitions[wanted['family']],
                       'launchType': 'FARGATE', 'platformVersion': '1.4.0', 'count': 1,
                       'clientToken': job['token'], 'startedBy': self.ledger.state['trial_id'],
                       'enableExecuteCommand': False, 'enableECSManagedTags': False,
                       'networkConfiguration': self.plan['run_network'],
                       'tags': [{'key': key, 'value': value} for key, value in runtime_plan.TAGS.items()] +
                               [{'key': 'TrialJobToken', 'value': job['token']}]}
            result = self.aws.call('ecs', 'run-task', '--cli-input-json', json.dumps(request))
            if result.get('failures') or len(result.get('tasks', [])) != 1:
                raise TrialFailure('task_start_uncertain')
            job['id'] = result['tasks'][0]['taskArn']
            if not job['id'].startswith(TASK_PREFIX):
                raise TrialFailure('unexpected_task_identity')
        else:
            # StartJobRun has no idempotency token. Never repeat this call after an error.
            result = self.aws.call('glue', 'start-job-run', '--job-name', wanted['Name'],
                                   '--arguments', json.dumps({'--utils_trial_id': job['token']}))
            job['id'] = result['JobRunId']
        job['state'] = 'submitted'
        self.ledger.save()

    def wait(self, job, wanted, timeout=1200):
        deadline = self.clock() + timeout
        while self.clock() < deadline:
            if job['provider'] == 'fargate':
                result = self.aws.call('ecs', 'describe-tasks', '--cluster', NAME,
                                       '--tasks', job['id'])
                if result.get('failures') or len(result.get('tasks', [])) != 1:
                    raise TrialFailure('task_observation_uncertain')
                actual = result['tasks'][0]
                if actual['lastStatus'] == 'STOPPED':
                    if (len(actual.get('containers', [])) != 1 or
                            actual['containers'][0].get('exitCode') != 0):
                        raise TrialFailure('task_failed')
                    job['provider_evidence'] = {key: actual.get(key) for key in (
                        'createdAt', 'pullStartedAt', 'pullStoppedAt', 'startedAt',
                        'executionStoppedAt', 'stoppedAt', 'taskDefinitionArn', 'cpu', 'memory')}
                    job['provider_terminal'] = 'STOPPED'
                    return
            else:
                actual = self.aws.call('glue', 'get-job-run', '--job-name', wanted['Name'],
                                       '--run-id', job['id'])['JobRun']
                if actual['JobRunState'] in TERMINAL:
                    if actual['JobRunState'] != 'SUCCEEDED':
                        raise TrialFailure('glue_failed')
                    job['provider_evidence'] = {key: actual.get(key) for key in (
                        'StartedOn', 'CompletedOn', 'ExecutionTime', 'DPUSeconds',
                        'MaxCapacity', 'Timeout')}
                    job['provider_terminal'] = 'SUCCEEDED'
                    return
            self.sleep(10)
        raise TrialFailure('provider_deadline')

    def metrics(self, job, wanted):
        deadline = self.clock() + 120
        while self.clock() < deadline:
            messages = []
            if job['provider'] == 'fargate':
                stream = 'smoke/smoke/' + job['id'].split('/')[-1]
                groups = [('/utils-bot/csv-trial', stream)]
            else:
                groups = []
                for group in ('/aws-glue/python-jobs/output', '/aws-glue/python-jobs/error'):
                    data = self.aws.call('logs', 'describe-log-streams', '--log-group-name', group,
                                         '--log-stream-name-prefix', job['id'])
                    groups.extend((group, row['logStreamName']) for row in data['logStreams'])
            for group, stream in groups:
                data = self.aws.call('logs', 'get-log-events', '--log-group-name', group,
                                     '--log-stream-name', stream, '--start-from-head', '--limit', '1000')
                messages.extend(row['message'] for row in data['events'])
            if any(cloud_smoke.MARKER in message for message in messages):
                arch = {'ARM64': 'aarch64', 'X86_64': 'x86_64'}.get(
                    wanted.get('runtimePlatform', {}).get('cpuArchitecture'))
                return validated_message(messages, job['provider'], arch)
            self.sleep(5)
        raise TrialFailure('metrics_not_observed')

    def workers_absent(self):
        data = cloud_network.read(self.aws.call)
        if data['failures']:
            raise TrialFailure('post_job_network_or_cleanup')
        return True

    def run(self):
        old = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        def interrupted(_signum, _frame):
            raise TrialFailure('controller_interrupted')
        for sig in old:
            signal.signal(sig, interrupted)
        try:
            return self._run()
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)

    def _run(self):
        if self.ledger.state is None:
            self.ledger.claim(self.plan)
        tiers = [('fargate', t) for t in self.plan['task_definitions']]
        tiers += [('glue', t) for t in self.plan['glue_jobs']]
        if len(tiers) != 6:
            raise TrialFailure('invalid_trial_plan')
        try:
            for provider, wanted in tiers:
                self.admission()
                label = wanted.get('family', wanted.get('Name'))
                job = self.reserve(label, provider)
                self.submit(job, wanted)
                self.wait(job, wanted)
                job['metrics'] = self.metrics(job, wanted)
                # Provider termination can precede release of a Glue ENI.
                deadline = self.clock() + 180
                while True:
                    try:
                        self.workers_absent()
                        break
                    except TrialFailure:
                        if self.clock() >= deadline:
                            raise
                        self.sleep(10)
                job['state'] = 'verified'
                self.ledger.save()
                self.emit({'event': 'job_verified', 'tier': label,
                           'provider_terminal': job['provider_terminal']})
            self.ledger.state['phase'] = 'workers_verified'
            self.ledger.save()
        except BaseException:
            self.ledger.state['phase'] = 'failed_or_uncertain'
            try:
                self.ledger.save()
            finally:
                self.stop_owned()
            raise

    def stop_owned(self):
        # Reconcile provider IDs using fixed synthetic tokens, never resubmit.
        deadline = self.clock() + 300
        while self.clock() < deadline:
            errors = []
            try:
                running = self.aws.call('ecs', 'list-tasks', '--cluster', NAME)['taskArns']
                stopped = self.aws.call('ecs', 'list-tasks', '--cluster', NAME,
                                        '--desired-status', 'STOPPED')['taskArns']
                ids = sorted(set(running + stopped))
                if any(not item.startswith(TASK_PREFIX) for item in ids):
                    raise TrialFailure('unexpected_task_identity')
                if ids:
                    records = self.aws.call('ecs', 'describe-tasks', '--cluster', NAME,
                                            '--tasks', *ids, '--include', 'TAGS')
                    if records.get('failures'):
                        raise TrialFailure('task_reconciliation_uncertain')
                    for actual in records['tasks']:
                        tags = {t['key']: t['value'] for t in actual.get('tags', [])}
                        for job in self.ledger.state['jobs']:
                            if (job['provider'] == 'fargate' and not job.get('id') and
                                    tags.get('TrialJobToken') == job['token']):
                                job['id'] = actual['taskArn']
                for task in running:
                    self.aws.call('ecs', 'stop-task', '--cluster', NAME, '--task', task,
                                  '--reason', 'bounded synthetic CSV trial cleanup')
            except TrialFailure:
                errors.append('ecs_stop_unconfirmed')
            for wanted in self.plan['glue_jobs']:
                try:
                    runs = self.aws.call('glue', 'get-job-runs', '--job-name', wanted['Name'])['JobRuns']
                    for actual in runs:
                        for job in self.ledger.state['jobs']:
                            if (job['provider'] == 'glue' and not job.get('id') and
                                    actual.get('Arguments', {}).get('--utils_trial_id') == job['token']):
                                job['id'] = actual['Id']
                    ids = [row['Id'] for row in runs if row['JobRunState'] not in TERMINAL]
                    if ids:
                        result = self.aws.call('glue', 'batch-stop-job-run',
                                               '--job-name', wanted['Name'], '--job-run-ids', *ids)
                        if result.get('Errors'):
                            errors.append('glue_stop_unconfirmed')
                except TrialFailure:
                    errors.append('glue_stop_unconfirmed')
            unresolved = any(not j.get('id') for j in self.ledger.state['jobs'])
            try:
                self.workers_absent()
                if not unresolved and not errors:
                    self.ledger.state['workers_termination_confirmed'] = True
                    self.ledger.save()
                    return
            except (TrialFailure, AssertionError):
                pass
            self.sleep(10)
        self.ledger.state['workers_termination_confirmed'] = False
        self.ledger.state['stop_errors'] = errors
        self.ledger.state['submission_reconciliation_required'] = unresolved
        self.ledger.save()
        raise TrialFailure('cleanup_unconfirmed')
