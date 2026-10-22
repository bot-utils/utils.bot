"""Pure request builder for six fixed synthetic smoke tiers; never calls AWS.

These supplied identifiers and digests are not live admission or authorization.
Provisioning and dispatch need independent live checks and a trial controller.
"""
import re

REGION = 'us-east-2'
NAME = 'utils-bot-csv-trial'
TAGS = {'Project': 'utils-bot', 'Purpose': NAME}
TIERS = (('arm-small', 'ARM64', 256, 1024), ('x86-small', 'X86_64', 256, 1024),
         ('arm-large', 'ARM64', 4096, 16384), ('x86-large', 'X86_64', 4096, 16384))


def build(account, subnet, glue_group, fargate_group, code_sha256, arm_digest, x86_digest):
    if not re.fullmatch(r'[0-9]{12}', account) or account == '000000000000':
        raise ValueError('invalid account')
    for value, prefix in ((subnet, 'subnet'), (glue_group, 'sg'), (fargate_group, 'sg')):
        if not re.fullmatch(prefix + r'-[a-f0-9]{17}', value):
            raise ValueError('invalid network identifier')
    if glue_group == fargate_group:
        raise ValueError('worker groups must be separate')
    for digest in (code_sha256, arm_digest, x86_digest):
        if not re.fullmatch(r'[a-f0-9]{64}', digest):
            raise ValueError('immutable digest required')
    role = lambda suffix: 'arn:aws:iam::' + account + ':role/' + NAME + '-' + suffix
    bucket = NAME + '-' + account + '-' + REGION
    code = 's3://' + bucket + '/trial/code/' + code_sha256 + '/'
    registry = account + '.dkr.ecr.' + REGION + '.amazonaws.com/' + NAME
    list_tags = [{'key': key, 'value': value} for key, value in TAGS.items()]
    definitions = []
    for label, architecture, cpu, memory in TIERS:
        digest = arm_digest if architecture == 'ARM64' else x86_digest
        definitions.append({
            'family': NAME + '-' + label, 'networkMode': 'awsvpc',
            'requiresCompatibilities': ['FARGATE'], 'cpu': str(cpu), 'memory': str(memory),
            'executionRoleArn': role('ecs-execution'),
            'runtimePlatform': {'cpuArchitecture': architecture, 'operatingSystemFamily': 'LINUX'},
            'volumes': [{'name': 'work'}], 'tags': list_tags,
            'containerDefinitions': [{
                'name': 'smoke', 'image': registry + '@sha256:' + digest, 'essential': True,
                'user': '10001:10001', 'readonlyRootFilesystem': True, 'privileged': False,
                'command': ['--provider', 'fargate', '--work-root', '/work'],
                'linuxParameters': {'capabilities': {'drop': ['ALL']}, 'initProcessEnabled': True},
                'mountPoints': [{'sourceVolume': 'work', 'containerPath': '/work', 'readOnly': False}],
                'ulimits': [{'name': 'core', 'softLimit': 0, 'hardLimit': 0},
                            {'name': 'nofile', 'softLimit': 256, 'hardLimit': 256}],
                'logConfiguration': {'logDriver': 'awslogs', 'options': {
                    'awslogs-group': '/utils-bot/csv-trial', 'awslogs-region': REGION,
                    'awslogs-stream-prefix': 'smoke'}},
            }],
        })
    jobs = []
    for label, dpu in (('small', .0625), ('large', 1)):
        jobs.append({
            'Name': NAME + '-glue-' + label, 'Role': role('glue'),
            'Command': {'Name': 'pythonshell', 'PythonVersion': '3.9',
                        'ScriptLocation': code + 'glue_smoke.py'},
            'Connections': {'Connections': [NAME]},
            'DefaultArguments': {'--library-set': 'none',
                                 '--extra-py-files': code + 'utils_bot_csv_trial-0.1.0-py3-none-any.whl'},
            'MaxCapacity': dpu, 'Timeout': 15, 'MaxRetries': 0,
            'ExecutionProperty': {'MaxConcurrentRuns': 1}, 'Tags': TAGS,
        })
    return {
        'schema_version': 1, 'synthetic_only': True, 'max_jobs': 6, 'max_concurrency': 1,
        'scope': '1 MiB correctness smoke only; no customer transfers, public routes or payment',
        'requires': ['live network and IAM admission', 'serial crash-safe controller',
                     'reviewed six-job cost reservation', 'provider termination evidence'],
        'bucket': {'name': bucket, 'public_access_block': {
            'BlockPublicAcls': True, 'IgnorePublicAcls': True,
            'BlockPublicPolicy': True, 'RestrictPublicBuckets': True},
            'encryption': 'AES256', 'object_ownership': 'BucketOwnerEnforced',
            'code_expiration_days': 1, 'abort_incomplete_multipart_days': 1},
        'repository': {'repositoryName': NAME, 'imageTagMutability': 'IMMUTABLE',
                       'imageScanningConfiguration': {'scanOnPush': False},
                       'encryptionConfiguration': {'encryptionType': 'AES256'},
                       'tags': list_tags},
        'cluster': {'clusterName': NAME, 'tags': list_tags,
                    'settings': [{'name': 'containerInsights', 'value': 'disabled'}]},
        'logs': {'retention_days_for_new_groups': 7,
                 'existing_group_settings': 'preserve', 'names': ['/utils-bot/csv-trial',
                 '/aws-glue/python-jobs/output', '/aws-glue/python-jobs/error']},
        'glue_connection': {'Name': NAME, 'ConnectionType': 'NETWORK',
            'PhysicalConnectionRequirements': {'SubnetId': subnet,
                'SecurityGroupIdList': [glue_group], 'AvailabilityZone': 'us-east-2a'}},
        'glue_jobs': jobs, 'task_definitions': definitions,
        'run_network': {'awsvpcConfiguration': {'subnets': [subnet],
                        'securityGroups': [fargate_group], 'assignPublicIp': 'DISABLED'}},
    }
