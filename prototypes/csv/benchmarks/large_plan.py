"""Pure three-job ARM Fargate large-file plan. Does not provision or start AWS jobs.

The completed six-job smoke ledger is immutable history. This workload requires a
new conditional ledger, image admission, network/role checks and cost reservation.
"""
import re

REGION = 'us-east-2'
NAME = 'utils-bot-csv-trial'


def build(account, subnet, group, image_digest):
    if not re.fullmatch(r'[0-9]{12}', account) or account == '000000000000':
        raise ValueError('invalid account')
    for value, prefix in ((subnet, 'subnet'), (group, 'sg')):
        if not re.fullmatch(prefix + r'-[a-f0-9]{17}', value):
            raise ValueError('invalid network identifier')
    if not re.fullmatch(r'[a-f0-9]{64}', image_digest):
        raise ValueError('immutable digest required')
    return {
        'schema_version': 1, 'synthetic_only': True, 'max_jobs': 3, 'max_concurrency': 1,
        'deadline_seconds': 900,
        'scope': '1 GiB per input, fixed synthetic dedupe/join/aggregate; no customer transfers or payments',
        'requires': ['new conditional ledger; never reset the completed first-six-v1 ledger',
                     'source and image admission', 'live private network and IAM checks',
                     'compute plus private endpoint/storage/logging cost reservation',
                     'provider timestamps and verified task/ENI/scratch cleanup'],
        'task_definition': {
            'family': NAME + '-arm-large', 'networkMode': 'awsvpc',
            'requiresCompatibilities': ['FARGATE'], 'cpu': '1024', 'memory': '2048',
            'executionRoleArn': 'arn:aws:iam::' + account + ':role/' + NAME + '-ecs-execution',
            'runtimePlatform': {'cpuArchitecture': 'ARM64', 'operatingSystemFamily': 'LINUX'},
            'volumes': [{'name': 'work'}],
            'tags': [{'key': 'Project', 'value': 'utils-bot'}, {'key': 'Purpose', 'value': NAME}],
            'containerDefinitions': [{
                'name': 'large-trial',
                'image': account + '.dkr.ecr.' + REGION + '.amazonaws.com/' + NAME + '@sha256:' + image_digest,
                'essential': True, 'user': '10001:10001', 'readonlyRootFilesystem': True,
                'privileged': False, 'stopTimeout': 30,
                'linuxParameters': {'capabilities': {'drop': ['ALL']}, 'initProcessEnabled': True},
                'mountPoints': [{'sourceVolume': 'work', 'containerPath': '/work', 'readOnly': False}],
                'ulimits': [{'name': 'core', 'softLimit': 0, 'hardLimit': 0},
                            {'name': 'nofile', 'softLimit': 256, 'hardLimit': 256}],
                'logConfiguration': {'logDriver': 'awslogs', 'options': {
                    'awslogs-group': '/utils-bot/csv-trial', 'awslogs-region': REGION,
                    'awslogs-stream-prefix': 'large'}},
            }],
        },
        'run_network': {'awsvpcConfiguration': {'subnets': [subnet], 'securityGroups': [group],
                                               'assignPublicIp': 'DISABLED'}},
        'overrides': [{'containerOverrides': [{'name': 'large-trial', 'command': [
            '--mib', '1024', '--operation', operation]}]} for operation in ('dedupe', 'join', 'aggregate')],
    }
