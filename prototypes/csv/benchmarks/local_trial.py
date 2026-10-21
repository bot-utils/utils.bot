#!/usr/bin/env python3
"""Resource-limited native local diagnostic. No AWS calls or billing claims."""
import argparse
import json
import os
import stat
import random
import statistics
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from worker import digest


_endpoint = None


def local_endpoint():
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT'):
        if key in os.environ:
            raise RuntimeError('Docker endpoint overrides are not supported')
    result = subprocess.run(['docker', 'context', 'inspect'], text=True,
                            capture_output=True, timeout=5, check=True)
    contexts = json.loads(result.stdout)
    if len(contexts) != 1:
        raise RuntimeError('ambiguous Docker context')
    endpoint = contexts[0]['Endpoints']['docker']['Host']
    parsed = urlsplit(endpoint)
    allowed = {'/var/run/docker.sock', str(Path.home()/'.docker/run/docker.sock'),
               str(Path.home()/'.colima/default/docker.sock')}
    if parsed.scheme != 'unix' or parsed.netloc or parsed.query or parsed.fragment or parsed.path not in allowed:
        raise RuntimeError('only a supported local Docker socket is allowed')
    if not stat.S_ISSOCK(Path(parsed.path).stat().st_mode):
        raise RuntimeError('Docker endpoint is not a local socket')
    return endpoint


def docker(args, timeout=60):
    if _endpoint is None:
        raise RuntimeError('local Docker endpoint was not verified')
    env = {key: value for key, value in os.environ.items()
           if key not in ('DOCKER_HOST', 'DOCKER_CONTEXT')}
    result = subprocess.run(['docker', '--host', _endpoint, *args], text=True,
                            capture_output=True, timeout=timeout, env=env)
    if result.returncode:
        raise RuntimeError('local docker ' + args[0] + ' failed')
    return result


def main():
    global _endpoint
    _endpoint = local_endpoint()
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixtures', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--repeats', type=int, default=3, choices=[1, 3])
    args = parser.parse_args()
    fixture = Path(args.fixtures).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError('output directory must be empty')
    manifest = json.loads((fixture / 'manifest.json').read_text())
    for name, entry in manifest['files'].items():
        assert digest(fixture / name) == entry['sha256'], 'fixture checksum mismatch'
    image = docker(['image', 'inspect', '--format', '{{.Id}}', 'utils-bot-csv-python-trial:local']).stdout.strip()
    label = uuid.uuid4().hex
    plan = [(repeat, tier, operation) for repeat in range(args.repeats)
            for tier in ['small', 'large'] for operation in ['dedupe', 'join', 'aggregate']]
    random.Random(20261021).shuffle(plan)
    measurements = []
    owned = []
    try:
        for repeat, tier, operation in plan:
            name = 'utils-csv-trial-' + label[:10] + '-' + str(len(measurements))
            work = output / name
            work.mkdir(mode=0o777)
            work.chmod(0o777)  # Dedicated synthetic scratch only, never content/credentials.
            command = ['create', '--name', name, '--label', 'utils.bot.csv.python.trial=' + label,
                       '--pull=never', '--network=none', '--ipc=none', '--read-only', '--cap-drop=ALL',
                       '--security-opt=no-new-privileges', '--pids-limit=32', '--log-driver=none',
                       '--cpus=' + ('.25' if tier == 'small' else '4'),
                       '--memory=' + ('1g' if tier == 'small' else '16g'),
                       '--memory-swap=' + ('1g' if tier == 'small' else '16g'),
                       '--mount', 'type=bind,src=' + str(fixture) + ',dst=/data,readonly',
                       '--mount', 'type=bind,src=' + str(work) + ',dst=/work', image,
                       '--operation', operation, '--left', '/data/left.csv', '--work', '/work/job']
            if operation == 'join':
                command += ['--right', '/data/right.csv']
            docker(command)
            owned.append(name)
            t = time.perf_counter()
            result = json.loads(docker(['start', '--attach', name], timeout=900).stdout)
            result.update(repeat=repeat, tier=tier, container_elapsed_seconds=time.perf_counter() - t)
            expected = manifest['expected_' + {'dedupe': 'dedupe_rows', 'join': 'join_rows',
                                               'aggregate': 'aggregate_groups'}[operation]]
            assert result['output_rows'] == expected, 'planted row-count mismatch'
            assert result['logical_sha256'] == manifest['expected_logical_sha256'][operation], 'independent logical checksum mismatch'
            assert result['status'] == 'ok'
            result['scope'] = 'local native ARM diagnostic; no AWS startup, transfer or billed time'
            measurements.append(result)
            (output / 'measurements.json').write_text(json.dumps({'image': image, 'fixture': manifest,
                'runs': measurements, 'trial_label': label}, indent=2))
            print(json.dumps({'repeat': repeat, 'tier': tier, 'operation': operation,
                              'wall_seconds': result['worker_wall_seconds'],
                              'rss_mib': result['peak_rss_bytes'] / 2**20,
                              'logical_bytes': result['logical_bytes'],
                              'encoded_bytes': result['encoded_bytes']}), flush=True)
            # Keep raw metrics and exact checksum; trash generated result/scratch.
            subprocess.run(['trash', str(work)], check=True, capture_output=True)
    finally:
        for name in owned:
            subprocess.run(['docker', '--host', _endpoint, 'kill', '--signal=KILL', name], capture_output=True, timeout=15, env={k:v for k,v in os.environ.items() if k not in ('DOCKER_HOST','DOCKER_CONTEXT')})
        docker(['container', 'prune', '--force', '--filter', 'label=utils.bot.csv.python.trial=' + label])
        remaining = docker(['ps', '--all', '--filter', 'label=utils.bot.csv.python.trial=' + label,
                            '--format', '{{.Names}}']).stdout.strip()
        if remaining:
            raise RuntimeError('owned container cleanup unconfirmed')
        (output / 'cleanup.json').write_text(json.dumps({'owned_containers_remaining': 0,
                                                        'no_aws_calls': True}))
    for op in ['dedupe', 'join', 'aggregate']:
        for tier in ['small', 'large']:
            runs = [r for r in measurements if r['operation'] == op and r['tier'] == tier]
            assert len({r['logical_sha256'] for r in runs}) == 1
            assert len({r['encoded_sha256'] for r in runs}) == 1
            print(json.dumps({'operation': op, 'tier': tier, 'n': len(runs),
                              'median_worker_seconds': statistics.median(r['worker_wall_seconds'] for r in runs)}))


if __name__ == '__main__':
    main()
