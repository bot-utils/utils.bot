#!/usr/bin/env python3
"""Serial local-only resource-limited validation. Prints metrics; creates no report."""
import argparse
import json
import os
import subprocess
import uuid

import large_trial
import local_trial

LABEL = 'utils.bot.csv.large.trial'


def run_cases(sizes, operations, image='utils-bot-csv-large:local'):
    if (not sizes or len(set(sizes)) != len(sizes) or any(n not in large_trial.SIZES for n in sizes) or
            not operations or len(set(operations)) != len(operations) or
            any(op not in large_trial.OPERATIONS for op in operations)):
        raise ValueError('invalid trial plan')
    local_trial._endpoint = local_trial.local_endpoint()
    image_id = local_trial.docker(['image', 'inspect', '--format', '{{.Id}}', image]).stdout.strip()
    if not image_id.startswith('sha256:') or len(image_id) != 71:
        raise RuntimeError('immutable local image unavailable')
    label = uuid.uuid4().hex
    owned = []
    results = []
    try:
        for mib in sizes:
            for operation in operations:
                name = 'utils-csv-large-' + label + '-' + str(len(owned))
                owned.append(name)
                local_trial.docker(['volume', 'create', '--label', LABEL + '=' + label, name])
                local_trial.docker(['create', '--name', name, '--label', LABEL + '=' + label,
                                    '--pull=never', '--network=none', '--ipc=none', '--read-only',
                                    '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                                    '--pids-limit=32', '--ulimit=core=0', '--ulimit=nofile=256:256',
                                    '--log-driver=none', '--cpus=1', '--memory=2g', '--memory-swap=2g',
                                    '--mount', 'type=volume,source=' + name + ',target=/work', image_id,
                                    '--mib', str(mib), '--operation', operation])
                raw = local_trial.docker(['start', '--attach', name], timeout=920).stdout
                if not raw.startswith(large_trial.MARKER) or len(raw) > 32768:
                    raise RuntimeError('invalid trial metrics')
                result = json.loads(raw[len(large_trial.MARKER):])
                supervisor = result.pop('supervisor_seconds')
                if (result.pop('provider_evidence_required') is not True or
                        result.pop('provider_storage_cleanup_required') is not True):
                    raise RuntimeError('invalid trial metrics')
                large_trial.validate(json.dumps(result), mib, operation)
                state = json.loads(local_trial.docker(['inspect', '--format', '{{json .State}}', name]).stdout)
                if state['Running'] or state['ExitCode'] != 0 or state.get('OOMKilled'):
                    raise RuntimeError('worker terminal state invalid')
                result.update(local_supervisor_seconds=supervisor, local_cpu_limit=1, local_memory_mib=2048,
                              provider_billing_measured=False)
                results.append(result)
                row = result['result']
                print(json.dumps(dict(mib_per_input=mib, operation=operation,
                                      worker_seconds=row['worker_wall_seconds'],
                                      process_peak_rss_bytes=row['peak_rss_bytes'],
                                      logical_bytes=row['logical_bytes'], encoded_bytes=row['encoded_bytes'],
                                      output_rows=row['output_rows'], python=row['python'],
                                      logical_sha256=row['logical_sha256'], image_id=image_id,
                                      local_cpu_limit=1, local_memory_mib=2048,
                                      oracle_verified=True, scope='local_synthetic_only'), sort_keys=True), flush=True)
                # Reclaim each finished job before admitting the next size/operation.
                local_trial.docker(['container', 'prune', '--force', '--filter', 'label=' + LABEL + '=' + label])
                local_trial.docker(['volume', 'prune', '--all', '--force', '--filter', 'label=' + LABEL + '=' + label])
                if local_trial.docker(['volume', 'ls', '--filter', 'label=' + LABEL + '=' + label,
                                       '--format', '{{.Name}}']).stdout.strip():
                    raise RuntimeError('scratch cleanup unconfirmed')
    finally:
        # Kill is intentionally allowed to fail for a task already pruned/stopped.
        for name in owned:
            subprocess.run(['docker', '--host', local_trial._endpoint, 'kill', '--signal=KILL', name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                           env={k: v for k, v in os.environ.items() if k not in ('DOCKER_HOST', 'DOCKER_CONTEXT')})
        local_trial.docker(['container', 'prune', '--force', '--filter', 'label=' + LABEL + '=' + label])
        local_trial.docker(['volume', 'prune', '--all', '--force', '--filter', 'label=' + LABEL + '=' + label])
        containers = local_trial.docker(['ps', '--all', '--filter', 'label=' + LABEL + '=' + label,
                                         '--format', '{{.Names}}']).stdout.strip()
        volumes = local_trial.docker(['volume', 'ls', '--filter', 'label=' + LABEL + '=' + label,
                                      '--format', '{{.Name}}']).stdout.strip()
        clean = not containers and not volumes
        print(json.dumps(dict(cleanup_confirmed=clean, owned_containers_remaining=bool(containers),
                              owned_scratch_volumes_remaining=bool(volumes), no_aws_calls=True)), flush=True)
        if not clean:
            raise RuntimeError('owned worker or scratch cleanup unconfirmed')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sizes', nargs='+', type=int, choices=large_trial.SIZES, default=list(large_trial.SIZES))
    parser.add_argument('--operations', nargs='+', choices=large_trial.OPERATIONS, default=list(large_trial.OPERATIONS))
    args = parser.parse_args()
    run_cases(args.sizes, args.operations)


if __name__ == '__main__':
    main()
