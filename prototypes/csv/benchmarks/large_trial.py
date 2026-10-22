#!/usr/bin/env python3
"""Synthetic large-file candidate for ARM Fargate; never accepts customer data.

One fixed operation per task. Fixture generation/oracle time is reported separately
from processing. Provider startup, transfer, billing and deletion require separate
controller evidence; a successful local run proves none of those cloud properties.
"""
import argparse
import gzip
import hashlib
import json
import os
import re
import resource
import signal
import sys
import tempfile
import time
from pathlib import Path

import cloud_smoke
import fixtures
import worker

SIZES = (16, 128, 1024)
OPERATIONS = ('dedupe', 'join', 'aggregate')
MARKER = 'UTILS_CSV_LARGE_METRICS '
SCOPE = 'synthetic disk-backed diagnostic; not a public tool or cloud cost measurement'


def evaluate(root, mib, operation):
    root = Path(root)
    if (mib not in (1,) + SIZES or operation not in OPERATIONS or
            root.is_symlink() or not root.is_dir() or any(root.iterdir()) or
            root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077):
        raise cloud_smoke.SmokeFailure('invalid_trial')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    started = time.monotonic()
    manifest = fixtures.generate(root / 'fixtures', mib=mib, join_stride=2)
    fixture_seconds = time.monotonic() - started
    for name, entry in manifest['files'].items():
        if entry['bytes'] > mib << 20 or worker.digest(root / 'fixtures' / name) != entry['sha256']:
            raise cloud_smoke.SmokeFailure('fixture_mismatch')
    row = worker.execute(operation, root / 'fixtures/left.csv',
                         root / 'fixtures/right.csv' if operation == 'join' else None,
                         root / 'result', max_input=mib << 20,
                         max_output=2 * (mib << 20), max_encoded=2 * (mib << 20))
    key = {'dedupe': 'dedupe_rows', 'join': 'join_rows', 'aggregate': 'aggregate_groups'}[operation]
    # Read the complete actual artifact, independently of the worker's own hash.
    verification_started = time.monotonic()
    actual = hashlib.sha256()
    logical_bytes = 0
    with gzip.open(root / 'result/result.csv.gz', 'rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            logical_bytes += len(block)
            if logical_bytes > 2 * (mib << 20):
                raise cloud_smoke.SmokeFailure('output_limit')
            actual.update(block)
    if (row['status'] != 'ok' or row['output_rows'] != manifest['expected_' + key] or
            row['logical_sha256'] != actual.hexdigest() or row['logical_bytes'] != logical_bytes or
            actual.hexdigest() != manifest['expected_logical_sha256'][operation] or
            row['encoded_sha256'] != worker.digest(root / 'result/result.csv.gz')):
        raise cloud_smoke.SmokeFailure('oracle_mismatch')
    result = {key: row[key] for key in cloud_smoke.METRIC_KEYS}
    return dict(schema_version=1, status='ok', synthetic=True, mib_per_input=mib,
                operation=operation, fixture_seconds=fixture_seconds,
                artifact_verification_seconds=time.monotonic() - verification_started,
                fixture_bytes={name: entry['bytes'] for name, entry in manifest['files'].items()},
                result=result,
                source_sha256={name: worker.digest(Path(__file__).with_name(name)) for name in
                               ('large_trial.py', 'cloud_smoke.py', 'fixtures.py', 'worker.py')},
                scope=SCOPE)


def validate(raw, mib, operation):
    try:
        value = json.loads(raw)
        keys = {'schema_version', 'status', 'synthetic', 'mib_per_input', 'operation',
                'fixture_seconds', 'artifact_verification_seconds', 'fixture_bytes',
                'result', 'source_sha256', 'scope'}
        if (set(value) != keys or value['schema_version'] != 1 or value['status'] != 'ok' or
                value['synthetic'] is not True or value['mib_per_input'] != mib or
                value['operation'] != operation or value['scope'] != SCOPE or
                set(value['result']) != cloud_smoke.METRIC_KEYS or
                value['result']['operation'] != operation or
                value['source_sha256'] != {name: worker.digest(Path(__file__).with_name(name))
                                          for name in ('large_trial.py', 'cloud_smoke.py', 'fixtures.py', 'worker.py')}):
            raise ValueError()
        # Reuse the smoke validator's restricted scalar vocabulary, numeric checks
        # and metric schema without changing the completed six-job smoke contract.
        import math
        def check(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    if not re.fullmatch(r'[A-Za-z0-9_.]+', key):
                        raise ValueError()
                    check(child)
            elif isinstance(item, list):
                for child in item:
                    check(child)
            elif isinstance(item, bool):
                return
            elif isinstance(item, (int, float)):
                if not math.isfinite(item) or item < 0:
                    raise ValueError()
            elif isinstance(item, str):
                if not re.fullmatch(r'[A-Za-z0-9_.]+', item):
                    raise ValueError()
            else:
                raise ValueError()
        check({k: v for k, v in value.items() if k != 'scope'})
        if (set(value['fixture_bytes']) != {'left.csv', 'right.csv'} or
                any(type(n) is not int or not 0 < n <= mib << 20 for n in value['fixture_bytes'].values())):
            raise ValueError()
        for key in ('logical_sha256', 'encoded_sha256', 'worker_sha256'):
            if not re.fullmatch(r'[a-f0-9]{64}', value['result'][key]):
                raise ValueError()
        if value['result']['worker_sha256'] != value['source_sha256']['worker.py']:
            raise ValueError()
        return value
    except (ValueError, TypeError, KeyError, AttributeError):
        raise cloud_smoke.SmokeFailure('invalid_metrics') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mib', type=int, choices=SIZES, required=True)
    parser.add_argument('--operation', choices=OPERATIONS, required=True)
    parser.add_argument('--work-root', default='/work')
    parser.add_argument('--child-root', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.child_root:
        try:
            print(json.dumps(evaluate(args.child_root, args.mib, args.operation), sort_keys=True))
            return 0
        except Exception:
            print('{"status":"failed","code":"large_trial_failed"}')
            return 1
    def interrupted(_signum, _frame):
        raise cloud_smoke.SmokeFailure('interrupted')
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in handlers:
        signal.signal(sig, interrupted)
    mask = os.umask(0o077)
    try:
        base = Path(args.work_root)
        if base.is_symlink() or not base.is_dir() or os.getuid() == 0:
            raise cloud_smoke.SmokeFailure('invalid_scratch')
        root = Path(tempfile.mkdtemp(prefix='utils-csv-large-', dir=base))
        command = [sys.executable, str(Path(__file__).resolve()), '--mib', str(args.mib),
                   '--operation', args.operation, '--child-root', str(root)]
        env = dict(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', TMPDIR=str(root))
        started = time.monotonic()
        result = validate(cloud_smoke.run_child(command, env), args.mib, args.operation)
        result.update(supervisor_seconds=time.monotonic() - started,
                      provider_evidence_required=True, provider_storage_cleanup_required=True)
        print(MARKER + json.dumps(result, sort_keys=True), flush=True)
        return 0
    except cloud_smoke.SmokeFailure as error:
        print(MARKER + json.dumps(dict(status='failed', code=str(error))), flush=True)
        return 1
    except Exception:
        print(MARKER + '{"status":"failed","code":"supervisor_failed"}', flush=True)
        return 1
    finally:
        os.umask(mask)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    raise SystemExit(main())
