#!/usr/bin/env python3
"""Fixed synthetic smoke workload; no cloud control API or customer inputs.

Success proves worker correctness only. The controller must separately observe
provider termination before treating ephemeral storage cleanup as complete.
"""
import argparse
import hashlib
import json
import math
import os
import platform
import re
import resource
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if __package__:
    from . import fixtures, worker
else:
    import fixtures
    import worker

MAX_STDOUT = 32768
DEADLINE_SECONDS = 900
OPERATIONS = ('dedupe', 'join', 'aggregate')
MARKER = 'UTILS_CSV_TRIAL_METRICS '
METRIC_KEYS = {
    'operation', 'input_rows', 'output_rows', 'input_bytes', 'logical_bytes',
    'encoded_bytes', 'logical_sha256', 'encoded_sha256', 'worker_wall_seconds',
    'worker_cpu_seconds', 'peak_rss_bytes', 'sampled_peak_scratch_bytes',
    'phases', 'python', 'architecture', 'sqlite', 'zlib', 'worker_sha256',
    'gzip_level',
}


class SmokeFailure(Exception):
    pass


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def smoke(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
        raise SmokeFailure('invalid_scratch')
    if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise SmokeFailure('invalid_scratch')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    started = time.perf_counter()
    manifest = fixtures.generate(root / 'fixtures', mib=1, join_stride=2)
    fixture_seconds = time.perf_counter() - started
    results = []
    expected_keys = ('expected_dedupe_rows', 'expected_join_rows', 'expected_aggregate_groups')
    for operation, expected_key in zip(OPERATIONS, expected_keys):
        row = worker.execute(
            operation, root / 'fixtures/left.csv',
            root / 'fixtures/right.csv' if operation == 'join' else None,
            root / operation, max_input=1 << 20, max_output=2 << 20,
            max_encoded=2 << 20, max_rows=5000, max_pairs=5000, max_groups=100)
        if (row['status'] != 'ok' or row['output_rows'] != manifest[expected_key] or
                row['logical_sha256'] != manifest['expected_logical_sha256'][operation]):
            raise SmokeFailure('oracle_mismatch')
        results.append({key: row[key] for key in METRIC_KEYS})
    return {
        'schema_version': 1, 'status': 'ok', 'synthetic': True,
        'fixture_version': manifest['fixture_version'],
        'input_bytes': {name: item['bytes'] for name, item in manifest['files'].items()},
        'results': results, 'fixture_seconds': fixture_seconds,
        'python': platform.python_version(), 'architecture': platform.machine(),
        'worker_sha256': _digest(worker.__file__),
        'fixtures_sha256': _digest(fixtures.__file__),
        'harness_sha256': _digest(__file__),
        'scope': 'synthetic 1 MiB correctness smoke; worker time is not provider billed time',
        'scratch': 'disposable job storage; provider termination must be confirmed separately',
    }


def run_child(command, env, timeout=DEADLINE_SECONDS, max_stdout=MAX_STDOUT):
    """Bound time/output and always stop the owned POSIX process group."""
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=env, start_new_session=True)
    buffer = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise SmokeFailure('deadline_exceeded')
                if not selector.select(timeout=min(left, .25)):
                    continue
                chunk = os.read(child.stdout.fileno(), min(4096, max_stdout + 1 - len(buffer)))
                if not chunk:
                    break
                buffer.extend(chunk)
                if len(buffer) > max_stdout:
                    raise SmokeFailure('metrics_limit')
        try:
            code = child.wait(timeout=max(.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise SmokeFailure('deadline_exceeded') from None
        if code != 0:
            raise SmokeFailure('worker_failed')
        return bytes(buffer)
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise SmokeFailure('termination_unconfirmed') from None
        finally:
            child.stdout.close()


def validate_metrics(raw):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise SmokeFailure('invalid_metrics') from None
    wanted = {'schema_version', 'status', 'synthetic', 'fixture_version', 'input_bytes',
              'results', 'fixture_seconds', 'python', 'architecture', 'worker_sha256',
              'fixtures_sha256', 'harness_sha256', 'scope', 'scratch'}
    if (not isinstance(value, dict) or set(value) != wanted or
            value['schema_version'] != 1 or value['status'] != 'ok' or
            value['synthetic'] is not True or value['fixture_version'] != 2):
        raise SmokeFailure('invalid_metrics')
    if value['scope'] != 'synthetic 1 MiB correctness smoke; worker time is not provider billed time':
        raise SmokeFailure('invalid_metrics')
    if value['scratch'] != 'disposable job storage; provider termination must be confirmed separately':
        raise SmokeFailure('invalid_metrics')
    def check(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_.]+', key):
                    raise SmokeFailure('invalid_metrics')
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
        elif isinstance(item, bool):
            return
        elif isinstance(item, (int, float)):
            if not math.isfinite(item) or item < 0:
                raise SmokeFailure('invalid_metrics')
        elif isinstance(item, str):
            if not re.fullmatch(r'[A-Za-z0-9_.]+', item):
                raise SmokeFailure('invalid_metrics')
        else:
            raise SmokeFailure('invalid_metrics')
    check({key: child for key, child in value.items() if key not in ('scope', 'scratch')})
    if (not isinstance(value['results'], list) or len(value['results']) != 3 or
            [row.get('operation') for row in value['results']] != list(OPERATIONS) or
            any(set(row) != METRIC_KEYS for row in value['results'])):
        raise SmokeFailure('invalid_metrics')
    if value['input_bytes'].keys() != {'left.csv', 'right.csv'} or any(
            not isinstance(n, int) or isinstance(n, bool) or not 0 < n <= 1 << 20
            for n in value['input_bytes'].values()):
        raise SmokeFailure('invalid_metrics')
    for key, path in [('worker_sha256', worker.__file__),
                      ('fixtures_sha256', fixtures.__file__), ('harness_sha256', __file__)]:
        if value[key] != _digest(path):
            raise SmokeFailure('source_mismatch')
    for row in value['results']:
        for key in ('logical_sha256', 'encoded_sha256', 'worker_sha256'):
            if not re.fullmatch(r'[0-9a-f]{64}', row[key]):
                raise SmokeFailure('invalid_metrics')
        if row['worker_sha256'] != value['worker_sha256']:
            raise SmokeFailure('source_mismatch')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-root', default='/work')
    parser.add_argument('--provider', choices=['local', 'fargate', 'glue'], default='fargate')
    parser.add_argument('--child-root', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.child_root:
        try:
            print(json.dumps(smoke(args.child_root), sort_keys=True))
            return 0
        except Exception:
            print('{"status":"failed","code":"smoke_failed"}')
            return 1
    def interrupted(_signum, _frame):
        raise SmokeFailure('interrupted')
    old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in old_handlers:
        signal.signal(sig, interrupted)
    old_mask = os.umask(0o077)
    try:
        base = Path(args.work_root).resolve(strict=True)
        if not base.is_dir() or os.getuid() == 0:
            raise SmokeFailure('invalid_scratch')
        root = Path(tempfile.mkdtemp(prefix='utils-csv-smoke-', dir=base))
        root.chmod(0o700)
        if __package__:
            command = [sys.executable, '-m', __package__ + '.cloud_smoke']
            module_root = Path(__file__).resolve().parents[1]
        else:
            command = [sys.executable, str(Path(__file__).resolve())]
            module_root = Path(__file__).resolve().parent
        # No inherited AWS credential/environment variables in the child.
        # This does not remove Glue's service identity or prove a sandbox.
        child_env = {'PYTHONPATH': str(module_root), 'PYTHONDONTWRITEBYTECODE': '1',
                     'PYTHONUNBUFFERED': '1', 'TMPDIR': str(root)}
        started = time.monotonic()
        value = validate_metrics(run_child(command + ['--child-root', str(root)], child_env))
        value.update(supervisor_seconds=time.monotonic() - started, provider_label=args.provider,
                     provider_evidence_required=True, provider_storage_cleanup_required=True)
        print(MARKER + json.dumps(value, sort_keys=True), flush=True)
        return 0
    except SmokeFailure as error:
        print(MARKER + json.dumps({'status': 'failed', 'code': str(error)}), flush=True)
        return 1
    except Exception:
        print(MARKER + '{"status":"failed","code":"supervisor_failed"}', flush=True)
        return 1
    finally:
        os.umask(old_mask)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    raise SystemExit(main())
