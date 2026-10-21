#!/usr/bin/env python3
"""Private backend diagnostic, not a production CSV endpoint.

Identical Python/SQLite disk-backed operations for Glue and Fargate. Fixed
fixture schema and options intentionally cover only the comparison workload.
No network, customer data, credentials, dynamic SQL names or content logging.
"""
import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import platform
import re
import resource
import sqlite3
import sys
import time
import zlib
from pathlib import Path

HEADER = ['key', 'group', 'amount', 'payload']
SCALE = 10**18


class Failure(Exception):
    pass


def scaled(value):
    if not re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]+)?', value):
        raise Failure('invalid_decimal')
    unsigned = value.lstrip('+-')
    whole, _, fraction = unsigned.partition('.')
    if len(whole + fraction) > 38 or len(fraction) > 18:
        raise Failure('decimal_range')
    result = int(whole) * SCALE + int((fraction + '0' * 18)[:18])
    return -result if value.startswith('-') else result


def canonical(value):
    sign = '-' if value < 0 else ''
    whole, fraction = divmod(abs(value), SCALE)
    text = str(whole) + ('.' + str(fraction).zfill(18).rstrip('0') if fraction else '')
    if len(text.replace('.', '')) > 43:
        raise Failure('decimal_range')
    return sign + text


class ExactSum:
    def __init__(self):
        self.total = 0

    def step(self, value):
        self.total += scaled(value)

    def finalize(self):
        return canonical(self.total)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def rows(path, max_input, max_rows):
    if Path(path).stat().st_size > max_input:
        raise Failure('file_limit')
    csv.field_size_limit(16 << 10)
    with Path(path).open(encoding='utf-8', newline='') as source:
        reader = csv.reader(source, strict=True)
        if next(reader, None) != HEADER:
            raise Failure('invalid_header')
        count = 0
        for row in reader:
            if not row:
                continue
            if len(row) != 4 or any('\x00' in v for v in row):
                raise Failure('invalid_csv')
            if any(len(v.encode('utf-8')) > 16384 for v in row):
                raise Failure('cell_limit')
            count += 1
            if count > max_rows:
                raise Failure('row_limit')
            yield row


def execute(operation, left, right, work, max_input=1 << 30,
            max_output=1 << 30, max_encoded=1 << 30, max_rows=10_000_000,
            max_pairs=10_000_000, max_groups=10_000, keep='first', level=1):
    started = time.perf_counter()
    cpu_started = time.process_time()
    work = Path(work)
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(work.iterdir()):
        raise Failure('work_directory_not_empty')
    if operation not in ('dedupe', 'join', 'aggregate') or keep not in ('first', 'last'):
        raise Failure('invalid_options')
    db = sqlite3.connect(str(work / 'spill.sqlite'))
    # Bound SQLite cache; temp spill stays in this job's isolated scratch.
    os.environ['SQLITE_TMPDIR'] = str(work)
    db.execute('PRAGMA cache_size=-8192')
    db.execute('PRAGMA temp_store=FILE')
    db.execute('PRAGMA journal_mode=DELETE')
    db.create_aggregate('exact_sum', 1, ExactSum)
    db.set_progress_handler(lambda: 1 if time.perf_counter() - started > 840 else 0, 10000)
    phases = {}
    counts = {}
    try:
        for table, path in [('l', left)] + ([('r', right)] if operation == 'join' else []):
            if path is None:
                raise Failure('missing_input')
            db.execute('CREATE TABLE ' + table + ' (seq INTEGER PRIMARY KEY,k TEXT,g TEXT,a TEXT,p TEXT)')
            count = 0
            for row in rows(path, max_input, max_rows):
                count += 1
                if operation == 'aggregate':
                    scaled(row[2])
                db.execute('INSERT INTO ' + table + ' VALUES (?,?,?,?,?)', [count] + row)
            db.commit()
            counts[table] = count
        phases['load_seconds'] = time.perf_counter() - started
        query_started = time.perf_counter()
        if operation == 'dedupe':
            selector = 'MIN' if keep == 'first' else 'MAX'
            query = ('SELECT k,g,a,p FROM l WHERE seq IN '
                     '(SELECT ' + selector + '(seq) FROM l GROUP BY k,g) ORDER BY seq')
            header = HEADER
        elif operation == 'join':
            db.execute('CREATE INDEX rk ON r(k,g,seq)')
            query = ('SELECT l.k,l.g,l.a,l.p,r.a,r.p FROM l '
                     'JOIN r ON l.k=r.k AND l.g=r.g ORDER BY l.seq,r.seq')
            header = HEADER + ['right_amount', 'right_payload']
        else:
            if db.execute('SELECT COUNT(*) FROM (SELECT g FROM l GROUP BY g)').fetchone()[0] > max_groups:
                raise Failure('group_limit')
            query = 'SELECT g,CAST(COUNT(*) AS TEXT),exact_sum(a) FROM l GROUP BY g ORDER BY MIN(seq)'
            header = ['group', 'count', 'sum']
        output = work / 'result.csv.gz.partial'
        logical = hashlib.sha256()
        logical_bytes = 0
        output_rows = 0
        compression_seconds = 0.0
        scratch_peak = 0
        with output.open('xb') as raw:
            encoder = gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=level, mtime=0)

            def emit(row):
                nonlocal logical_bytes, compression_seconds, scratch_peak
                buf = io.StringIO(newline='')
                csv.writer(buf, lineterminator='\n').writerow(row)
                data = buf.getvalue().encode('utf-8')
                if logical_bytes + len(data) > max_output:
                    raise Failure('output_limit')
                logical_bytes += len(data)
                logical.update(data)
                t = time.perf_counter()
                encoder.write(data)
                compression_seconds += time.perf_counter() - t
                if raw.tell() > max_encoded:
                    raise Failure('encoded_limit')

            emit(header)
            for row in db.execute(query):
                if output_rows >= (max_pairs if operation == 'join' else max_rows):
                    raise Failure('pair_limit' if operation == 'join' else 'row_limit')
                output_rows += 1
                emit(row)
                if output_rows % 4096 == 0:
                    scratch_peak = max(scratch_peak, sum(p.stat().st_size for p in work.iterdir() if p.is_file()))
                    if scratch_peak > 8 << 30:
                        raise Failure('scratch_limit')
            encoder.close()
            raw.flush()
            os.fsync(raw.fileno())
        if output.stat().st_size > max_encoded:
            raise Failure('encoded_limit')
        phases['query_serialize_compress_seconds'] = time.perf_counter() - query_started
        phases['encoder_write_seconds_included_above'] = compression_seconds
        verify_started = time.perf_counter()
        check = hashlib.sha256()
        verified = 0
        with gzip.open(output, 'rb') as source:
            while True:
                block = source.read(65536)
                if not block:
                    break
                verified += len(block)
                if verified > max_output:
                    raise Failure('verification_limit')
                check.update(block)
                if time.perf_counter() - verify_started > 60:
                    raise Failure('verification_timeout')
        if verified != logical_bytes or check.hexdigest() != logical.hexdigest():
            raise Failure('verification_failed')
        phases['verification_seconds'] = time.perf_counter() - verify_started
        output = output.rename(work / 'result.csv.gz')
        db.close()
        scratch_peak = max(scratch_peak, sum(p.stat().st_size for p in work.iterdir() if p.is_file()))
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {'status': 'ok', 'operation': operation, 'keep': keep,
                'input_rows': counts, 'output_rows': output_rows,
                'input_bytes': sum(Path(p).stat().st_size for p in [left, right] if p),
                'logical_bytes': logical_bytes, 'encoded_bytes': output.stat().st_size,
                'logical_sha256': logical.hexdigest(), 'encoded_sha256': digest(output),
                'worker_wall_seconds': time.perf_counter() - started,
                'worker_cpu_seconds': time.process_time() - cpu_started,
                'peak_rss_bytes': rss if sys.platform == 'darwin' else rss * 1024,
                'sampled_peak_scratch_bytes': scratch_peak,
                'scratch_measurement': 'file samples; excludes unlinked SQLite temp files; not a hard cap',
                'phases': phases, 'python': platform.python_version(),
                'architecture': platform.machine(), 'sqlite': sqlite3.sqlite_version,
                'zlib': zlib.ZLIB_RUNTIME_VERSION,
                'worker_sha256': digest(__file__), 'gzip_level': level,
                'scope': 'local worker only; no AWS billing, S3 persistence or customer acknowledgment measured'}
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--operation', required=True, choices=['dedupe', 'join', 'aggregate'])
    parser.add_argument('--left', required=True)
    parser.add_argument('--right')
    parser.add_argument('--work', required=True)
    parser.add_argument('--keep', default='first', choices=['first', 'last'])
    parser.add_argument('--max-input', type=int, default=1 << 30)
    parser.add_argument('--max-output', type=int, default=1 << 30)
    parser.add_argument('--max-encoded', type=int, default=1 << 30)
    args = vars(parser.parse_args())
    try:
        print(json.dumps(execute(**{k.replace('-', '_'): v for k, v in args.items()}), sort_keys=True))
    except (Failure, csv.Error, UnicodeError, sqlite3.Error) as error:
        # Never log parser/SQL exception strings, which may include content.
        print(json.dumps({'status': 'failed', 'code': str(error) if isinstance(error, Failure) else 'processing_failed'}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
