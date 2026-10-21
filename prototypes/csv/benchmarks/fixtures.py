#!/usr/bin/env python3
"""Deterministic synthetic-only fixtures and an independent in-memory oracle."""
import argparse
import csv
import hashlib
import io
import json
from collections import OrderedDict
from decimal import Decimal, localcontext
from pathlib import Path

HEADER = ['key', 'group', 'amount', 'payload']


def encode(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def reference(operation, left, right=(), keep='first'):
    if operation == 'dedupe':
        selected = {}
        for i, row in enumerate(left):
            key = tuple(row[:2])
            if key not in selected or keep == 'last':
                selected[key] = i
        return encode(HEADER, [row for i, row in enumerate(left) if selected[tuple(row[:2])] == i])
    if operation == 'join':
        # Deliberately nested, independent of the SQL join implementation.
        return encode(HEADER + ['right_amount', 'right_payload'],
                      [a + b[2:] for a in left for b in right if a[:2] == b[:2]])
    groups = OrderedDict()
    with localcontext() as context:
        context.prec = 80
        for row in left:
            count, total = groups.get(row[1], (0, Decimal(0)))
            groups[row[1]] = (count + 1, total + Decimal(row[2]))
        def number(n):
            if n == 0:
                return '0'
            value = format(n, 'f')
            return value.rstrip('0').rstrip('.') if '.' in value else value
        return encode(['group', 'count', 'sum'],
                      [[g, str(n), number(s)] for g, (n, s) in groups.items()])


def generate(directory, mib=128, join_stride=2):
    """Two raw CSV inputs, each no larger than mib MiB (whole rows only).

    Left: two rows per composite key; right: one, with 1/join_stride matching keys.
    Join emits exactly one pair per left row of the matching keys. Both inputs
    alternate compressible payloads and seeded SHAKE hex payloads.
    """
    directory = Path(directory)
    if join_stride not in (2, 4):
        raise ValueError('join_stride must be 2 or 4')
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError('fixture directory must be empty')
    count = 0
    size = 0
    with (directory / 'left.csv').open('wb') as out:
        header = encode(HEADER, [])
        out.write(header)
        size += len(header)
        while size < mib * 2**20:
            key = count // 2
            payload = ('repeat,' * 128 if count % 2 == 0 else
                       hashlib.shake_256(('utils-bot-20261021-' + str(count)).encode()).hexdigest(512))
            row = [str(key), 'g' + str(key % 97), ('-' if count % 3 == 0 else '') + '123.000000000000000001', payload]
            data = encode(HEADER, [row])[len(header):]
            if size + len(data) > mib * 2**20:
                break
            out.write(data)
            size += len(data)
            count += 1
    right_count = 0
    size = 0
    with (directory / 'right.csv').open('wb') as out:
        out.write(header)
        size += len(header)
        while size < mib * 2**20:
            key = right_count * join_stride
            payload = hashlib.shake_256(('utils-bot-right-' + str(right_count)).encode()).hexdigest(512)
            row = [str(key), 'g' + str(key % 97), '7.5', payload]
            data = encode(HEADER, [row])[len(header):]
            if size + len(data) > mib * 2**20:
                break
            out.write(data)
            size += len(data)
            right_count += 1
    unique_left = (count + 1) // 2
    matched_keys = min(right_count, (unique_left + join_stride - 1) // join_stride)
    join_rows = sum(min(2, count - 2*join_stride*i) for i in range(matched_keys))
    # Independent planted-data oracle: no SQLite, joins or dedupe engine reused.
    expected = {op: hashlib.sha256(encode(header_names, [])) for op, header_names in [
        ('dedupe', HEADER), ('join', HEADER + ['right_amount', 'right_payload'])]}
    groups = OrderedDict()
    with localcontext() as context:
        context.prec = 80
        with (directory / 'left.csv').open(encoding='utf-8', newline='') as source:
            reader = csv.reader(source)
            next(reader)
            for index, row in enumerate(reader):
                if index % 2 == 0:
                    expected['dedupe'].update(encode(HEADER, [row])[len(header):])
                key = index // 2
                if key % join_stride == 0 and key // join_stride < right_count:
                    payload = hashlib.shake_256(('utils-bot-right-' + str(key // join_stride)).encode()).hexdigest(512)
                    joined = row + ['7.5', payload]
                    join_header = HEADER + ['right_amount', 'right_payload']
                    expected['join'].update(encode(join_header, [joined])[len(encode(join_header, [])):])
                n, total = groups.get(row[1], (0, Decimal(0)))
                groups[row[1]] = (n + 1, total + Decimal(row[2]))
        agg_rows = []
        for g, (n, total) in groups.items():
            text = format(total, 'f')
            text = text.rstrip('0').rstrip('.') if '.' in text else text
            agg_rows.append([g, str(n), '0' if total == 0 else text])
        expected['aggregate'] = hashlib.sha256(encode(['group', 'count', 'sum'], agg_rows))
    files = {}
    for name in ('left.csv', 'right.csv'):
        h = hashlib.sha256()
        with (directory / name).open('rb') as source:
            for block in iter(lambda: source.read(65536), b''):
                h.update(block)
        files[name] = {'bytes': (directory / name).stat().st_size, 'sha256': h.hexdigest()}
    result = {'fixture_version': 2, 'synthetic': True, 'seed': 'utils-bot-20261021', 'requested_mib_per_file': mib,
              'join_stride': join_stride,
              'files': files, 'left_rows': count, 'right_rows': right_count,
              'expected_dedupe_rows': unique_left, 'expected_join_rows': join_rows,
              'expected_aggregate_groups': min(97, unique_left),
              'expected_logical_sha256': {op: h.hexdigest() for op, h in expected.items()},
              'payloads': 'left alternating repeated text/SHAKE hex; right SHAKE hex'}
    (directory / 'manifest.json').write_text(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', required=True)
    parser.add_argument('--mib', type=int, default=128, choices=[1, 16, 128, 1024])
    parser.add_argument('--join-stride', type=int, default=2, choices=[2, 4])
    args = parser.parse_args()
    print(json.dumps(generate(args.directory, args.mib, args.join_stride), sort_keys=True))
