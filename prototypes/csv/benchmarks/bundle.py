#!/usr/bin/env python3
"""Build deterministic, dependency-free trial code artifacts. No AWS calls."""
import argparse
import base64
import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

NAME = 'utils_bot_csv_trial'
VERSION = '0.1.0'
SCRIPT = """from utils_bot_csv_trial.cloud_smoke import main
if __name__ == '__main__':
    raise SystemExit(main(['--provider', 'glue', '--work-root', '/tmp']))
"""


def build(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError('bundle directory must be empty')
    source = Path(__file__).resolve().parent
    files = {NAME + '/__init__.py': b'"""Synthetic CSV backend diagnostic only."""\n'}
    for name in ('worker.py', 'fixtures.py', 'cloud_smoke.py'):
        files[NAME + '/' + name] = (source / name).read_bytes()
    dist = NAME + '-' + VERSION + '.dist-info/'
    files[dist + 'METADATA'] = ('Metadata-Version: 2.1\nName: ' + NAME +
                              '\nVersion: ' + VERSION + '\nRequires-Python: >=3.9\n').encode()
    files[dist + 'WHEEL'] = b'Wheel-Version: 1.0\nGenerator: utils.bot\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
    files[dist + 'top_level.txt'] = (NAME + '\n').encode()
    record = io.StringIO(newline='')
    writer = csv.writer(record, lineterminator='\n')
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
        writer.writerow([name, 'sha256=' + digest, str(len(data))])
    writer.writerow([dist + 'RECORD', '', ''])
    files[dist + 'RECORD'] = record.getvalue().encode()
    wheel = directory / (NAME + '-' + VERSION + '-py3-none-any.whl')
    with zipfile.ZipFile(wheel, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(2026, 10, 21, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100444 << 16
            archive.writestr(entry, data)
    script = directory / 'glue_smoke.py'
    script.write_text(SCRIPT)
    result = {p.name: {'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
              for p in (wheel, script)}
    return {'schema_version': 1, 'synthetic_only': True, 'artifacts': result,
            'scope': 'code artifacts only; no cloud deployment or execution'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True)
    print(json.dumps(build(parser.parse_args().directory), sort_keys=True))
