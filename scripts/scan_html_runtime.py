#!/usr/bin/env python3
"""Scan an immutable Docker archive, then stage it only if release checks pass.

No Docker socket, AWS credentials, customer traffic or funded payments are
exposed to the scanner. Stopped scanner containers remain available for review.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
SCANNER = 'ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('image', nargs='?', default='utils-bot-html-runtime:local')
    args = parser.parse_args()
    image = subprocess.check_output(['docker', 'image', 'inspect', args.image, '--format', '{{.Id}}'], text=True).strip()
    base = ROOT / 'build/security/html'
    base.mkdir(parents=True, exist_ok=True)
    area = Path(tempfile.mkdtemp(prefix='scan-', dir=base)).resolve()
    cache = (ROOT / 'build/security/trivy-cache').resolve()
    cache.mkdir(parents=True, exist_ok=True)
    subprocess.run(['docker', 'image', 'save', '--output', str(area / 'image.tar'), image], check=True)
    name = 'utils-html-release-scan-' + uuid.uuid4().hex[:16]
    subprocess.run(['docker', 'create', '--name', name, '--network', 'bridge',
                    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '--memory', '2g', '--cpus', '2', '--pids-limit', '256',
                    '--tmpfs', '/tmp:rw,noexec,nosuid,size=1g',
                    '--mount', 'type=bind,src=' + str(area) + ',dst=/scan',
                    '--mount', 'type=bind,src=' + str(cache) + ',dst=/cache',
                    SCANNER, 'image', '--input', '/scan/image.tar', '--scanners', 'vuln',
                    '--list-all-pkgs', '--format', 'json', '--cache-dir', '/cache',
                    '--output', '/scan/runtime-scan.json'], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['docker', 'start', '--attach', name], check=True)
    state = json.loads(subprocess.check_output(['docker', 'inspect', name], text=True))[0]['State']
    if state.get('Running') or state.get('ExitCode') != 0:
        raise SystemExit('HTML runtime scanner failed')
    environment = dict(os.environ, HTML_RUNTIME_IMAGE=image, HTML_RUNTIME_SCAN=str(area / 'runtime-scan.json'))
    subprocess.run(['python3', str(ROOT / 'scripts/build-microvm.py')], cwd=ROOT, env=environment, check=True)


if __name__ == '__main__':
    main()
