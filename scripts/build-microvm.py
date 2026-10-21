#!/usr/bin/env python3
"""Package a frozen runtime; production requires an exact fresh scan.

Set HTML_RUNTIME_SCAN to a scan of HTML_RUNTIME_IMAGE. Without a scan the asset
is usable only by the private mock-payment integration stack.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from check_html_image import inspect
from check_html_scan import evaluate
from html_artifact import DOCKERFILE, ROOT, digest, source_digest, validate, validate_build


def main():
    target = ROOT / 'build/html-microvm-image'
    target.mkdir(parents=True, exist_ok=True)
    # Invalidate old approval before any operation that might fail.
    (target / 'release.json').write_text('{"releaseReady":false}\n')
    validate_build()
    tag = os.environ.get('HTML_RUNTIME_IMAGE', 'utils-bot-html-runtime:local')
    if not os.environ.get('HTML_RUNTIME_IMAGE'):
        subprocess.run(['docker', 'build', '--provenance=false', '--platform', 'linux/arm64',
                        '-f', 'Dockerfile.browser', '--target', 'microvm', '-t', tag, '.'],
                       cwd=ROOT, check=True)
    # Resolve once; retagging cannot alter inspected/exported image bytes.
    image = subprocess.check_output(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}'], text=True).strip()
    # Native compilation can take minutes. Reject source edits during that
    # interval even when this asset is intended only for private integration.
    validate_build()
    runtime = inspect(image)
    if runtime['bootstrap_sha256'] != digest(ROOT / 'build/html-microvm/bootstrap'):
        raise SystemExit('Runtime contains a different worker; rebuild before staging')
    name = 'utils-html-inspect-' + hashlib.sha256(image.encode()).hexdigest()[:12]
    subprocess.run(['docker', 'export', '--output', str(target / 'runtime.tar'), name], check=True)
    (target / 'Dockerfile').write_text(DOCKERFILE)
    (target / '.dockerignore').write_text('**\n!Dockerfile\n!runtime.tar\n')
    scan_path = os.environ.get('HTML_RUNTIME_SCAN')
    if not scan_path:
        print('Frozen runtime staged for private tests; production release remains blocked.')
        return
    scan_bytes = Path(scan_path).read_bytes()
    scan = json.loads(scan_bytes)
    policy_path = ROOT / 'native/browser-advisories.json'
    reviews = json.loads((ROOT / 'native/browser-vendor-reviews.json').read_text())['reviews']
    risks = json.loads((ROOT / 'native/browser-risk-acceptances.json').read_text())['reviews']
    outcome = evaluate(scan, runtime, json.loads(policy_path.read_text()), reviews, risks)
    if not outcome['passed']:
        raise SystemExit('HTML native scan blocks production release: ' + str(len(outcome['blocking_findings'])) + ' findings')
    (target / 'runtime-scan.json').write_bytes(scan_bytes)
    runtime['files'] = sorted(runtime['files'])
    receipt = {'schema': 1, 'releaseReady': True, 'runtime': runtime,
               'scanOutcome': outcome,
               'sourceSHA256': source_digest(),
               'browserVersion': runtime['browser_version'],
               'rootfsSHA256': digest(target / 'runtime.tar'),
               'scanSHA256': digest(target / 'runtime-scan.json'),
               'policySHA256': digest(policy_path),
               'bootstrapSHA256': digest(ROOT / 'build/html-microvm/bootstrap'),
               'buildInputsSHA256': digest(ROOT / 'Dockerfile.browser'),
               'aptSourcesSHA256': digest(ROOT / 'native/browser-apt.sources'),
               'nativeSourcesSHA256': digest(ROOT / 'native/browser-libraries.json')}
    (target / 'release.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
    try:
        validate(target)
    except Exception:
        (target / 'release.json').write_text('{"releaseReady":false}\n')
        raise
    print('Reviewed frozen runtime staged; fresh scan and stable browser verified.')


if __name__ == '__main__':
    main()
