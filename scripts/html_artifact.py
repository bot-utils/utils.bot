"""Bind a MicroVM source asset to the exact locally inspected filesystem.

AWS only unpacks this filesystem; it does not repeat mutable package downloads.
The release receipt is a local deployment guard, not a third-party attestation.
"""
import hashlib
import json
from pathlib import Path
import urllib.request

from check_html_scan import evaluate

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = '''FROM scratch
ADD runtime.tar /
ENV HOME=/tmp LANG=C.UTF-8
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/opt/utils/bootstrap"]
'''
STABLE_URL = 'https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json'


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def current_browser():
    with urllib.request.urlopen(STABLE_URL, timeout=15) as response:
        data = response.read((1 << 20) + 1)
    if len(data) > 1 << 20:
        raise ValueError('Browser release manifest exceeds bound')
    return json.loads(data)['channels']['Stable']['version']


def source_digest(root=ROOT):
    """Catch edits after scanning, including local native patches and Go sources."""
    root = Path(root)
    paths = [root / 'Dockerfile.browser', root / 'go.mod', root / 'go.sum']
    if (root / 'Dockerfile.browser.dockerignore').is_file():
        paths.append(root / 'Dockerfile.browser.dockerignore')
    for directory, pattern in [('native', '*'), ('cmd', '*.go'), ('internal', '*.go'), ('scripts', '*.py')]:
        paths.extend(p for p in (root / directory).rglob(pattern) if p.is_file() and '__pycache__' not in p.parts)
    paths.extend((root / 'scripts').rglob('*.sh'))
    h = hashlib.sha256()
    for path in sorted(set(paths)):
        h.update(str(path.relative_to(root)).encode() + b'\0' + bytes.fromhex(digest(path)))
    return h.hexdigest()


def validate_build(root=ROOT):
    root = Path(root)
    record = json.loads((root / 'build/html-microvm/build.json').read_text())
    if record.get('sourceSHA256') != source_digest(root) or record.get('bootstrapSHA256') != digest(root / 'build/html-microvm/bootstrap'):
        raise ValueError('Rebuild HTML worker after source changes')


def validate(area, *, stable_version=None, root=ROOT):
    area, root = Path(area), Path(root)
    receipt = json.loads((area / 'release.json').read_text())
    if receipt.get('schema') != 1 or receipt.get('releaseReady') is not True:
        raise ValueError('HTML filesystem has not passed its release scan')
    if (area / 'Dockerfile').read_text() != DOCKERFILE:
        raise ValueError('AWS build must only unpack the reviewed filesystem')
    if receipt.get('sourceSHA256') != source_digest(root):
        raise ValueError('Source changed since HTML runtime review')
    validate_build(root)
    for field, file in [('rootfsSHA256', area / 'runtime.tar'),
                        ('scanSHA256', area / 'runtime-scan.json'),
                        ('policySHA256', root / 'native/browser-advisories.json'),
                        ('bootstrapSHA256', root / 'build/html-microvm/bootstrap'),
                        ('buildInputsSHA256', root / 'Dockerfile.browser'),
                        ('aptSourcesSHA256', root / 'native/browser-apt.sources'),
                        ('nativeSourcesSHA256', root / 'native/browser-libraries.json')]:
        if receipt.get(field) != digest(file):
            raise ValueError('HTML release input changed: ' + field)
    scan = json.loads((area / 'runtime-scan.json').read_text())
    if receipt['runtime'].get('bootstrap_sha256') != receipt['bootstrapSHA256']:
        raise ValueError('Scanned worker does not match the built bootstrap')
    policy = json.loads((root / 'native/browser-advisories.json').read_text())
    reviews = json.loads((root / 'native/browser-vendor-reviews.json').read_text())['reviews']
    risks = json.loads((root / 'native/browser-risk-acceptances.json').read_text())['reviews']
    if not evaluate(scan, receipt['runtime'], policy, reviews, risks, root=root)['passed']:
        raise ValueError('HTML native scan blocks release')
    stable = stable_version if stable_version is not None else current_browser()
    if receipt.get('browserVersion') != stable or receipt['runtime'].get('browser_version') != stable:
        raise ValueError('Browser update review required before release')
    return receipt
