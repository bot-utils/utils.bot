"""Narrow, expiring owner acceptance of five unpatched resource-exhaustion risks.

This is not a patch, vendor dispute or proof of unreachable code. A changed
version, browser or confinement implementation requires a fresh decision.
"""
from datetime import date
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
BROWSER = '156.0.8078.47'
IDENTITIES = {
    ('libc6', 'CVE-2010-4756'): '2.43-7',
    ('libc6', 'CVE-2018-20796'): '2.43-7',
    ('libc6', 'CVE-2019-9192'): '2.43-7',
    ('libglib2.0-0t64', 'CVE-2012-0039'): '2.84.4-3~deb13u5+utils1',
    ('libexpat1', 'CVE-2025-66382'): '2.9.0-1~deb13u1',
}
# Hash the actual confinement, limits, egress validation and VM lifecycle code,
# not just a list of mitigation names. The frozen image receipt separately
# binds all source inputs, library bytes and the built worker to its fresh scan.
CONTROL_FILES = (
    'Dockerfile.browser', 'native/browser-launch.c',
    'native/browser-runtime.py', 'native/browser-libraries.json',
    'cmd/html-microvm/main.go', 'internal/browser/pipe.go',
    'internal/browser/parent_linux.go', 'internal/browser/render.go',
    'internal/browser/warm.go', 'internal/browser/check.go',
    'internal/jsonwire/json.go', 'internal/htmltool/controller.go',
    'internal/htmltool/response.go',
    'internal/htmllimits/limits.go', 'internal/htmlrender/browser.go',
    'internal/htmlrender/fetch.go', 'internal/htmlrender/url.go',
    'internal/htmlrender/vm.go', 'internal/htmlrender/worker.go',
    'internal/htmlrender/result.go', 'internal/microvm/runner.go',
    'infra/html.go', 'infra/microvm.go',
)


def controls_digest(root=ROOT):
    h = hashlib.sha256()
    for name in CONTROL_FILES:
        h.update(name.encode() + b'\0' + hashlib.sha256((Path(root) / name).read_bytes()).digest())
    return h.hexdigest()


def risk_accepted(item, reviews, *, root=ROOT, today=None):
    today = today or date.today()
    identity = item.get('package'), item.get('cve')
    if item.get('status') != 'risk_accepted' or item.get('version') != IDENTITIES.get(identity):
        return False
    # Unknown identities never pass, even if a record is copied from another CVE.
    if identity not in IDENTITIES:
        return False
    matches = [row for row in reviews if (row.get('package'), row.get('cve')) == identity]
    if len(matches) != 1:
        return False
    row = matches[0]
    if row.get('decision') != 'risk_accepted' or row.get('version') != item['version'] or row.get('browserVersion') != BROWSER:
        return False
    if row.get('source') != 'https://security-tracker.debian.org/tracker/' + identity[1]:
        return False
    if not re.fullmatch('[a-f0-9]{64}', row.get('evidenceSHA256', '')):
        return False
    if any(not isinstance(row.get(field), str) or not row[field].strip()
           for field in ('authorization', 'analysis', 'limitations', 'residualRisk')):
        return False
    try:
        start, end = date.fromisoformat(row['reviewedOn']), date.fromisoformat(row['reviewUntil'])
        return (start <= today <= end and 0 < (end - start).days <= 30
                and row.get('controlsSHA256') == controls_digest(root))
    except (KeyError, TypeError, ValueError, OSError):
        return False
