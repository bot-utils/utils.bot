"""Validate explicit version-bound vendor classifications, never generic waivers."""
from datetime import date
import re


def vendor_reviewed(item, reviews, today=None):
    today = today or date.today()
    matches = [row for row in reviews if (row.get('package'), row.get('cve')) == (item['package'], item['cve'])]
    if len(matches) != 1:
        return False
    row = matches[0]
    # Deliberately limited to the four individually examined reports. Adding a
    # URL or a reason to a new scan finding cannot make it pass this gate.
    identities = {
        ('libc6', 'CVE-2019-1010022'): ('2.43-7', 'https://security-tracker.debian.org/tracker/CVE-2019-1010022'),
        ('libc6', 'CVE-2019-1010024'): ('2.43-7', 'https://security-tracker.debian.org/tracker/CVE-2019-1010024'),
        ('libc6', 'CVE-2019-1010025'): ('2.43-7', 'https://security-tracker.debian.org/tracker/CVE-2019-1010025'),
        ('libsqlite3-0', 'CVE-2021-45346'): ('3.53.4-2', 'https://www.sqlite.org/cves.html'),
    }
    expected = identities.get((item['package'], item['cve']))
    if not expected or (item.get('version'), row.get('source')) != expected or row.get('version') != item.get('version'):
        return False
    if row.get('decision') != 'vendor_disputed' or not re.fullmatch('[a-f0-9]{64}', row.get('evidenceSHA256', '')):
        return False
    if not row.get('analysis') or not row.get('limitations'):
        return False
    try:
        start, end = date.fromisoformat(row['reviewedOn']), date.fromisoformat(row['reviewUntil'])
        return start <= today <= end and 0 < (end - start).days <= 30
    except (KeyError, TypeError, ValueError):
        return False
