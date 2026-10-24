from datetime import date, timedelta
import json
from pathlib import Path
import unittest

from html_vendor_review import vendor_reviewed


class VendorReviewTests(unittest.TestCase):
    def setUp(self):
        self.today = date.today()
        identities = [('libc6', 'CVE-2019-1010022', '2.43-7'),
                      ('libc6', 'CVE-2019-1010024', '2.43-7'),
                      ('libc6', 'CVE-2019-1010025', '2.43-7'),
                      ('libsqlite3-0', 'CVE-2021-45346', '3.53.4-2')]
        self.reviews = [dict(package=package, cve=cve, version=version,
            decision='vendor_disputed', evidenceSHA256='1' * 64,
            source=('https://www.sqlite.org/cves.html' if package == 'libsqlite3-0'
                    else 'https://security-tracker.debian.org/tracker/' + cve),
            reviewedOn=self.today.isoformat(),
            reviewUntil=(self.today + timedelta(days=30)).isoformat(),
            analysis='synthetic test fixture', limitations='synthetic test case')
            for package, cve, version in identities]
        self.row = self.reviews[0]
        self.item = {key: self.row[key] for key in ('package', 'cve', 'version')}

    def check(self):
        return vendor_reviewed(self.item, self.reviews, self.today)

    def test_each_explicit_upstream_classification(self):
        for row in self.reviews:
            self.assertTrue(vendor_reviewed(row, self.reviews, self.today))

    def test_unreviewed_cve_is_never_accepted(self):
        self.item['cve'] = 'CVE-new'
        self.assertFalse(self.check())

    def test_changed_version_is_rejected(self):
        self.item['version'] = 'unreviewed'
        self.assertFalse(self.check())

    def test_label_url_and_reason_are_insufficient(self):
        self.row.clear()
        self.row.update(self.item, source='https://example.test', reason='vendor dispute')
        self.assertFalse(self.check())

    def test_expired_review_blocks(self):
        self.today += timedelta(days=31)
        self.assertFalse(self.check())

    def test_future_review_blocks(self):
        self.today -= timedelta(days=1)
        self.assertFalse(self.check())

    def test_duplicate_review_blocks(self):
        self.reviews.append(dict(self.row))
        self.assertFalse(self.check())

    def test_unbounded_review_blocks(self):
        self.row['reviewUntil'] = (self.today + timedelta(days=365)).isoformat()
        self.assertFalse(self.check())

    def test_missing_evidence_blocks(self):
        self.row.pop('evidenceSHA256')
        self.assertFalse(self.check())

    def test_missing_risk_limitations_blocks(self):
        self.row.pop('limitations')
        self.assertFalse(self.check())


if __name__ == '__main__':
    unittest.main()
