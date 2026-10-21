from datetime import date
import json
from pathlib import Path
import unittest

from html_vendor_review import vendor_reviewed


class VendorReviewTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parent.parent
        self.reviews = json.loads((root / 'native/browser-vendor-reviews.json').read_text())['reviews']
        self.row = self.reviews[0]
        self.item = {key: self.row[key] for key in ('package', 'cve', 'version')}
        self.today = date(2026, 10, 20)

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
        self.today = date(2026, 11, 20)
        self.assertFalse(self.check())

    def test_future_review_blocks(self):
        self.today = date(2026, 10, 19)
        self.assertFalse(self.check())

    def test_duplicate_review_blocks(self):
        self.reviews.append(dict(self.row))
        self.assertFalse(self.check())

    def test_unbounded_review_blocks(self):
        self.row['reviewUntil'] = '2030-01-01'
        self.assertFalse(self.check())

    def test_missing_evidence_blocks(self):
        self.row.pop('evidenceSHA256')
        self.assertFalse(self.check())

    def test_missing_risk_limitations_blocks(self):
        self.row.pop('limitations')
        self.assertFalse(self.check())


if __name__ == '__main__':
    unittest.main()
