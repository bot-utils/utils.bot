from datetime import date, datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from html_risk_review import BROWSER, CONTROL_FILES, IDENTITIES, controls_digest, risk_accepted
from check_html_scan import evaluate

ROOT = Path(__file__).resolve().parent.parent


class RiskAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.reviews = json.loads((ROOT / 'native/browser-risk-acceptances.json').read_text())['reviews']
        self.row = self.reviews[0]
        self.item = dict(self.row, status='risk_accepted')
        self.today = date(2026, 10, 20)

    def check(self):
        return risk_accepted(self.item, self.reviews, today=self.today)

    def test_all_five_are_explicit_unpatched_risks(self):
        self.assertEqual({(r['package'], r['cve']) for r in self.reviews}, set(IDENTITIES))
        for row in self.reviews:
            self.assertTrue(risk_accepted(dict(row, status='risk_accepted'), self.reviews, today=self.today))
            self.assertIn('unpatched', row['limitations'])

    def test_new_cve_or_package_is_not_accepted(self):
        for field in ('cve', 'package'):
            other = dict(self.item, **{field: 'unreviewed'})
            self.assertFalse(risk_accepted(other, [dict(other, decision='risk_accepted')], today=self.today))

    def test_changed_version_is_not_accepted(self):
        self.item['version'] = 'new-version'
        self.row['version'] = 'new-version'
        self.assertFalse(self.check())

    def test_browser_update_needs_new_review(self):
        self.row['browserVersion'] = 'other-browser'
        self.assertFalse(self.check())

    def test_containment_does_not_mean_fixed_or_absent(self):
        for status in ('fixed', 'component_absent', 'unfixed', 'bounded', 'vendor_disputed'):
            self.item['status'] = status
            self.assertFalse(self.check())

    def test_expired_future_and_unbounded_review(self):
        for today in (date(2026, 10, 19), date(2026, 11, 20)):
            self.assertFalse(risk_accepted(self.item, self.reviews, today=today))
        self.row['reviewUntil'] = '2030-01-01'
        self.assertFalse(self.check())

    def test_missing_evidence_risk_or_authorization(self):
        original = dict(self.row)
        for field in ('authorization', 'evidenceSHA256', 'analysis', 'limitations', 'residualRisk', 'source'):
            self.row.clear()
            self.row.update(original)
            self.row.pop(field)
            self.assertFalse(self.check(), field)

    def test_duplicate_or_renamed_decision(self):
        self.reviews.append(dict(self.row))
        self.assertFalse(self.check())
        self.reviews.pop()
        self.row['decision'] = 'patched'
        self.assertFalse(self.check())

    def test_confinement_edits_or_missing_files_invalidate_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in CONTROL_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            self.assertEqual(controls_digest(root), controls_digest())
            self.assertTrue(risk_accepted(self.item, self.reviews, root=root, today=self.today))
            target = root / 'native/browser-launch.c'
            target.write_bytes(target.read_bytes() + b'\n// changed confinement\n')
            self.assertFalse(risk_accepted(self.item, self.reviews, root=root, today=self.today))
        self.assertFalse(risk_accepted(self.item, self.reviews, root=root, today=self.today))

    def test_gate_counts_risk_separately_and_requires_explicit_record(self):
        # Fresh production-shaped data, with only one of the reviewed findings.
        runtime = {'image_id': 'sha256:test', 'files': [], 'browser_version': BROWSER,
                   'versions': {self.item['package']: self.item['version']}}
        scan = {'Metadata': {'ImageID': 'sha256:test'}, 'CreatedAt': datetime.now(timezone.utc).isoformat(),
                'Results': [{'Class': 'os-pkgs',
                             'Packages': [{'Name': self.item['package'], 'Version': self.item['version']}],
                             'Vulnerabilities': [{'PkgName': self.item['package'], 'VulnerabilityID': self.item['cve'],
                                                  'InstalledVersion': self.item['version']}]}]}
        policy = {'findings': [self.item]}
        outcome = evaluate(scan, runtime, policy, risk_reviews=self.reviews)
        self.assertTrue(outcome['passed'])
        self.assertEqual(outcome['accepted_risk_records'], 1)
        self.assertEqual(outcome['fixed_matching_records'], 0)
        self.assertEqual(outcome['vendor_disputed_records'], 0)
        self.assertFalse(evaluate(scan, runtime, policy)['passed'])
        runtime['browser_version'] = 'other-browser'
        self.assertFalse(evaluate(scan, runtime, policy, risk_reviews=self.reviews)['passed'])


if __name__ == '__main__':
    unittest.main()
