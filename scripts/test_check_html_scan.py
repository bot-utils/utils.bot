import unittest
from datetime import datetime, timezone, timedelta

from check_html_scan import evaluate


class ScanGateTests(unittest.TestCase):
    def setUp(self):
        self.runtime = {'image_id': 'sha256:test', 'files': {'usr/lib/libx.so'},
                        'versions': {'libx': '2+patched'}}
        self.scan = {'Metadata': {'ImageID': 'sha256:test'},
                     'CreatedAt': datetime.now(timezone.utc).isoformat(), 'Results': [{
            'Class': 'os-pkgs', 'Packages': [{'Name': 'libx', 'Version': '2+patched'}],
            'Vulnerabilities': [{'PkgName': 'libx', 'VulnerabilityID': 'CVE-test',
                                 'InstalledVersion': '2+patched'}]}]}
        self.policy = {'findings': [{'package': 'libx', 'cve': 'CVE-test',
                                    'status': 'fixed', 'version': '2+patched'}]}

    def test_exact_patched_version_and_image(self):
        self.assertTrue(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_scan_of_another_image_rejected(self):
        self.scan['Metadata']['ImageID'] = 'sha256:other'
        with self.assertRaises(ValueError):
            evaluate(self.scan, self.runtime, self.policy)

    def test_containerd_config_identity_requires_exact_ordered_layers(self):
        self.runtime.update(image_config_id='sha256:config', layer_ids=['sha256:layer1', 'sha256:layer2'])
        self.scan['Metadata'].update(ImageID='sha256:config', DiffIDs=['sha256:layer1', 'sha256:layer2'])
        self.assertTrue(evaluate(self.scan, self.runtime, self.policy)['passed'])
        self.scan['Metadata']['DiffIDs'].reverse()
        with self.assertRaises(ValueError): evaluate(self.scan, self.runtime, self.policy)

    def test_config_alias_without_layer_proof_is_rejected(self):
        self.runtime['image_config_id'] = 'sha256:config'
        self.scan['Metadata']['ImageID'] = 'sha256:config'
        with self.assertRaises(ValueError): evaluate(self.scan, self.runtime, self.policy)

    def test_wrong_config_cannot_match_even_with_same_layers(self):
        self.runtime.update(image_config_id='sha256:config', layer_ids=['sha256:layer'])
        self.scan['Metadata'].update(ImageID='sha256:other', DiffIDs=['sha256:layer'])
        with self.assertRaises(ValueError): evaluate(self.scan, self.runtime, self.policy)

    def test_new_cve_is_not_silently_accepted(self):
        self.scan['Results'][0]['Vulnerabilities'][0]['VulnerabilityID'] = 'CVE-new'
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_changed_package_version_is_not_waived(self):
        self.runtime['versions']['libx'] = '3'
        self.scan['Results'][0]['Packages'][0]['Version'] = '3'
        self.scan['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = '3'
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_affected_component_reintroduction_blocks_release(self):
        entry = self.policy['findings'][0]
        entry.update(status='component_absent', forbidden=['nsenter'])
        self.assertTrue(evaluate(self.scan, self.runtime, self.policy)['passed'])
        self.runtime['files'].add('usr/bin/nsenter')
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_unfixed_does_not_become_fixed_because_isolated(self):
        self.policy['findings'][0].update(status='unfixed', note='one job per VM')
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_missing_dynamic_imports_do_not_waive_finding(self):
        self.policy['findings'][0].update(status='code_path_absent', forbidden_symbols=['regexec'])
        # An absent dynamic import cannot establish the full native call graph.
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])
        self.runtime['imports'] = set()
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_vendor_dispute_does_not_automatically_waive_finding(self):
        self.policy['findings'][0].update(status='reviewed_not_security', source='https://example.test/advisory', reason='Vendor classifies this as not a security issue.')
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])
        self.policy['findings'][0].pop('reason')
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_containment_labels_do_not_waive_unfixed_finding(self):
        self.policy['findings'][0].update(status='bounded', control='isolated_worker_deadline', reason='A bounded disposable worker limits this issue to one request.')
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_absent_component_review_is_version_bound(self):
        entry = self.policy['findings'][0]
        entry.update(status='component_absent', forbidden=['nsenter'])
        self.assertTrue(evaluate(self.scan, self.runtime, self.policy)['passed'])
        entry['version'] = 'older-version'
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_empty_component_exclusion_does_not_waive_finding(self):
        entry = self.policy['findings'][0]
        for forbidden in (None, [], [''], 'nsenter'):
            entry.update(status='component_absent', forbidden=forbidden)
            self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_duplicate_policy_does_not_overwrite_unresolved_entry(self):
        self.policy['findings'].insert(0, dict(self.policy['findings'][0], status='unfixed'))
        with self.assertRaises(ValueError):
            evaluate(self.scan, self.runtime, self.policy)

    def test_inventory_disagreement_rejected(self):
        self.scan['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = '1'
        self.assertFalse(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_empty_or_incomplete_scan_rejected(self):
        self.scan['Results'] = []
        with self.assertRaises(ValueError):
            evaluate(self.scan, self.runtime, self.policy)

    def test_stale_scan_rejected(self):
        self.scan['CreatedAt'] = (datetime.now(timezone.utc)-timedelta(days=2)).isoformat()
        with self.assertRaises(ValueError):
            evaluate(self.scan, self.runtime, self.policy)

    def test_trivy_nanosecond_timestamp(self):
        self.scan['CreatedAt'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.123456789Z')
        self.assertTrue(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_package_epoch_is_preserved(self):
        self.scan['Results'][0]['Packages'][0]['Epoch'] = 2
        self.scan['Results'][0]['Packages'][0]['Release'] = '1'
        self.runtime['versions']['libx'] = '2:2+patched-1'
        self.scan['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = '2:2+patched-1'
        self.policy['findings'][0]['version'] = '2:2+patched-1'
        self.assertTrue(evaluate(self.scan, self.runtime, self.policy)['passed'])

    def test_missing_source_identity_cannot_hide_advisories(self):
        self.runtime['sources'] = {'libx': 'upstream-x'}
        with self.assertRaises(ValueError):
            evaluate(self.scan, self.runtime, self.policy)
        self.scan['Results'][0]['Packages'][0]['SrcName'] = 'upstream-x'
        self.assertTrue(evaluate(self.scan, self.runtime, self.policy)['passed'])


if __name__ == '__main__':
    unittest.main()
