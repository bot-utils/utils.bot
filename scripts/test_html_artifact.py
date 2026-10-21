import copy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from html_artifact import DOCKERFILE, digest, source_digest, validate, validate_build


class FrozenArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.area = self.root / 'build/html-microvm-image'
        files = {'Dockerfile.browser': 'pinned build recipe', 'go.mod': 'module test', 'go.sum': '',
                 'native/browser-apt.sources': 'dated signed snapshot',
                 'native/browser-libraries.json': '{}',
                 'native/browser-vendor-reviews.json': '{"reviews":[]}',
                 'native/browser-risk-acceptances.json': '{"reviews":[]}',
                 'build/html-microvm/bootstrap': 'test executable',
                 'build/html-microvm-image/Dockerfile': DOCKERFILE,
                 'build/html-microvm-image/runtime.tar': 'test exported filesystem'}
        self.policy = {'findings': [{'package': 'libx', 'cve': 'CVE-test', 'status': 'fixed', 'version': '2'}]}
        files['native/browser-advisories.json'] = json.dumps(self.policy)
        for name, data in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        self.scan = {'CreatedAt': datetime.now(timezone.utc).isoformat(),
                     'Metadata': {'ImageID': 'sha256:test'}, 'Results': [{
                         'Class': 'os-pkgs', 'Packages': [{'Name': 'libx', 'Version': '2'}],
                         'Vulnerabilities': [{'PkgName': 'libx', 'VulnerabilityID': 'CVE-test', 'InstalledVersion': '2'}]}]}
        self.runtime = {'image_id': 'sha256:test', 'versions': {'libx': '2'}, 'files': [],
                        'browser_version': '155.test', 'bootstrap_sha256': digest(self.root / 'build/html-microvm/bootstrap')}
        self.write_receipt()

    def write_receipt(self):
        (self.root / 'build/html-microvm/build.json').write_text(json.dumps({
            'sourceSHA256': source_digest(self.root),
            'bootstrapSHA256': digest(self.root / 'build/html-microvm/bootstrap')}))
        (self.area / 'runtime-scan.json').write_text(json.dumps(self.scan))
        self.receipt = {'schema': 1, 'releaseReady': True, 'runtime': copy.deepcopy(self.runtime),
                        'browserVersion': '155.test', 'sourceSHA256': source_digest(self.root)}
        for field, name in [('rootfsSHA256', self.area / 'runtime.tar'),
                            ('scanSHA256', self.area / 'runtime-scan.json'),
                            ('policySHA256', self.root / 'native/browser-advisories.json'),
                            ('bootstrapSHA256', self.root / 'build/html-microvm/bootstrap'),
                            ('buildInputsSHA256', self.root / 'Dockerfile.browser'),
                            ('aptSourcesSHA256', self.root / 'native/browser-apt.sources'),
                            ('nativeSourcesSHA256', self.root / 'native/browser-libraries.json')]:
            self.receipt[field] = digest(name)
        self.save()

    def save(self):
        (self.area / 'release.json').write_text(json.dumps(self.receipt))

    def check(self):
        return validate(self.area, stable_version='155.test', root=self.root)

    def test_matching_artifact(self):
        self.assertTrue(self.check()['releaseReady'])

    def test_no_approval_for_private_test_asset(self):
        self.receipt = {'releaseReady': False}
        self.save()
        with self.assertRaises(ValueError): self.check()

    def test_modified_rootfs(self):
        (self.area / 'runtime.tar').write_text('different filesystem')
        with self.assertRaises(ValueError): self.check()

    def test_remote_rebuild_cannot_replace_unpack(self):
        (self.area / 'Dockerfile').write_text(DOCKERFILE + 'RUN apt-get update\n')
        with self.assertRaises(ValueError): self.check()

    def test_stale_scan(self):
        self.scan['CreatedAt'] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        self.write_receipt()
        with self.assertRaises(ValueError): self.check()

    def test_scan_of_other_image(self):
        self.scan['Metadata']['ImageID'] = 'sha256:other'
        self.write_receipt()
        with self.assertRaises(ValueError): self.check()

    def test_source_edits_after_review(self):
        (self.root / 'native/new.patch').write_text('changed native source')
        with self.assertRaises(ValueError): self.check()

    def test_policy_edit_after_review(self):
        (self.root / 'native/browser-advisories.json').write_text('{}')
        with self.assertRaises(ValueError): self.check()

    def test_bootstrap_edit_after_review(self):
        (self.root / 'build/html-microvm/bootstrap').write_text('different worker')
        with self.assertRaises(ValueError): self.check()

    def test_scanned_image_contains_other_bootstrap(self):
        self.receipt['runtime']['bootstrap_sha256'] = 'other'
        self.save()
        with self.assertRaises(ValueError): self.check()

    def test_new_browser_requires_review(self):
        with self.assertRaises(ValueError):
            validate(self.area, stable_version='156.test', root=self.root)

    def test_browser_manifest_failure_cannot_pass(self):
        with patch('html_artifact.current_browser', side_effect=OSError('unavailable')):
            with self.assertRaises(OSError): validate(self.area, root=self.root)

    def test_unresolved_advisory_still_blocks(self):
        self.policy['findings'][0]['status'] = 'unfixed'
        (self.root / 'native/browser-advisories.json').write_text(json.dumps(self.policy))
        self.write_receipt()
        with self.assertRaises(ValueError): self.check()

    def test_old_binary_cannot_be_approved_for_changed_source(self):
        (self.root / 'native/new.patch').write_text('new code not yet compiled')
        with self.assertRaises(ValueError): validate_build(self.root)

    def test_replacing_binary_invalidates_build_record(self):
        (self.root / 'build/html-microvm/bootstrap').write_text('other binary')
        with self.assertRaises(ValueError): validate_build(self.root)


if __name__ == '__main__':
    unittest.main()
