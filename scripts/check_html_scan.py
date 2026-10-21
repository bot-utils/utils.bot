#!/usr/bin/env python3
"""Fail closed on new findings, changed packages, and unresolved advisories.

Trivy's stable Debian database can flag newer, patched Debian/upstream versions
as unfixed. Exact reviewed fixes and verifiably absent components can pass.
Vendor classifications and owner-accepted residual risks have separate, version-
bound 30-day reviews. Generic containment labels never waive a finding.
Accepted risks are reported separately from fixes and vendor classifications.
"""
import argparse
from datetime import datetime, timezone
import json
import re
from pathlib import Path
import sys

from check_html_image import inspect
from html_vendor_review import vendor_reviewed
from html_risk_review import risk_accepted, BROWSER


ROOT = Path(__file__).resolve().parent.parent


def evaluate(scan, runtime, policy, vendor_reviews=(), risk_reviews=(), *, root=None):
    metadata = scan.get('Metadata', {})
    if runtime.get('layer_ids') and metadata.get('DiffIDs') != runtime['layer_ids']:
        raise ValueError('Scan/image filesystem layer mismatch')
    if metadata.get('ImageID') != runtime['image_id']:
        # Containerd Docker reports the manifest ID; archive scanners identify
        # its config blob. Require Docker's config identity AND exact ordered
        # filesystem layer digests, never an arbitrary alternate image ID.
        if not runtime.get('image_config_id') or not runtime.get('layer_ids') or metadata.get('ImageID') != runtime['image_config_id']:
            raise ValueError('Scan/image identity mismatch')
    stamp = re.sub(r'(\.\d{6})\d+', r'\1', scan.get('CreatedAt', ''))
    created = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    age = (datetime.now(timezone.utc) - created).total_seconds()
    if age < -300 or age > 24 * 3600:
        raise ValueError('Fresh scan required')
    packages = {p['Name']: (str(p['Epoch'])+':' if p.get('Epoch') else '')+p['Version']+('-'+p['Release'] if p.get('Release') else '') for r in scan.get('Results', [])
                if r.get('Class') == 'os-pkgs' for p in r.get('Packages', [])}
    if not packages or packages != runtime['versions']:
        raise ValueError('Full OS scan/inventory match required')
    sources = {p['Name']: p.get('SrcName') for r in scan.get('Results', [])
               if r.get('Class') == 'os-pkgs' for p in r.get('Packages', [])}
    if any(sources.get(name) != source for name, source in runtime.get('sources', {}).items()):
        raise ValueError('Upstream source identity omitted or altered; advisory matching would be incomplete')
    reviewed = {}
    for row in policy['findings']:
        key = row['package'], row['cve']
        if key in reviewed:
            raise ValueError('Duplicate advisory policy entry')
        reviewed[key] = row
    problems = []
    fixed = absent = disputed = 0
    accepted = []
    for result in scan.get('Results', []):
        for finding in result.get('Vulnerabilities', []):
            key = finding['PkgName'], finding['VulnerabilityID']
            item = reviewed.get(key)
            if not item:
                problems.append((*key, 'unreviewed_finding'))
            elif finding['InstalledVersion'] != runtime['versions'].get(key[0]):
                problems.append((*key, 'scan_inventory_mismatch'))
            elif item['status'] in ('fixed', 'component_absent', 'vendor_disputed', 'risk_accepted') and finding['InstalledVersion'] != item.get('version'):
                problems.append((*key, 'unreviewed_version'))
            elif item['status'] == 'fixed':
                if item.get('version'):
                    fixed += 1
                else:
                    problems.append((*key, 'unreviewed_version'))
            elif item['status'] == 'component_absent':
                paths = runtime['files']
                forbidden = item.get('forbidden')
                if not isinstance(forbidden, list) or not forbidden or any(not isinstance(part, str) or not part for part in forbidden):
                    problems.append((*key, 'component_review_incomplete'))
                elif any(part in Path(path).name for part in forbidden for path in paths):
                    problems.append((*key, 'affected_component_present'))
                else:
                    absent += 1
            elif item['status'] == 'vendor_disputed' and vendor_reviewed(item, vendor_reviews):
                disputed += 1
            elif (item['status'] == 'risk_accepted' and runtime.get('browser_version') == BROWSER
                  and risk_accepted(item, risk_reviews, **({'root': root} if root is not None else {}))):
                accepted.append(key)
            else:
                problems.append((*key, 'unresolved_review'))
    return {'fixed_matching_records': fixed, 'absent_component_records': absent,
            'vendor_disputed_records': disputed, 'accepted_risk_records': len(accepted),
            'accepted_risk_findings': accepted, 'blocking_findings': problems, 'passed': not problems}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('image')
    parser.add_argument('scan', type=Path)
    args = parser.parse_args()
    result = evaluate(json.loads(args.scan.read_text()), inspect(args.image),
                      json.loads((ROOT/'native/browser-advisories.json').read_text()),
                      json.loads((ROOT/'native/browser-vendor-reviews.json').read_text())['reviews'],
                      json.loads((ROOT/'native/browser-risk-acceptances.json').read_text())['reviews'])
    print(json.dumps(result, sort_keys=True))
    sys.exit(0 if result['passed'] else 1)
