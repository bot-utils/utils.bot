#!/usr/bin/env python3
"""Check dated vendor review records used by the CDK policy prerequisite."""
import json
from pathlib import Path
import sys
from html_vendor_review import vendor_reviewed

if __name__ == '__main__':
    root = Path(__file__).resolve().parent.parent
    reviews = json.loads((root / 'native/browser-vendor-reviews.json').read_text())['reviews']
    findings = json.loads(Path(sys.argv[1]).read_text())['findings']
    if any(not vendor_reviewed(row, reviews) for row in findings if row.get('status') == 'vendor_disputed'):
        raise SystemExit('Missing, expired or changed HTML vendor review')
