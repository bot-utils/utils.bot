#!/usr/bin/env python3
"""CDK prerequisite: do not confuse accepted risk with a repaired dependency."""
import json
from pathlib import Path
import sys

from html_risk_review import ROOT, risk_accepted

if __name__ == '__main__':
    reviews = json.loads((ROOT / 'native/browser-risk-acceptances.json').read_text())['reviews']
    findings = json.loads(Path(sys.argv[1]).read_text())['findings']
    if any(not risk_accepted(row, reviews) for row in findings if row.get('status') == 'risk_accepted'):
        raise SystemExit('Missing, expired or changed HTML risk acceptance')
