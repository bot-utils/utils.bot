#!/usr/bin/env python3
"""Production CDK gate for a frozen, scanned HTML runtime asset."""
import sys
from html_artifact import validate

if __name__ == '__main__':
    try:
        validate(sys.argv[1])
    except Exception as error:
        raise SystemExit('HTML release blocked: ' + str(error))
    print('HTML frozen runtime release checks passed.')
