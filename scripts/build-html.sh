#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
go test ./internal/htmlrender -run '^TestDisposableWorkerDependencyBoundary$'
for target in payment html html-worker html-microvm threat-update html-network-check; do
  mkdir -p "build/$target"
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -tags lambda.norpc -ldflags='-s -w' -o "build/$target/bootstrap" "./cmd/$target"
done

# Bind the compiled worker to these sources before freezing/scanning its image.
python3 - <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from html_artifact import digest, source_digest
Path('build/html-microvm/build.json').write_text(json.dumps({
    'sourceSHA256': source_digest(),
    'bootstrapSHA256': digest('build/html-microvm/bootstrap'),
}, sort_keys=True) + '\n')
PY
python3 scripts/build-microvm.py
