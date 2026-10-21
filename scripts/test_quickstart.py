#!/usr/bin/env python3
"""Exercise the actual README client against an offline x402 quote/sign/replay.

Optional caller-side SDKs are installed only under ignored build/. Service
modules and runtime images acquire no dependencies. No funded request is sent.
"""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
def main():
    area = ROOT / 'build/quickstart-validation'
    area.mkdir(parents=True, exist_ok=True)
    readme = (ROOT / 'internal/serviceinfo/readme.md').read_text()
    client = readme.split('```typescript\n', 1)[1].split('\n```', 1)[0]
    (area / 'client.ts').write_text(client)
    (area / 'offline.mts').write_text((ROOT / 'scripts/quickstart-offline.mts').read_text())
    subprocess.run(['npm', 'install', '--ignore-scripts', '--no-audit', '--no-fund',
                    '--package-lock=false', '@x402/fetch@2.28.0', '@x402/evm@2.28.0',
                    'viem', 'tsx', 'typescript', '@types/node'], cwd=area, check=True)
    subprocess.run([str(area / 'node_modules/.bin/tsc'), '--noEmit', '--module', 'nodenext',
                    '--target', 'es2022', '--esModuleInterop', '--skipLibCheck', '--types',
                    'node', 'client.ts'], cwd=area, check=True)
    subprocess.run([str(area / 'node_modules/.bin/tsx'), 'offline.mts'], cwd=area, check=True)


if __name__ == "__main__":
    main()
