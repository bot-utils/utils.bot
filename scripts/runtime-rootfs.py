"""Assemble a scratch musl runtime with exact file/package/source provenance."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess

root = pathlib.Path('/rootfs')
root.mkdir()
files = {}
packages = set()
records = pathlib.Path('/lib/apk/db/installed').read_text().split('\n\n')
package_records = {}
for record in records:
    fields = dict(line.split(':', 1) for line in record.splitlines() if ':' in line)
    if 'P' in fields:
        package_records[fields['P']] = (record, fields)


def copy(source, destination=None, package=True):
    source = pathlib.Path(source)
    destination = pathlib.Path(destination or source)
    target = root / destination.relative_to('/')
    if source.is_dir():
        for child in sorted(source.iterdir()):
            copy(child, destination / child.name, package)
        return
    # X11 font indexes are generated installation artifacts, not used by Fontconfig.
    if destination.name in ('fonts.dir', 'fonts.scale') and str(destination).startswith('/usr/share/fonts/'):
        return
    if any(name in str(destination) for name in ('libc.so.6', 'libstdc++', 'libgcc_s')):
        raise SystemExit('GNU runtime dependency returned: ' + str(destination))
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    mode = source.stat().st_mode
    if mode & 0o6000:
        raise SystemExit('Privileged input: ' + str(source))
    target.chmod(mode & 0o777)
    files[str(destination)] = hashlib.sha256(target.read_bytes()).hexdigest()
    if package:
        result = subprocess.run(['apk', 'info', '--no-network', '-W', str(source)], capture_output=True, text=True)
        if result.returncode:
            raise SystemExit('Unowned runtime package file: ' + str(source))
        owner = result.stdout.strip().rsplit(' ', 1)[-1]
        matches = [name for name, (_, fields) in package_records.items() if owner == name + '-' + fields['V']]
        if len(matches) != 1:
            raise SystemExit('Ambiguous package provenance: ' + str(source))
        packages.add(matches[0])


def libraries(binary):
    result = subprocess.run(['ldd', binary], capture_output=True, text=True,
                            env=dict(os.environ, LD_LIBRARY_PATH='/opt/expat/lib:/opt/freetype/lib:/opt/zlib/lib'))
    if result.returncode or 'not found' in result.stdout + result.stderr:
        raise SystemExit('Unresolved native dependency: ' + result.stdout + result.stderr)
    return [m.group(1) for line in result.stdout.splitlines()
            if (m := re.search(r'(?:=>\s*)?(/\S+)\s+\(', line))]


for binary in ('/app/pdfium-worker', '/app/poppler-worker'):
    copy(binary, package=False)
    for library in libraries(binary):
        name = pathlib.Path(library).name
        custom = name.startswith(('libexpat.so', 'libfreetype.so', 'libz.so'))
        source_built = custom or name.startswith('libpoppler')
        copy(library, '/usr/lib/' + name if custom else None, package=not source_built)

copy('/app/server', package=False)
for path in ('/etc/fonts', '/usr/share/fonts/dejavu'):
    copy(path)
copy('/var/cache/fontconfig', package=False)
for path in ('/etc/ssl/certs/ca-certificates.crt', '/etc/os-release'):
    copy(path)
for path in (
    '/opt/pdfium/LICENSE', '/opt/pdfium/licenses', '/opt/pdfium/args.gn',
    '/opt/pdfium/VERSION', '/opt/pdfium/provenance.json', '/opt/poppler/COPYING', '/opt/poppler/COPYING3',
    '/opt/expat/COPYING', '/opt/expat/Changes', '/opt/freetype/FTL.TXT',
    '/opt/freetype/GPLv2.TXT', '/opt/freetype/LICENSE.TXT', '/opt/zlib/LICENSE',
    '/usr/share/agent-pdf/patches',
):
    copy(path, package=False)

for path in pathlib.Path('/usr/share/licenses').iterdir():
    if path.is_file():
        copy(path, package=False)

# Cache files are generated data, not owned APK paths; verify the source packages
# for the surrounding library/font/config assets, not a fabricated cache package.
status = root / 'lib/apk/db/installed'
status.parent.mkdir(parents=True, exist_ok=True)
status.write_text('\n\n'.join(package_records[name][0] for name in sorted(packages)) + '\n')
files['/lib/apk/db/installed'] = hashlib.sha256(status.read_bytes()).hexdigest()
components = [
    {'name': name, 'version': package_records[name][1]['V'],
     'kind': 'alpine-partial-package', 'license': package_records[name][1].get('L', '')}
    for name in sorted(packages)
]
components += [
    {'name': 'pdfium', 'version': 'chromium/8086', 'kind': 'upstream-source',
     'commit': '2fd6cff57d9412cc42ef1a7e4e0a59b13a1e7cec'},
    {'name': 'poppler', 'version': '26.10.0', 'kind': 'upstream-source'},
    {'name': 'expat', 'version': '2.9.0', 'kind': 'upstream-source'},
    {'name': 'freetype', 'version': '2.14.3', 'kind': 'patched-upstream-source',
     'patch': 'f3ca71c9900fe860849b3163a6e2c1e765b291d9'},
    {'name': 'zlib', 'version': '1.3.2', 'kind': 'patched-upstream-source',
     'patch': 'df84af25dc1942490e1d1c899a07619152a46148'},
    {'name': 'compiler-rt', 'version': package_records['compiler-rt'][1]['V'], 'kind': 'static-runtime'},
]
manifest = root / 'usr/share/agent-pdf/runtime.json'
manifest.parent.mkdir(parents=True, exist_ok=True)
manifest.write_text(json.dumps({'abi': 'musl-libc++', 'components': components, 'files': files}, indent=2, sort_keys=True) + '\n')
(root / 'tmp').mkdir(mode=0o555)
print('Runtime assembled:', len(files), 'files;', len(components), 'components')
