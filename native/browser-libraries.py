"""Build pinned native security updates; never install tools into the runtime.

The Debian base stays stable. Selected newer ABI-compatible shared libraries
come from Debian's archive, with exact package bytes and control records kept.
Upstream libraries not yet packaged by Debian retain separate source provenance.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path('/native-overrides')
WORK = Path('/tmp/native-build')
LIB = ROOT / 'usr/lib/aarch64-linux-gnu'
ROOT.mkdir()
WORK.mkdir()
LIB.mkdir(parents=True)
lock = json.loads(Path('/src/browser-libraries.json').read_text())
records = {}
owners = {}


def run(args, cwd=None, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def download(record, target):
    with urllib.request.urlopen(record['url'], timeout=60) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != record['sha256']:
        raise RuntimeError('Native source/package checksum mismatch: ' + record['name'])
    target.write_bytes(data)


for record in lock['debianLibraries']:
    archive = WORK / (record['name'] + '.deb')
    download(record, archive)
    control = subprocess.check_output(['dpkg-deb', '-f', str(archive)], text=True)
    for key, value in [('Package', record['name']), ('Version', record['version']), ('Architecture', 'arm64')]:
        if key + ': ' + value + '\n' not in control + '\n':
            raise RuntimeError('Native Debian package identity mismatch')
    records[record['name']] = control.strip() + '\nStatus: install ok installed'
    run(['dpkg-deb', '-x', str(archive), str(ROOT)])
    process = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(archive)], stdout=subprocess.PIPE)
    with tarfile.open(fileobj=process.stdout, mode='r|*') as bundle:
        for member in bundle:
            if member.isfile() or member.issym():
                owners['/' + member.name.removeprefix('./')] = record['name']
    if process.wait():
        raise RuntimeError('Debian file inventory failed')

for record in lock['upstreamLibraries']:
    archive = WORK / (record['name'] + '.tar')
    download(record, archive)
    source = WORK / record['name']
    source.mkdir()
    with tarfile.open(archive) as bundle:
        bundle.extractall(source, filter='data')
    dirs = list(source.iterdir())
    if len(dirs) != 1 or not dirs[0].is_dir():
        raise RuntimeError('Unexpected upstream archive structure')
    source = dirs[0]
    if record.get('debianPatches'):
        backports = WORK / 'glib-debian.tar.xz'
        download(record['debianPatches'], backports)
        with tarfile.open(backports) as bundle:
            bundle.extractall(source, filter='data')
        for line in (source/'debian/patches/series').read_text().splitlines():
            line = line.partition('#')[0].strip()
            if line:
                run(['patch', '-p1', '--fuzz=0', '-i', str(source/'debian/patches'/line)], cwd=source)
    if record.get('patch'):
        patch = Path('/src/patches') / record['patch']
        if hashlib.sha256(patch.read_bytes()).hexdigest() != record['patchSHA256']:
            raise RuntimeError('Native patch checksum mismatch')
        run(['patch', '-p1', '--fuzz=0', '-i', str(patch)], cwd=source)
    if record['name'] == 'alsa':
        run(['autoreconf', '-fi'], cwd=source)
    env = dict(os.environ, CFLAGS='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3',
               LDFLAGS='-Wl,-z,relro,-z,now')
    config = ['./configure', '--prefix=/usr', '--libdir=/usr/lib/aarch64-linux-gnu', '--disable-static']
    if record['name'] == 'zlib':
        config = ['./configure', '--prefix=/usr', '--libdir=/usr/lib/aarch64-linux-gnu', '--shared']
    elif record['name'] == 'x11':
        config += ['--disable-xf86bigfont', '--disable-specs']
    elif record['name'] in {'xi', 'xrender'}:
        config += ['--disable-specs']
    elif record['name'] == 'alsa':
        # No devices/audio are exposed. Exclude the independently vulnerable
        # topology/UCM parsers, Python bindings and external plugin loader.
        config += ['--disable-topology', '--disable-ucm', '--disable-python', '--disable-alisp']
    if record['name'] == 'glib':
        link_dir=WORK/'zlib-link';link_dir.mkdir()
        shutil.copy2(LIB/'libz.so',link_dir/'libz.so',follow_symlinks=True)
        env['LDFLAGS']+=' -L'+str(link_dir)
        env['PKG_CONFIG_PATH']=str(LIB/'pkgconfig')
        env['CFLAGS']+=' -I'+str(ROOT/'usr/include')
        run(['meson', 'setup', 'out', '--prefix=/usr', '--libdir=lib/aarch64-linux-gnu',
             '--default-library=shared', '--wrap-mode=nodownload', '-Dtests=false',
             '-Dinstalled_tests=false', '-Ddocumentation=false', '-Dintrospection=disabled',
             '-Dman-pages=disabled', '-Dsysprof=disabled', '-Dlibelf=disabled',
             '-Dlibmount=disabled', '-Dselinux=disabled'], cwd=source, env=env)
        run(['ninja', '-C', 'out', '-j4'], cwd=source, env=env)
        run(['meson', 'install', '-C', 'out', '--no-rebuild', '--destdir='+str(ROOT)], cwd=source, env=env)
    else:
        run(config, cwd=source, env=env)
        run(['make', '-j4'], cwd=source, env=env)
    if record['name'] == 'zlib':
        run(['make', 'test'], cwd=source, env=env)
    if record['name'] != 'glib':run(['make', 'install', 'DESTDIR=' + str(ROOT)], cwd=source, env=env)
    name = record['package']
    prefixes = {'x11': ['libX11'], 'xi': ['libXi'], 'xrender': ['libXrender'], 'alsa': ['libasound'], 'zlib': ['libz'], 'glib': ['libglib-2.0','libgobject-2.0','libgio-2.0','libgmodule-2.0','libgthread-2.0']}[record['name']]
    for prefix in prefixes:
        for library in LIB.glob(prefix + '.so*'):
            owners['/' + str(library.relative_to(ROOT))] = name
    records[name] = ('Package: ' + name + '\nStatus: install ok installed\nArchitecture: arm64\n'
                     'Version: ' + record['version'] + '\nSource: ' + record['sourcePackage'] + '\nMaintainer: utils.bot <info@utils.bot>\n'
                     'Description: shared library built from checksum-pinned upstream source\n'
                     'Homepage: ' + record['url'])
    notices = ROOT / 'usr/share/doc' / name
    notices.mkdir(parents=True, exist_ok=True)
    for notice in ['COPYING', 'LICENSE', 'README']:
        if (source / notice).is_file():
            shutil.copy2(source / notice, notices / notice)
    # Preserve the attribution for Debian's source and backported patches too.
    if (source / 'debian/copyright').is_file():
        shutil.copy2(source / 'debian/copyright', notices / 'copyright')

(ROOT / 'packages.json').write_text(json.dumps(records, sort_keys=True))
(ROOT / 'sources.json').write_text(json.dumps(lock, sort_keys=True))

(ROOT / 'owners.json').write_text(json.dumps(owners, sort_keys=True))
