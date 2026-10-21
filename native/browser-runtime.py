"""Assemble the browser's runtime closure, keeping real package/license metadata."""
import hashlib,json,pathlib,re,shutil,subprocess,zipfile
root=pathlib.Path('/runtime');root.mkdir()
with zipfile.ZipFile('/tmp/browser.zip') as z:z.extractall('/tmp/cft')
browser=pathlib.Path('/tmp/cft/chrome-headless-shell-linux-arm64')
destination=root/'usr/lib/chromium';destination.mkdir(parents=True)
# UI translations and GPU drivers do not participate in DOM-to-Markdown.
# Retain ICU data for all customer languages, and the complete license notice.
for name in ['ABOUT','LICENSE.headless_shell','chrome-headless-shell','headless_command_resources.pak','headless_lib_data.pak','headless_lib_strings.pak','icudtl.dat','v8_context_snapshot.bin']:
 shutil.copy2(browser/name,destination/name)
(destination/'locales').mkdir()
shutil.copy2(browser/'locales/en-US.pak',destination/'locales/en-US.pak')
shutil.copytree(browser/'hyphen-data',destination/'hyphen-data')
(root/'usr/lib/chromium/chromium-headless-shell').symlink_to('chrome-headless-shell')
(root/'usr/lib/chromium/chrome-headless-shell').chmod(0o555)
packages=set()
copied=set()
overrides=pathlib.Path('/native-overrides')
records=json.loads((overrides/'packages.json').read_text())
owners=json.loads((overrides/'owners.json').read_text())
loader=overrides/'usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1'
library_path=str(overrides/'usr/lib/aarch64-linux-gnu')+':/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu'
def track(path):
 if str(path)=='/etc/ssl/certs/ca-certificates.crt':packages.add('ca-certificates');return
 for candidate in [str(path),str(path.resolve()),str(path).replace('/lib/','/usr/lib/',1)]:
  p=subprocess.run(['dpkg-query','-S',candidate],capture_output=True,text=True)
  if p.returncode==0:
   for line in p.stdout.splitlines():
    if ': ' in line:
     package=line.split(': ',1)[0]
     if re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?',package):packages.add(package)
   if any(re.match(r'^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?: ',line) for line in p.stdout.splitlines()):return
 raise RuntimeError('No package provenance for '+str(path))
def copy(path):
 path=pathlib.Path(path)
 actual=path
 if path.is_relative_to(overrides):path=pathlib.Path('/')/path.relative_to(overrides)
 elif (overrides/str(path).lstrip('/')).exists():actual=overrides/str(path).lstrip('/')
 elif str(path).startswith('/lib/') and (overrides/'usr'/str(path).lstrip('/')).exists():actual=overrides/'usr'/str(path).lstrip('/')
 if str(path) in copied:return
 copied.add(str(path));dest=root/str(path).lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True)
 if path.is_dir():shutil.copytree(path,dest,dirs_exist_ok=True);return
 shutil.copy2(actual,dest,follow_symlinks=True)
 owner=owners.get('/'+str(actual.relative_to(overrides))) if actual.is_relative_to(overrides) else None
 if owner:packages.add(owner)
 else:track(path)
def closure(path):
 out=subprocess.check_output([str(loader),'--library-path',library_path,'--list',str(path)],text=True)
 if 'not found' in out:raise RuntimeError('Missing browser runtime dependency')
 for name in re.findall(r'(?:=>\s+|^\s*)(/[^\s]+)',out,re.M):copy(name)
closure(browser/'chrome-headless-shell');closure('/browser-launch')
for name in ['libsoftokn3.so','libfreebl3.so','libfreeblpriv3.so','libnssckbi.so']:
 path=pathlib.Path('/usr/lib/aarch64-linux-gnu')/name
 if path.exists():copy(path);closure(path)
for path in ['/etc/ssl/certs/ca-certificates.crt','/etc/fonts','/usr/share/fonts/truetype/liberation','/usr/share/fonts/truetype/liberation2']:
 if pathlib.Path(path).exists():copy(path)
# Directory copies have separately pinned Debian package provenance.
packages.update(['ca-certificates','fontconfig-config','fonts-liberation'])
for directory in ['tmp','etc','opt/utils','var/lib/dpkg','usr/share/doc']:(root/directory).mkdir(parents=True,exist_ok=True)
(root/'tmp').chmod(0o1777)
(root/'etc/passwd').write_text('utils:x:10001:10001::/tmp:/nonexistent\n')
(root/'etc/group').write_text('utils:x:10001:\n')
(root/'etc/nsswitch.conf').write_text('hosts: files dns\n')
(root/'etc/os-release').write_bytes(pathlib.Path('/etc/os-release').read_bytes())
(root/'etc/debian_version').write_bytes(pathlib.Path('/etc/debian_version').read_bytes())
shutil.copy2('/browser-launch',root/'opt/utils/browser-launch')
# Preserve complete stanzas for packages whose actual runtime files are copied.
status=[]
for package in sorted(packages):
 name=package.split(':')[0]
 stanza=records.get(name) or subprocess.check_output(['dpkg-query','-s',package],text=True).strip();status.append(stanza)
 doc=pathlib.Path('/usr/share/doc')/name
 if (overrides/'usr/share/doc'/name).exists():doc=overrides/'usr/share/doc'/name
 if doc.exists():
  (root/'usr/share/doc'/name).mkdir(exist_ok=True)
  for notice in ['copyright','changelog.Debian.gz','COPYING','LICENSE','README']:
   if (doc/notice).exists():shutil.copy2(doc/notice,root/'usr/share/doc'/name/notice,follow_symlinks=True)
(root/'var/lib/dpkg/status').write_text('\n\n'.join(status)+'\n')

(root/'opt/utils/browser-provenance.json').write_text(json.dumps({'name':'chrome-headless-shell','version':'156.0.8078.47','platform':'linux-arm64','url':'https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.47/linux-arm64/chrome-headless-shell-linux-arm64.zip','sha256':hashlib.sha256(pathlib.Path('/tmp/browser.zip').read_bytes()).hexdigest()}))

(root/'opt/utils/browser-libraries.json').write_bytes((overrides/'sources.json').read_bytes())

# Native security rebuilds may retain DWARF/debug symbols. They are build-time
# data, not runtime dependencies. Preserve dynamic symbols and license/package
# provenance; the native tests run against these exact stripped library bytes.
for path in sorted(root.rglob('*')):
 if path.is_file() and not path.is_symlink():
  with path.open('rb') as stream:elf=stream.read(4)==b'\x7fELF'
  if elf:subprocess.run(['strip','--strip-unneeded',str(path)],check=True)


# Bind the scanner inventory to the actual shared-library bytes in this image.
files={}
for relative in sorted(copied):
 path=root/relative.lstrip('/')
 if path.is_file():files[relative]=hashlib.sha256(path.read_bytes()).hexdigest()
(root/'opt/utils/browser-runtime-files.json').write_text(json.dumps(files,sort_keys=True))
