#!/usr/bin/env python3
"""Verify the actual browser filesystem and provenance without executing a shell."""
import argparse,hashlib,json,pathlib,re,subprocess,tarfile

FORBIDDEN={'bin/sh','bin/bash','bin/mount','usr/bin/mount','usr/bin/nsenter','usr/lib/systemd/systemd-homed','usr/sbin/sshd','usr/bin/python3','usr/bin/apt','sbin/apk','usr/bin/gcc','usr/bin/node','usr/bin/Xorg','usr/lib/chromium/libvk_swiftshader.so','usr/lib/chromium/libEGL.so','usr/lib/chromium/libGLESv2.so','opt/utils/native-test'}
REQUIRED={'etc/os-release','etc/debian_version','var/lib/dpkg/status','usr/lib/chromium/chrome-headless-shell','usr/lib/chromium/LICENSE.headless_shell','opt/utils/bootstrap','opt/utils/browser-launch','opt/utils/browser-provenance.json','opt/utils/browser-libraries.json','opt/utils/browser-runtime-files.json','opt/utils/native-regressions-passed'}
REQUIRED.add('usr/share/doc/libglib2.0-0t64/copyright')
REMOVED_LIBRARIES=('libmount.so', 'libblkid.so', 'libgtk-3.so', 'libpango-', 'libcairo.so', 'libcups.so', 'libcurl.so', 'libvulkan.so', 'libatk-bridge-')

def verify_removed_components(paths):
 if any(pathlib.PurePosixPath(path).name.startswith(REMOVED_LIBRARIES) for path in paths):raise RuntimeError('Unused desktop/runtime component reintroduced')

def verify_native_inventory(hashes, inventory):
 expected={path:digest for path,digest in inventory.items() if path.startswith(('/lib/','/usr/lib/'))}
 if not expected or hashes!=expected:raise RuntimeError('Native runtime files differ from reviewed inventory')
 loader=hashes.get('/lib/ld-linux-aarch64.so.1')
 if not loader or loader!=hashes.get('/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1'):raise RuntimeError('Missing or mixed libc/loader versions')

def inspect(image):
 info=json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]
 if info.get('Architecture')!='arm64' or info.get('Os')!='linux':raise RuntimeError('ARM64 Linux runtime required')
 if info['Config'].get('User')!='10001:10001':raise RuntimeError('Browser runtime must be unprivileged')
 name='utils-html-inspect-'+hashlib.sha256(info['Id'].encode()).hexdigest()[:12]
 found=subprocess.run(['docker','container','inspect',name],capture_output=True,text=True)
 if found.returncode:
  subprocess.check_output(['docker','create','--name',name,'--network','none','--read-only','--cap-drop','ALL',image],text=True)
 else:
  record=json.loads(found.stdout)[0]
  if record['State']['Running'] or record['Image']!=info['Id']:raise RuntimeError('Unexpected inspection container')
 seen=set();data={};hashes={};bootstrap=None
 process=subprocess.Popen(['docker','export',name],stdout=subprocess.PIPE)
 with tarfile.open(fileobj=process.stdout,mode='r|*') as archive:
  for member in archive:
   path=member.name.lstrip('./');seen.add(path)
   if path in FORBIDDEN or member.mode & 0o6000:raise RuntimeError('Forbidden or privileged runtime file: '+path)
   if path in {'opt/utils/bootstrap','opt/utils/browser-launch','usr/lib/chromium/chrome-headless-shell'} and member.mode & 0o555 != 0o555:raise RuntimeError('Runtime executable inaccessible to arbitrary unprivileged UID')
   if member.isfile() and (path.startswith('lib/') or path.startswith('usr/lib/') and not path.startswith('usr/lib/chromium/')):
    stream=archive.extractfile(member);digest=hashlib.sha256()
    while chunk:=stream.read(65536):digest.update(chunk)
    hashes['/'+path]=digest.hexdigest()
   if path=='opt/utils/bootstrap' and member.isfile():
    digest=hashlib.sha256();stream=archive.extractfile(member)
    while chunk:=stream.read(65536):digest.update(chunk)
    bootstrap=digest.hexdigest()
   if path in {'etc/os-release','etc/debian_version','var/lib/dpkg/status','opt/utils/browser-provenance.json','opt/utils/browser-libraries.json','opt/utils/browser-runtime-files.json','opt/utils/native-regressions-passed'}:
    stream=archive.extractfile(member)
    if not stream or member.size>1024*1024:raise RuntimeError('Missing/bounded scanner provenance')
    data[path]=stream.read().decode()
 if process.wait()!=0:raise RuntimeError('Image export failed')
 verify_removed_components(seen)
 if REQUIRED-seen:raise RuntimeError('Missing runtime files: '+str(sorted(REQUIRED-seen)))
 if data['opt/utils/native-regressions-passed']!='native_regressions_passed\n':raise RuntimeError('Native build regression evidence missing')
 if 'ID=debian' not in data['etc/os-release'] or not data['etc/debian_version'].strip():raise RuntimeError('OS scanner metadata missing')
 packages=re.findall(r'^Package: (.+)$',data['var/lib/dpkg/status'],re.M)
 if len(packages)<20 or any(p in packages for p in ['libxml2','chromium-common','chromium-headless-shell','mount','util-linux','systemd-homed']):raise RuntimeError('Incorrect runtime closure/package provenance')
 provenance=json.loads(data['opt/utils/browser-provenance.json'])
 if provenance['version']!='156.0.8078.47' or provenance['sha256']!='955059fa7020d7be85eb503e21339fd4d718f51f5996d3b60633fbf908bda132':raise RuntimeError('Browser provenance mismatch')
 sources=json.loads(data['opt/utils/browser-libraries.json'])
 expected=json.loads((pathlib.Path(__file__).resolve().parent.parent/'native/browser-libraries.json').read_text())
 if sources!=expected:raise RuntimeError('Native source provenance mismatch')
 files=json.loads(data['opt/utils/browser-runtime-files.json'])
 verify_native_inventory(hashes,files)
 versions={}
 for stanza in data['var/lib/dpkg/status'].split('\n\n'):
  fields=dict(re.findall(r'^(Package|Version): (.+)$',stanza,re.M))
  if 'Package' in fields:versions[fields['Package']]=fields.get('Version')
 for row in expected['debianLibraries']:
  if versions.get(row['name'])!=row['version'] and not (row.get('optional') and row['name'] not in versions):raise RuntimeError('Pinned native Debian version mismatch')
 for row in expected['upstreamLibraries']:
  if versions.get(row['package'])!=row['version']:raise RuntimeError('Pinned native upstream version mismatch')
 print(json.dumps({'runtime_checked':True,'os_packages':len(packages),'browser_version':provenance['version'],'privileged_files':0,'shell_present':False}))
 return {'image_id':info['Id'],
         'image_config_id':info.get('Descriptor',{}).get('annotations',{}).get('config.digest'),
         'layer_ids':info['RootFS']['Layers'],
         'files':seen,'versions':versions,'bootstrap_sha256':bootstrap,'browser_version':provenance['version'],
         'sources':{row['package']:row['sourcePackage'] for row in expected['upstreamLibraries']}}

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('image');args=parser.parse_args();inspect(args.image)
