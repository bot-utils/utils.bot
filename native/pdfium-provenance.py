"""Record the exact compiled primary-parser source and patched dependencies."""
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path('/source/pdfium')
commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
if commit != '2fd6cff57d9412cc42ef1a7e4e0a59b13a1e7cec':
    raise SystemExit('Unexpected PDFium source revision')
sources = {}
for relative, required in (
    ('third_party/freetype/src/src/cid/cidload.c', 'cum_len / 4 > stream->size'),
    ('third_party/zlib/gzwrite.c', 'state->strm.avail_in = 0;\n                state->strm.next_in = state->in;'),
    ('core/fpdfapi/page/cpdf_dib.cpp', 'Reject JPEG 2000 and JBIG2 before invoking the bundled decoders'),
):
    data = (root / relative).read_bytes()
    if required not in data.decode():
        raise SystemExit('Missing upstream security fix: ' + relative)
    sources[relative] = hashlib.sha256(data).hexdigest()
args = (root / 'out/Musl/args.gn').read_text()
for required in ('pdf_enable_v8 = false', 'pdf_enable_xfa = false', 'is_clang = true'):
    if required not in args:
        raise SystemExit('Unexpected build configuration')
build_files = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (root / 'build/toolchain/linux/local_musl/BUILD.gn', root / 'build/config/BUILD.gn')}
json.dump({'buildSourceHashes': build_files, 'muslBuildPatchSHA256': '0907bee72c60439639ca454cf5bd86e14be21e953511a7c1fb77e8eda4765bfc', 'sourceCommit': commit, 'sourceHashes': sources, 'compiler': subprocess.check_output(['clang++', '--version'], text=True).strip(), 'argsSHA256': hashlib.sha256(args.encode()).hexdigest(), 'bundledFreetypePatch': 'f3ca71c9900fe860849b3163a6e2c1e765b291d9', 'bundledZlibPatch': 'df84af25dc1942490e1d1c899a07619152a46148', 'disabledRasterDecoders': ['JBIG2Decode', 'JPXDecode'], 'rasterDisablePatchSHA256': 'c3ffebb7e0f0674b40acf416c4ec3e3c0d390da7a93478bf13f4a6ac0fe2af1c'}, sys.stdout, indent=2, sort_keys=True)
