# Third-party components and notices

The Go module manifests identify dependencies and versions; the Dockerfile
identifies the native source and build inputs. See [DEPENDENCIES.md](DEPENDENCIES.md)
for the distribution review still needed for these components.

Swagger UI assets are included under `internal/docs/assets/`. Their Apache 2.0
license, upstream notice, and bundled dependency notices are included alongside
the assets in `SWAGGER-UI-LICENSE`, `SWAGGER-UI-NOTICE`, and
`swagger-ui-bundle.js.LICENSE.txt`. The pinned upstream URLs, sizes, and hashes
are recorded in `internal/docs/swagger-assets.json`.

The Dockerfile builds PDFium and Poppler from upstream source. It retrieves a
separate PDFium packaging archive for its notice bundle and version metadata;
the production PDFium worker is built from source. Applicable PDFium and
packaging notices are distinct. Upstream patches and local build changes are
under `native/patches/`; retain the attribution in the patch files. The runtime
build preserves the PDFium notice bundle and the Poppler license and README.
The pinned PDFium source tree's own license and the upstream source attribution
for its modified `cpdf_dib.cpp` are included under `licenses/pdfium/`; they are
copied from the exact source commit named in the Dockerfile. They do not replace
the separate packaging and bundled-component notices. The source links and
hashes are recorded in the [PDFium provenance](licenses/pdfium/PROVENANCE.md).
Chromium build-file copyrights and the BSD-style root license referenced by
the musl build patch are preserved in `licenses/pdfium/CHROMIUM-BUILD-NOTICE.txt`
and `licenses/pdfium/CHROMIUM-BUILD-LICENSE`.
The Poppler GPL texts and the upstream `Stream.cc` attribution relevant to the
included Poppler patch are also included under `licenses/poppler/`. These were
copied from the source archive selected by the build recipe.

The PDF production image is assembled from scratch using musl, LLVM libc++ and a
small Alpine runtime closure. Debian is used only in build stages. Other native
inputs include Expat, FreeType, zlib, Fontconfig and DejaVu fonts. License texts
and source links for the runtime components are under `native/licenses/`, and
the runtime build retains component notices. Exact inputs and build choices
are in the Dockerfile and native configuration. Dependency notices and license requirements must be
reviewed for the exact artifacts being distributed; a source inventory or a
successful build alone does not establish redistribution compliance.

These notices do not alter rights granted by any third-party license.

## URL-to-Markdown branch

The Go HTML tokenizer is `golang.org/x/net/html` v0.61.0 (BSD-3-Clause);
its license is retained in `licenses/html/X-NET-LICENSE.txt`. Go/AWS module
versions and transitive components remain pinned in `go.mod`/`go.sum`.

The optional threat updater uses HaGeZi's **threat-only TIF**, not its ad/tracker
lists: <https://github.com/hagezi/dns-blocklists>, specifically
`wildcard/tif-onlydomains.txt`. HaGeZi publishes this data under GPL-3.0;
the license is retained in `licenses/html/HAGEZI-GPL-3.0.txt`. Feed data and the
resulting hashed lookup snapshot are separate data, not bundled application
source or binaries. Preserve its notices, provenance and applicable GPL rights
if distributing those data or derived snapshots. Our original-code copyright
notice does not restrict third-party data rights.

CERT Polska's warning list is <https://cert.pl/lista-ostrzezen/> with plain data
at <https://hole.cert.pl/domains/v2/domains.txt>. CERT's published reuse guidance
permits freely accessing, using and processing this list without special
permission: <https://github.com/CERT-Polska/phishing-api/blob/master/SPECIFICATION.md>.
That API documentation repository is archived; the official warning feed remains
maintained independently. Neither provider guarantees complete threat coverage.
No downloaded feed or customer HTML is committed to this repository.


The JavaScript worker is separate from the PDF image. It uses Google's official
Chrome for Testing ARM64 headless shell, with its exact version, source URL and
SHA-256 pinned in `Dockerfile.browser`. The upstream `LICENSE.headless_shell`
and package notices remain in the runtime image. Its small shared-library
closure is assembled from pinned Debian build stages; actual copied libraries,
Debian package versions and corresponding copyright notices remain in the image.
A browser provenance record identifies the official artifact independently of
Debian package metadata. Debian's browser package is not used. The runtime
contains no shell, package manager, Python, compiler, Node or npm. Review the
exact image's notices and corresponding-source obligations before distributing
a binary image; the original-code copyright notice does not apply to those
components. A successful OS-package scan alone does not cover the browser's
bundled libraries; also review the pinned browser against upstream security
releases. The optional local Docker test uses a pinned Playwright seccomp
profile under Apache-2.0, retaining its license in the ignored build folder;
Playwright itself is not installed in the worker.
