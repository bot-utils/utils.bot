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

The production image is assembled from scratch using musl, LLVM libc++ and a
small Alpine runtime closure. Debian is used only in build stages. Other native
inputs include Expat, FreeType, zlib, Fontconfig and DejaVu fonts. License texts
and source links for the runtime components are under `native/licenses/`, and
the runtime build retains component notices. Exact inputs and build choices
are in the Dockerfile and native configuration. Dependency notices and license requirements must be
reviewed for the exact artifacts being distributed; a source inventory or a
successful build alone does not establish redistribution compliance.

These notices do not alter rights granted by any third-party license.
