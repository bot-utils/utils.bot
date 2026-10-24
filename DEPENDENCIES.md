# Dependency and distribution review

The Go application dependencies are pinned in `go.mod` and `go.sum`. Consult
the exact dependency versions and their own license files; the list below is
not a complete license inventory.

- PDFium supplies a native PDF engine; its source and bundled components have
  their own copyright and notice requirements. The pinned source tree license
  and modified source-file attribution are included under `licenses/pdfium/`.
- Poppler supplies a separate PDF engine. The worker links Poppler, and the
  Poppler patch contains excerpts of upstream source. Review the patch's
  applicable terms and notices before source distribution, and the GPL terms
  and corresponding-source obligations before distributing a linked worker or
  image. The upstream license texts and `Stream.cc` attribution accompany the
  patch under `licenses/poppler/`.
- The x402 SDK and its transitive dependencies include go-ethereum. Review
  their licenses and any applicable static-binary redistribution and relinking
  obligations for the exact selected components.
- The MicroVM controller adds the pinned AWS SDK `lambdamicrovms` service
  module; it reuses the existing SDK core, signing and transport packages. No
  browser automation framework, JavaScript runtime package or new general
  purpose HTTP/JSON dependency is introduced.
- The AWS SDK and Swagger UI include components distributed under Apache
  2.0; preserve the required license and notice materials.
- Native runtime inputs also include Expat, FreeType, zlib, Fontconfig,
  DejaVu fonts, musl and LLVM runtime libraries. The production image is a
  scratch filesystem containing the selected Alpine and source-built runtime
  closure. Debian packages are build-stage inputs only. Pinned runtime notice
  provenance is under `native/licenses/PROVENANCE.json`.

The build recipe and source patches are in `Dockerfile` and `native/`; the
vendored Swagger UI notices are described in [THIRD_PARTY.md](THIRD_PARTY.md).
The native runtime build retains several upstream license files, but this file
is not a complete component-by-component distribution assessment. Review the
exact source and artifacts, their licenses and required notices before any
source, binary, or image release. Application-source terms must not restrict
rights independently granted by third-party licenses.
