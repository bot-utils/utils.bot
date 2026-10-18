# PDFium source notice provenance

The included PDFium notices were obtained from the upstream PDFium source tree
at commit `2fd6cff57d9412cc42ef1a7e4e0a59b13a1e7cec`, the source revision in
the Dockerfile. These are source notices; packaging and bundled components have
separate notices.

- [Upstream LICENSE](https://pdfium.googlesource.com/pdfium/+/2fd6cff57d9412cc42ef1a7e4e0a59b13a1e7cec/LICENSE): SHA-256 `1fe9dea718fbd75cf149adaf4d8a22a4335604d964ddb76d1b45383dec8668c9`. The included `LICENSE` is the complete upstream file.
- [Upstream cpdf_dib.cpp](https://pdfium.googlesource.com/pdfium/+/2fd6cff57d9412cc42ef1a7e4e0a59b13a1e7cec/core/fpdfapi/page/cpdf_dib.cpp): SHA-256 `ebe3ea0242c02e43a8ae22d9cf1e94fe0644387539ca822319d743d70416d185` for the complete upstream file. The included `CPDF-DIB-NOTICE.txt` is its exact leading copyright and license header before the first `#include`, with SHA-256 `84a5b948aa558898b8ec529004fc31bd06368f69db8f123e238d3ce3548d6691`.

The files were independently downloaded twice through the upstream Gitiles
text API, decoded from Base64, and checked for matching hashes. The full
source file is referenced for provenance and is not included here.

The musl build patch changes Chromium build files pinned by PDFium DEPS at
revision `ebdaeefa62db7c40f27cacb0eb034db3a5cdb849`. `CHROMIUM-BUILD-NOTICE.txt`
preserves the exact leading headers from each modified file at that revision.
Those headers refer to Chromium's BSD-style LICENSE at the source-tree root,
which is not present in the separate build repository.
`CHROMIUM-BUILD-LICENSE` supplies that [Chromium root license](https://chromium.googlesource.com/chromium/src/+/18f9a68cef344202f73a43120372287b46537f35/LICENSE)
from the explicitly recorded root revision, with SHA-256
`368cca1106be99d39ecd32a38d8305585d802a475effb66380b91ffc9bcf709b`. The root-license snapshot revision
is separate from the pinned build-repository revision.
