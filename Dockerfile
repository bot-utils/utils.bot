FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/server ./cmd/server
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /server ./cmd/server

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS native-source
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends g++ curl ca-certificates cmake ninja-build pkgconf xz-utils libfontconfig1-dev libfreetype-dev zlib1g-dev patch
WORKDIR /build
RUN curl -fL https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/8086/pdfium-linux-arm64.tgz -o pdfium.tgz && echo 'e7e2fe4686925618330103cb167950aca5a84bb00fd977a41b86be59dd1480a2  pdfium.tgz' | sha256sum -c - && mkdir pdfium && tar -xzf pdfium.tgz -C pdfium
COPY native/patches/poppler-disable-jbig2.patch /build/
RUN curl -fL https://poppler.freedesktop.org/poppler-26.10.0.tar.xz -o poppler.tar.xz && echo '6792cb7c69205007ad87d2e936cecc5b3a31fac29ab54ffc3175fdb6b2a6ce35  poppler.tar.xz' | sha256sum -c - && echo '545a0ecc20364146cda19a9f01c14517026b53c42d9e770760e76def7c54e3fc  poppler-disable-jbig2.patch' | sha256sum -c - && tar -xJf poppler.tar.xz && patch --fuzz=0 -d poppler-26.10.0 -p1 < poppler-disable-jbig2.patch
# Text extraction never consumes raster pixels. Exclude every optional image
# decoder and compile out the legacy JBIG2 decoder so malformed images cannot
# reach those parsers in the fallback.
# Fontconfig links Expat dynamically. Pin the current security release, not
# the older Debian library; install only its library in the runtime closure.
RUN curl -fL https://github.com/libexpat/libexpat/releases/download/R_2_9_0/expat-2.9.0.tar.xz -o expat.tar.xz && echo '1e6371862cc31999b368c3b89b49994f0677e1bab5f1b2b85ae3741f5d803051  expat.tar.xz' | sha256sum -c - && tar -xJf expat.tar.xz
# Backport the small published upstream security fixes to current releases.
COPY native/patches/ /build/patches/
RUN curl -fL https://download.savannah.gnu.org/releases/freetype/freetype-2.14.3.tar.xz -o freetype.tar.xz && echo '36bc4f1cc413335368ee656c42afca65c5a3987e8768cc28cf11ba775e785a5f  freetype.tar.xz' | sha256sum -c - && echo '42ca9cdf2da27ac0f5054bc96bf08b122e96f25116372712b0e37bd3ec350d89  patches/freetype-f3ca71c.patch' | sha256sum -c - && tar -xJf freetype.tar.xz && patch --fuzz=0 -d freetype-2.14.3 -p1 < patches/freetype-f3ca71c.patch
RUN curl -fL https://zlib.net/zlib-1.3.2.tar.xz -o zlib.tar.xz && echo 'd7a0654783a4da529d1bb793b7ad9c3318020af77667bcae35f95d0e42a792f3  zlib.tar.xz' | sha256sum -c - && echo '110ff14375733173d8aa54574473424fbd7dfe4b81f1ca34a759c6fe14b15b14  patches/zlib-df84af2.patch' | sha256sum -c - && tar -xJf zlib.tar.xz && patch --fuzz=0 -d zlib-1.3.2 -p1 < patches/zlib-df84af2.patch
# Build the primary parser from pinned source so its bundled libraries receive
# the same upstream security fixes. Depot tools and compilers stay in this stage.
FROM native-source AS pdfium-fetch
RUN apt-get update && apt-get install -y --no-install-recommends git python3
ENV DEPOT_TOOLS_UPDATE=0 DEPOT_TOOLS_METRICS=0 VPYTHON_BYPASS=manually-managed-python
RUN git clone --no-checkout https://chromium.googlesource.com/chromium/tools/depot_tools.git /depot_tools && git -C /depot_tools checkout 145c00c4349ced164f1a31e2d3f0733139d35c01
ENV PATH=/depot_tools:$PATH
WORKDIR /source
COPY native/pdfium.gclient .gclient
RUN git init pdfium && git -C pdfium remote add origin https://pdfium.googlesource.com/pdfium.git && git -C pdfium fetch --depth=1 origin 2fd6cff57d9412cc42ef1a7e4e0a59b13a1e7cec && git -C pdfium checkout FETCH_HEAD && echo 'c3ffebb7e0f0674b40acf416c4ec3e3c0d390da7a93478bf13f4a6ac0fe2af1c  /build/patches/pdfium-disable-raster-codecs.patch' | sha256sum -c - && patch --fuzz=0 -d pdfium -p1 < /build/patches/pdfium-no-remote-build.patch && patch --fuzz=0 -d pdfium -p1 < /build/patches/pdfium-disable-raster-codecs.patch
RUN gclient sync --no-history --shallow --nohooks
RUN gclient runhooks
ENV PATH=/usr/bin:/bin:/depot_tools
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS native-musl
RUN apk add --no-cache build-base linux-headers python3 cmake ninja pkgconf patch ca-certificates gn clang lld libc++-dev llvm-libunwind-dev compiler-rt fontconfig-dev freetype-dev zlib-dev expat-dev font-dejavu
COPY --from=native-source /build/poppler-26.10.0 /build/poppler
COPY --from=native-source /build/expat-2.9.0 /build/expat
COPY --from=native-source /build/freetype-2.14.3 /build/freetype
COPY --from=native-source /build/zlib-1.3.2 /build/zlib
RUN cmake -S /build/poppler -B /out/poppler -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/poppler -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_RPATH=/opt/poppler/lib -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_FLAGS='--rtlib=compiler-rt --unwindlib=libunwind -stdlib=libc++ -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now,-z,noexecstack' -DENABLE_CPP=ON -DENABLE_UTILS=OFF -DENABLE_GLIB=OFF -DENABLE_GOBJECT_INTROSPECTION=OFF -DENABLE_QT5=OFF -DENABLE_QT6=OFF -DENABLE_NSS3=OFF -DENABLE_GPGME=OFF -DENABLE_LIBCURL=OFF -DENABLE_LIBTIFF=OFF -DENABLE_LCMS=OFF -DENABLE_BOOST=OFF -DENABLE_HARFBUZZ=OFF -DENABLE_BROTLI=OFF -DENABLE_LIBOPENJPEG=OFF -DENABLE_LIBJPEG=OFF -DBUILD_MANUAL_TESTS=OFF -DBUILD_CPP_TESTS=OFF -DBUILD_GTK_TESTS=OFF -DBUILD_QT5_TESTS=OFF -DBUILD_QT6_TESTS=OFF -DCMAKE_DISABLE_FIND_PACKAGE_Cairo=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_PNG=TRUE
RUN cmake --build /out/poppler --parallel 2 && cmake --install /out/poppler
RUN cmake -S /build/expat -B /out/expat -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/expat -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS='--rtlib=compiler-rt -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now,-z,noexecstack' -DEXPAT_BUILD_TOOLS=OFF -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_DOCS=OFF && cmake --build /out/expat --parallel 2 && cmake --install /out/expat
RUN cmake -S /build/freetype -B /out/freetype -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/freetype -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS='--rtlib=compiler-rt -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now,-z,noexecstack' -DBUILD_SHARED_LIBS=ON -DFT_DISABLE_BZIP2=ON -DFT_DISABLE_PNG=ON -DFT_DISABLE_HARFBUZZ=ON -DFT_DISABLE_BROTLI=ON && cmake --build /out/freetype --parallel 2 && cmake --install /out/freetype
RUN cmake -S /build/zlib -B /out/zlib -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/zlib -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS='--rtlib=compiler-rt -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now,-z,noexecstack' -DZLIB_BUILD_TESTING=OFF -DZLIB_BUILD_STATIC=OFF && cmake --build /out/zlib --parallel 2 && cmake --install /out/zlib
COPY --from=native-source /build/patches/ /build/patches/

FROM native-musl AS pdfium-build
COPY --from=pdfium-fetch /source/pdfium /source/pdfium
COPY native/pdfium-musl-args.gn /source/pdfium/out/Musl/args.gn
COPY native/pdfium-musl-toolchain.gn /source/pdfium/build/toolchain/linux/local_musl/BUILD.gn
COPY native/patches/pdfium-musl-build.patch /build/patches/pdfium-musl-build.patch
RUN echo '0907bee72c60439639ca454cf5bd86e14be21e953511a7c1fb77e8eda4765bfc  /build/patches/pdfium-musl-build.patch' | sha256sum -c - && patch --fuzz=0 -d /source/pdfium/build -p1 < /build/patches/pdfium-musl-build.patch
WORKDIR /source/pdfium
RUN patch --fuzz=0 -d third_party/freetype/src -p1 < /build/patches/freetype-f3ca71c.patch && patch --fuzz=0 -d third_party/zlib -p1 < /build/patches/zlib-df84af2.patch
RUN gn gen out/Musl --script-executable=/usr/bin/python3 --fail-on-unused-args && ninja -C out/Musl -j4 pdfium

FROM pdfium-build AS native-workers
COPY native/worker.cc native/warmup.inc /build/
RUN clang++ -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -std=c++23 -stdlib=libc++ -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE -fPIE -pie -Wl,-z,relro,-z,now,-z,noexecstack,--gc-sections -include signal.h -DPDFIUM /build/worker.cc -I/source/pdfium/public /source/pdfium/out/Musl/obj/libpdfium.a -ldl -pthread -o /pdfium-worker
RUN clang++ -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -std=c++23 -stdlib=libc++ -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE -fPIE -pie -Wl,-z,relro,-z,now,-z,noexecstack -include signal.h /build/worker.cc -I/opt/poppler/include -L/opt/poppler/lib -lpoppler-cpp -lfontconfig -Wl,-rpath,/opt/poppler/lib -o /poppler-worker
RUN clang++ -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -std=c++23 -stdlib=libc++ -O2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now,-z,noexecstack,--gc-sections -include signal.h -include fcntl.h -DPDFIUM -DPDF_WORKER_TEST /build/worker.cc -I/source/pdfium/public /source/pdfium/out/Musl/obj/libpdfium.a -ldl -pthread -o /worker-test

RUN strip /pdfium-worker /poppler-worker /worker-test && python3 -c "from pathlib import Path; data = Path('/pdfium-worker').read_bytes(); markers = (b'opj_setup_decoder', b'opj_j2k_read_tlm', b'OpenJpeg only supports', b'CJBig2_Image', b'JBig2_GRDProc'); assert not any(marker in data for marker in markers), 'disabled bundled raster decoder remains in runtime binary'"
RUN apk add --no-cache git
COPY native/pdfium-provenance.py /build/
RUN python3 /build/pdfium-provenance.py > /pdfium-provenance.json

FROM native-workers AS runtime-files
COPY --from=go-build /server /app/server
COPY --from=native-workers /pdfium-worker /app/pdfium-worker
COPY --from=native-workers /poppler-worker /app/poppler-worker
COPY --from=native-source /build/pdfium/LICENSE /opt/pdfium/LICENSE
COPY --from=native-source /build/pdfium/licenses/ /opt/pdfium/licenses/
COPY --from=native-source /build/pdfium/VERSION /opt/pdfium/VERSION
COPY --from=native-workers /source/pdfium/out/Musl/args.gn /opt/pdfium/args.gn
COPY --from=native-workers /pdfium-provenance.json /opt/pdfium/provenance.json
COPY --from=native-source /build/poppler-26.10.0/COPYING /opt/poppler/COPYING
COPY --from=native-source /build/poppler-26.10.0/COPYING3 /opt/poppler/COPYING3
COPY --from=native-source /build/expat-2.9.0/COPYING /opt/expat/COPYING
COPY --from=native-source /build/expat-2.9.0/Changes /opt/expat/Changes
COPY --from=native-source /build/freetype-2.14.3/docs/FTL.TXT /opt/freetype/FTL.TXT
COPY --from=native-source /build/freetype-2.14.3/docs/GPLv2.TXT /opt/freetype/GPLv2.TXT
COPY --from=native-source /build/freetype-2.14.3/LICENSE.TXT /opt/freetype/LICENSE.TXT
COPY --from=native-source /build/zlib-1.3.2/LICENSE /opt/zlib/LICENSE
COPY native/licenses/ /usr/share/licenses/
COPY native/patches/ /usr/share/agent-pdf/patches/
RUN fc-cache -f
COPY scripts/runtime-rootfs.py /build-runtime.py
RUN python3 /build-runtime.py

FROM scratch AS runtime
COPY --from=runtime-files /rootfs/ /
USER 10001:10001
ENV PORT=8080 WORKER_DIR=/app
EXPOSE 8080
ENTRYPOINT ["/app/server"]

FROM go-build AS private-check-build
COPY cmd/private-edge-check ./cmd/private-edge-check
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /private-edge-check ./cmd/private-edge-check

FROM runtime AS private-edge-check
COPY --from=private-check-build /private-edge-check /validation/private-edge-check
ENTRYPOINT ["/validation/private-edge-check", "-run-server"]

FROM native-workers AS sandbox-test
COPY native/runtime-check.cc /build/
RUN clang++ -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -std=c++23 -stdlib=libc++ -O2 /build/runtime-check.cc -I/opt/expat/include -I/opt/freetype/include/freetype2 -I/opt/zlib/include -L/opt/expat/lib -L/opt/freetype/lib -L/opt/zlib/lib -lexpat -lfreetype -lz -o /runtime-check
USER 10001:10001
ENTRYPOINT ["/worker-test"]

FROM runtime-files AS trace
USER root
RUN apk add --no-cache strace
USER 10001:10001
ENTRYPOINT ["/usr/bin/strace", "-f", "-qq"]
FROM go-build AS test-build
COPY cmd/native-test ./cmd/native-test
COPY testdata /testdata
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o /parser.test ./internal/parser && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o /server.test ./internal/server && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o /supervisor.test ./cmd/server && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o /native-test ./cmd/native-test

FROM scratch AS context-audit
COPY . /context

FROM runtime AS integration-test
COPY --from=test-build /native-test /app/native-test
COPY --from=test-build /native-test /cascade/document-error/pdfium-worker
COPY --from=test-build /native-test /cascade/empty/pdfium-worker
COPY --from=test-build /native-test /cascade/invalid-output/pdfium-worker
COPY --from=test-build /native-test /cascade/timeout/pdfium-worker
COPY --from=test-build /native-test /cascade/setup-failed/pdfium-worker
COPY --from=test-build /native-test /cascade/password-required/pdfium-worker
COPY --from=runtime /app/poppler-worker /cascade/document-error/poppler-worker
COPY --from=runtime /app/poppler-worker /cascade/empty/poppler-worker
COPY --from=runtime /app/poppler-worker /cascade/invalid-output/poppler-worker
COPY --from=runtime /app/poppler-worker /cascade/timeout/poppler-worker
COPY --from=runtime /app/poppler-worker /cascade/setup-failed/poppler-worker
COPY --from=runtime /app/poppler-worker /cascade/password-required/poppler-worker
COPY --from=test-build /parser.test /app/parser.test
COPY --from=test-build /server.test /app/server.test
COPY --from=test-build /supervisor.test /app/supervisor.test
COPY --from=native-workers /worker-test /app/worker-test
COPY --from=sandbox-test /runtime-check /app/runtime-check
COPY testdata /testdata
ENV PDF_NATIVE_TEST=1
ENTRYPOINT ["/app/native-test"]
