#!/bin/sh
# Synthetic Linux-only feasibility tests. No AWS credentials, real websites,
# settlement, published image or deployment are involved.
set -eu
cd "$(dirname "$0")/.."
mkdir -p build/browser-probe
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o build/browser-bench ./cmd/browser-bench
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -tags lambda.norpc -ldflags='-s -w' -o build/browser-probe/bootstrap ./cmd/browser-probe
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o build/htmltool-browser.test ./internal/htmlrender
# Docker's default seccomp profile denies user namespaces. Use the pinned
# upstream browser-testing profile, plus chroot inside Chromium's user namespace.
# This is a LOCAL container policy, not a policy Lambda lets us configure.
python3 - <<'PY'
import hashlib,json,urllib.request
commit='41e6a18b3bfc57f566e3cb0829f23a7a5eaad21b'
base='https://raw.githubusercontent.com/microsoft/playwright/'+commit+'/'
wire=urllib.request.urlopen(base+'utils/docker/seccomp_profile.json',timeout=20).read()
if hashlib.sha256(wire).hexdigest()!='cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849':
    raise SystemExit('Unexpected upstream test profile')
profile=json.loads(wire)
profile['syscalls'].append({'names':['chroot'],'action':'SCMP_ACT_ALLOW','args':[],'includes':{},'excludes':{}})
with open('build/browser-seccomp.json','w') as out: json.dump(profile,out)
with open('build/browser-seccomp-LICENSE','wb') as out: out.write(urllib.request.urlopen(base+'LICENSE',timeout=20).read())
PY
docker build --provenance=false --platform linux/arm64 -q -f Dockerfile.browser --target benchmark -t utils-bot-browser-bench:local .
# Private operator builds can inherit umask 077. Lambda uses an arbitrary
# unprivileged UID, so the image must override owner-only host executable modes.
chmod 0700 build/browser-probe/bootstrap
docker build --provenance=false --platform linux/arm64 -q -f Dockerfile.browser --target probe -t utils-bot-browser-probe:local .
docker run --name "utils-browser-permissions-$$" --network none --user 20000:20000 --read-only --cap-drop ALL --security-opt no-new-privileges --security-opt seccomp=build/browser-seccomp.json --entrypoint /opt/utils/browser-launch utils-bot-browser-probe:local --probe
# The native launcher must deny Internet sockets even on a connected container.
# The probe creates sockets only; it never connects to any address.
docker run --name "utils-browser-probe-$$" --cap-drop ALL --security-opt no-new-privileges --security-opt seccomp=build/browser-seccomp.json --read-only --tmpfs /tmp:rw,noexec,nosuid,size=512m --memory 1g --cpus 1 --pids-limit 192 --entrypoint /opt/utils/browser-launch utils-bot-browser-bench:local /opt/utils/browser-bench -socket-probe
docker run --name "utils-browser-tests-$$" --network none --cap-drop ALL --security-opt no-new-privileges --security-opt seccomp=build/browser-seccomp.json --read-only --tmpfs /tmp:rw,noexec,nosuid,size=512m --memory 1g --cpus 1 --pids-limit 192 --shm-size 128m --mount "type=bind,src=$(pwd)/build/htmltool-browser.test,dst=/opt/utils/htmltool.test,readonly" -e UTILS_BROWSER_TEST=1 --entrypoint /opt/utils/htmltool.test utils-bot-browser-bench:local -test.run TestSandboxedBrowser -test.v
docker run --name "utils-browser-bench-$$" --network none --cap-drop ALL --security-opt no-new-privileges --security-opt seccomp=build/browser-seccomp.json --read-only --tmpfs /tmp:rw,noexec,nosuid,size=512m --memory 1g --cpus 1 --pids-limit 192 --shm-size 128m utils-bot-browser-bench:local -n "${BROWSER_BENCH_SAMPLES:-10}"
