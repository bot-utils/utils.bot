# Source review guide

This repository contains the service's Go request handler and payment code,
native PDF/browser worker sources, build configuration, and tests. It implements
PDF text extraction, URL-to-Markdown conversion and x402 payment handling.
The API description and locally served documentation assets are in
`internal/docs/`.

The public service and API reference are at https://utils.bot/ and
https://utils.bot/docs. This is a source snapshot for inspection; it contains
no production credentials, customer documents or deployment records.

## Transparency

Inspect the code behind your request in [this repository](https://github.com/bot-utils/utils.bot).
Review processing, payment checks and parser isolation alongside the service's
privacy and security descriptions. We publish the source for scrutiny, with all
rights reserved in original application code and third-party licenses preserved.

## Repository contents

- `cmd/server/` and `internal/` contain the receiver and shared packages.
- `cmd/payment/` contains the payment handler.
- `native/` contains worker source, build configuration, and patches.
- `Dockerfile` describes the native and application builds.
- `internal/staticsite/`, `cmd/sitebuild/` and `cmd/edgeconfig/` generate the
  static website and its edge routing from the same service contract.
- `testdata/` contains test inputs. The fixture signing material is public and
  must never be funded or reused for a real wallet.

The snapshot does not include all operator deployment tooling or production
configuration. Do not treat it as a turnkey deployment, and do not use real
customer documents or credentials as test fixtures.

When infrastructure source is present, the operator-specific temporary
control-plane migration policy is omitted. Its permission test is explicitly
skipped in the published test file; other permission tests remain. Consequently,
the public tests do not validate that private operator policy or its migration.
The included CDK context is an empty starting point; deployment-specific
lookups are excluded and must be supplied or generated for the target account.

## Test layout

The Go version is specified in `go.mod`. Where you have the necessary permission
to execute the relevant code, the application test command is:

```sh
go test ./cmd/... ./internal/...
```

Some native integration checks require the separate build and test environment
described by the Dockerfile. Passing local tests alone does not establish the
security or behavior of a production deployment.

## Rights and third-party components

Original application code and documentation are **all rights reserved**. This
repository is source-visible for transparency; it is not an open-source release
and grants no general software license to the original material. GitHub's
platform viewing and forking rights and applicable legal exceptions remain.
Auditors seeking permission to compile, execute or modify original material
should contact info@utils.bot.

See [COPYRIGHT](COPYRIGHT), [THIRD_PARTY.md](THIRD_PARTY.md), and
[DEPENDENCIES.md](DEPENDENCIES.md). Third-party components and derived portions
retain their own applicable licenses and notices; the all-rights-reserved notice
does not replace or restrict those rights. No compiled binaries or container
images are distributed by this source snapshot.

## URL-to-Markdown implementation

The implementation separates controller/payment code in `internal/htmltool/`
from credential-free source handling in `internal/htmlrender/`. `cmd/html/` is
the ALB controller, `cmd/html-microvm/` is the disposable browser worker and
`cmd/threat-update/` refreshes the fixed-source threat feeds. Build the ARM64
artifacts with `scripts/build-html.sh`; production also requires the release
scan described below. The browser implementation is the public service path.
An optional HTML-only Go worker remains available for isolated integration use;
it is not a second advertised tool.

CDK enables these resources with `PDF_ENABLE_HTML=1 PDF_HTML_JAVASCRIPT=1`.
The independent `PDF_HTML_PUBLIC_ACCESS` switch defaults to zero: the HTML ALB
route then requires the configured owner IPv4 /32 even when PDF is public.
Setting it to one requires protected regional ingress, public Base payments,
and the disposable-browser configuration. The website contract is published
with the public cutover. Ordinary deployments preserve these deployed flags.
Infrastructure source defines the scoped IAM permissions and boundaries;
private operator configuration and deployment credentials are excluded.

Only the controller can invoke the existing payment alias. The browser VM has
no AWS execution role, payment credentials or database permissions. The updater
can write only public threat data and runs hourly. An absent or stale threat
snapshot fails closed. The bucket never stores customer URLs, fetched HTML or
conversion results.

The updater splits the sorted domain-hash index into 256 immutable S3 shards
and publishes a small manifest only after every shard has been written. Workers
read just the shards needed for the URL host and its parent domains; they do not
download the entire threat list. A job pins one generation through redirects,
checks freshness/digests/bounds and fails closed if its data is unavailable.
Old generations expire after three days; a manifest older than 24 hours is
rejected. Nothing is baked into an image or requires hourly code deployments.

Local tests use synthetic destinations and mocked settlement. Private AWS tests
exercise the deployed flow, isolation and cleanup. Neither establishes a
successful funded payment; that requires separate production evidence. The
existing PDF configuration is preserved on HTML deployments.

### JavaScript-rendered URL to Markdown

`internal/browser/` implements a small Go Chrome DevTools pipe client; no Node,
Playwright runtime or additional Go dependency is needed. `Dockerfile.browser`
pins the ARM64 Debian base and Chromium headless-shell package, installs no
recommended packages, keeps compilers in a separate build stage and preserves
Debian's installed package copyright notices. `cmd/html-microvm/` serves
this renderer as a disposable HTTP worker behind the same payment flow. Its image
captures an already-running blank browser and its private pipes, with no customer content. Image validation renders a synthetic page in a separate restored clone so AWS can learn the snapshot working set.

Each attempt starts a fresh disposable VM cloned from that customer-free image. A fresh browser context is created after restore; the snapshotted browser accepts exactly one job and is then closed. There is no pool of customer-used browsers or per-request initialization hook. Chromium's namespace
sandbox stays enabled. A native seccomp launcher additionally denies Internet
sockets, ptrace/process-memory access and io_uring; the browser communicates
with Go through private inherited pipes. Browser environment variables exclude
AWS/payment credentials, and the Go parent disables process dumping/inspection.
Every permitted page/script/stylesheet/fetch request is fulfilled by Go after
URL, threat-list and pinned-public-DNS checks. Caller headers, referrers and
cookies are not forwarded. Frames/workers/downloads/media/fonts/WebSockets and
POST requests are unsupported. Browser documents must be `text/html`. Network
XML media types, including XHTML and SVG, are refused before their bodies reach
Chromium, and script/style MIME sniffing is disabled. This reduces exposure;
JavaScript can still construct XML, and it does not prove all native XML paths
unreachable. Browser diagnostics are discarded to avoid
logging remote URLs or page content. Profiles/results are transient.

Bounds: 48 intercepted requests, 4 MiB per response and serialized DOM, 16 MiB
aggregate source, and up to 4 MiB Markdown sharing a 4 MiB uncompressed JSON
budget with metadata and required escaping. Standard negotiated gzip preserves
larger complete results within the one-MiB ALB envelope; results that cannot fit
are rejected before collection. We wait one additional second after the latest
page-load event, within a 15-second total fetch/render deadline. JavaScript also runs
during page loading. There is no universal render-complete signal; we do not
wait for all background activity or network-idle. Dynamic content can remain
incomplete. The machine-readable endpoint contract includes this timing policy. Infinite scripts,
unsafe destinations and unavailable confinement fail without collecting payment.

Build/test locally with `scripts/test-browser.sh`. It uses synthetic sources,
no-network containers, an additional socket-denial probe, and fresh browser
jobs. Its pinned upstream Docker test seccomp profile is downloaded under
`build/` with its Apache-2.0 license; the runtime does not use Playwright. Local
measurements exclude AWS environment/image initialization, threat lookups,
external network latency and payment confirmation. They are not Lambda cold-start
measurements. All test containers exit; they are retained for inspecting logs.

`PDF_ENABLE_HTML=1 PDF_HTML_JAVASCRIPT=1 PDF_MICROVM_BASE_VERSION=2`
prepares a separate AWS Lambda MicroVM image (512 MiB ARM64 baseline; bounded 512/1,024/2,048 MiB private sizing options),
controller and optional specification contracts. `scripts/build-html.sh` builds
the ARM64 runtime locally and stages its exact exported filesystem. Debian
package repositories use a dated, signature-verified snapshot; native security
overrides and the browser archive also have pinned checksums. AWS only unpacks
the staged filesystem and does not repeat package downloads or compilation.
The managed base version is explicitly pinned and must be available in Ohio.
The HTML-only option retains its tenant-isolated Go ZIP worker. Ordinary builds
omit HTML unless it is explicitly enabled; operator deployments preserve live flags.

Before production synthesis, run `python3 scripts/scan_html_runtime.py` against
the built runtime image. The pinned scanner reads a saved image archive without
a Docker socket or AWS credentials. Production CDK requires a matching fresh
scan, unchanged source/worker/filesystem/policy, and the current stable browser
version. It rejects unreviewed native findings. Explicit dated vendor
classifications are version-specific, expire after 30 days and are reported
separately from actual fixes. Five unpatched resource-exhaustion findings have
owner-authorized residual-risk acceptances in
`native/browser-risk-acceptances.json`: three glibc glob/regex reports, GLib string
hash collisions, and Expat XML CPU exhaustion. These are not patches or proven
code-path exclusions. Each acceptance pins the package and browser versions,
expires after 30 days, and hashes the confinement/limits/lifecycle implementation;
changes require a fresh review. Scan output lists accepted risks separately from
fixed, absent-component and vendor-disputed findings. Expiration blocks a future
release; it does not shut down a deployed service. The remaining risk includes
failed requests and bounded per-job compute costs; many wallets can still cause
aggregate availability/cost pressure. These checks do not certify the AWS-managed host
kernel or guarantee the absence of vulnerabilities. Private mock integration
stacks support rehearsal and are removed after testing.

The browser MicroVM has no AWS execution role, signing secret or database
permission. Its Go entrypoint imports `internal/htmlrender`, separated from
the controller's cloud SDK and payment packages. Threat capabilities are read
with bounded standard-library HTTP requests; the only external Go runtime
module is the maintained HTML tokenizer. A dependency-boundary regression test
prevents cloud/payment imports returning to this process. The controller
supplies the fresh public threat manifest and
short-lived, object-specific read links for its immutable hash shards. Browser
processes receive none of those links; the existing protected Go fetch broker
handles source traffic and threat checks. Only customer-free state is eligible
for image snapshots. Startup/readiness and post-restore hooks must successfully
render a synthetic JavaScript fixture with the security controls enabled. Each
runtime accepts exactly one job, cannot be reset by another lifecycle hook, and
is terminated before settlement. There is no suspend/resume or customer VM
reuse. A service-enforced 45-second maximum lifespan bounds orphaned workers;
controller cleanup runs even after cancellation and verifies termination. An exact
AWS internal-service terminal failure before readiness permits one fresh launch
only after confirmed termination, within the same work deadline. No customer
job, conversion, payment or ambiguous outcome is automatically replayed.

Both the worker and controller validate results: strict bounded JSON, valid
UTF-8, known metadata/error fields, expected URL and renderer, no raw angle
brackets, and no terminal/bidirectional control sequences. Raw HTML is escaped
even inside code fences. Content is never executed, rendered, logged or followed
by the controller. This cannot prove natural-language content harmless; prompt
injection and misleading or dangerous links remain untrusted source data.
Runtime stdout/stderr forwarding is disabled. Sanitized controller summaries
remain the operational log. Build logs contain only code/dependency setup and
synthetic fixture checks, with seven-day retention.

`PDF_MICROVM_PROBE_ONLY=1` stages an independent image in
`AgentPdfMock-MicroVMProbe`. Its worker accepts only `{}` and performs a fixed
in-memory browser check; it has no public API route or customer URL input.
`cmd/microvm-probe/` measures a disposable run including verified termination.
AWS deployment and sandbox compatibility are checked separately from local
HTTP/browser tests; local timings are not an AWS cold-start claim.


### Private Lambda browser probe

`cmd/browser-probe/` accepts only an empty JSON object and renders a fixed,
synthetic JavaScript fixture. It reports only bounded timing/capability fields:
seccomp availability, denied Internet sockets and namespace support. It cannot
accept a customer URL or call the payment provider. The explicit
`PDF_BROWSER_PROBE_ONLY=1` CDK mode prepares a separate temporary stack with one
2,048 MiB ARM64 Lambda, a maximum of two concurrent executions, a fresh tenant
ID required per job, and permission to write only its own seven-day log group.
It creates no ALB route, function URL, schedule, document bucket or always-on
capacity. Its image is the `probe` target in `Dockerfile.browser`; build the
bootstrap from `cmd/browser-probe/` first. Protected IAM foundation maintenance
must be reviewed separately before this new function can be deployed. A local
capability result does not establish what the actual Lambda kernel permits.

An actual ARM64 Ohio Lambda probe on 2026-10-19 returned `EPERM` for
user namespaces, installing the additional seccomp filter, no-new-privileges,
parent-death signaling and protecting the parent process from inspection. Three
fresh tenant IDs reproduced these results. This ordinary Lambda environment
cannot host the hardened browser. Production JavaScript rendering instead uses
the disposable MicroVM design above, which supports the required controls.
The probe diagnoses fixed capability codes without loosening browser launch requirements.
Image executables have explicit permissions independent of the builder's umask;
the local test checks execution access under an arbitrary unprivileged UID.

Application access records preserve bounded request paths and query diagnostics;
recognized sensitive query values are redacted and redaction/truncation is
explicit. Caller IPs, headers, payment proofs and submitted fetch URLs or source
contents are excluded. Viewer `/health` requests through the protected origin have
ordinary access records with zero tool completions; automatic health probes
remain quiet and are counted in the existing five-minute process-health record.
Requests rejected by WAF or a load-balancer fixed response do not reach these
application logs. Raw ALB logging stays disabled because its mandatory fields
include customer data; CloudWatch transformations also retain original events.

## Unreleased CSV source

CSV is not publicly available. The source under `internal/csvcloud/`,
`internal/csvtabular/` and `internal/csvwire/` contains disabled AWS/payment
adapters, a strict tabular engine and an authenticated worker protocol. The
prototype supports dedupe, select, join and a fixed set of column transforms.
The current isolated worker enforces 8 MiB per input and 8 MiB CSV/gzip output;
the upload adapter's 1 GiB bound does not establish processing at that size.

`cmd/csv-private-worker/`, `cmd/csv-private-broker/` and
`cmd/csv-private-verifier/` implement a private synthetic path. Source checks
cover task/image/network bindings, independent signed absence evidence and
bounded recovery. Local tests do not establish deployed AWS permissions,
runtime isolation, deletion propagation or large-file performance. These
components have no enabled public CSV routes and are not a production release.
