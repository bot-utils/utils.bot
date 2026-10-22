# CSV tools: specification and local prototype

**Status:** Local, unpaid prototype. The original three-operation contract was
agreed with Product Owner; transform was added to the eventual CSV release scope
by the owner and its fixed-operation scope was reviewed with Product Owner.
These endpoints are not deployed or advertised by utils.bot.
The released PDF and URL tools are unaffected. No LLM interprets requests.

## Why an agent would call this

An agent with authorized file attachments and HTTPS can replace repeated CSV
scripts, dependency setup, local memory use and untrusted-file handling with one
bounded operation. Keeping file bytes outside model context and returning selected
rows or aggregates can reduce context use. Small dedupe jobs already supported by
the caller's environment may have little paid value. Benefit must exceed discovery,
upload, payment, latency and retry overhead. Synthetic examples demonstrate
feasibility; they do not establish demand or token savings for a particular model.

The caller chooses the operation, columns and enums. The service never interprets
instructions, executes SQL/code/formulas, infers types or fetches URLs. Files are
untrusted data. Response strings may contain hostile instructions or formula-like
text; callers must treat them as data, including when subsequently exporting to
a spreadsheet. JSON output does not sanitize a later spreadsheet export.

## Common request and response

Each endpoint accepts `POST multipart/form-data` with exactly one `options` part
containing a JSON object and the raw CSV parts listed below. Filenames are ignored.
Unknown or duplicate parts/JSON keys, case-mismatched field names, null values,
trailing JSON and content transfer encodings are rejected. No compression,
base64 upload field, source URL, server path or retained dataset handle is accepted. MIME epilogue after the final multipart boundary is accepted and discarded; it counts toward the total HTTP body limit and is never passed to the worker.

Successful responses are `application/json`, containing string cells only:

```json
{"operation":"aggregate","columns":["total"],"rows":[["0.3"]],"input_rows":{"file":2},"output_rows":1}
```

Columns define row positions. Metric cells, including count_rows, are strings;
input_rows and output_rows are bounded JSON integer metadata. This preserves
decimal precision across clients. No hashes, filenames, upload IDs, source
rows in errors, persisted results or partial successful results are returned.
Errors have one fixed code, e.g. `{"error":"invalid_columns"}`. A result is fully
validated and bounded before sending its body; a network interruption can still
truncate delivery, so callers must require a complete successful JSON response.

| Bound | Limit |
| --- | --- |
| Raw CSV file | 8 MiB each; 50,000 data rows; 128 columns |
| Header / cell | 256 / 16,384 UTF-8 bytes |
| Options / total HTTP body | 32 KiB / 16 MiB + 96 KiB |
| Output | 8 MiB serialized JSON and 50,000 rows |
| Aggregate groups | 10,000 |
| Worker | 512 MiB, no swap beyond that, 1 CPU, 30-second wall deadline |
| Local admission | 1 job; at most 8 open connections |

CSV must be valid UTF-8 without BOM or NUL, comma-delimited with a required,
unique, nonempty header row. Fields follow Go `encoding/csv` strict quoting rules.
Records must match header width. LF and CRLF are accepted; CRLF becomes LF,
including inside quoted fields. Blank physical lines are ignored. Quoted empty
cells are data. Empty strings are literal values; there are no implicit nulls,
trimming, case folding, dates or numeric coercion for keys. Key comparison is exact
equality of decoded strings. Spaces and leading zeros are significant.

## POST /csv/dedupe

Parts: `options`, `file`.

```json
{"key_columns":["customer_id"],"keep":"last"}
```

`key_columns` is 1–8 distinct existing column names. `keep` is required: `first`
or `last`. All source columns are returned. Selected rows remain in their selected
source-position order. For keys A, B, A, keeping last returns B, A. A header-only
file returns zero rows.

## POST /csv/join

Parts: `options`, `left`, `right`.

```json
{"left_key_columns":["customer_id"],"right_key_columns":["id"],"type":"left","right_prefix":"right_"}
```

Both key lists contain 1–8 distinct existing names and have equal length. Composite
keys pair columns by list position. `type` is required:

| Type | Result |
| --- | --- |
| `inner` | One row per matching left/right pair |
| `left` | Matching pairs, plus unmatched left rows with empty right fields |
| `semi` | Each matching left row once, left columns only |
| `anti` | Each unmatched left row once, left columns only |

Rows follow left input order, then right input order within each left row.
Duplicate keys deliberately expand inner/left results; more than 50,000 matching
pairs or output rows fails atomically. Semi/anti do not enumerate pairs.

Inner/left output contains all left columns followed by right non-key columns.
`right_prefix` is optional (default `right_`); it applies only to right names
that collide with a left name. Any remaining output-name collision is rejected.
Right key columns are omitted even if they have different names. The 128-column
limit applies per input; joined output may have up to 255 columns. Unmatched
padding and an actual empty right cell both appear as `""`; choose inner/semi/anti
if the caller must avoid that ambiguity. Empty keys match other empty keys.

## POST /csv/aggregate

Parts: `options`, `file`.

```json
{"group_columns":["region"],"metrics":[{"name":"orders","op":"count_rows"},{"name":"revenue","op":"sum","column":"amount"}]}
```

`group_columns` contains 0–4 distinct existing names; omission means no groups
(one grand total). `metrics` contains 1–8 objects. Each requires a unique nonempty
`name` (at most 256 UTF-8 bytes), distinct from grouping columns, and an `op`:

| Op | Column | Semantics |
| --- | --- | --- |
| `count_rows` | Forbidden | All rows, including rows with empty cells |
| `sum` | Required | Exact decimal total |
| `min`, `max` | Required | Exact numeric minimum/maximum |

Numeric cells accept `[+-]digits` optionally followed by `.` and one or more
digits: at most 38 total digits, at most 18 fractional digits. Empty strings,
whitespace, exponent notation, NaN and Infinity are invalid. No rows are skipped.
Arithmetic uses scaled integers, never binary floating point. Canonical output
has no exponent, unnecessary zeros, trailing dot or negative zero. Exact sums
may widen to 43 digits with scale at most 18; a result requiring more precision
is rejected. Grouping columns precede metrics; groups follow first appearance.

Header-only input with grouping returns zero rows. Without grouping it returns
one row: count `"0"`, sum `"0"`, min/max `""` meaning no observation.

## POST /csv/transform

Parts: `options`, `file`. Transform is prepared for the eventual CSV release;
the HTTP prototype keeps the common small-file limits above. A separate synthetic
streaming validation path reuses the same Go transformation logic and has passed
1 GiB cases on ARM Fargate. The customer upload/job/payment path is not deployed.

```json
{"column":"email","op":"lower"}
```

Choose one existing, uniquely named column and exactly one operation. All source
columns and rows are returned in their original order, including empty cells.
Headers and every other column are unchanged. Header-only input returns zero rows.
There is no sequence of operations, inferred instruction or implicit type conversion.

| Op | Exact behavior | Extra fields |
| --- | --- | --- |
| `trim` | Remove leading/trailing Unicode White_Space; preserve internal whitespace | Forbidden |
| `lower` | Locale-independent Unicode simple lowercase mapping | Forbidden |
| `upper` | Locale-independent Unicode simple uppercase mapping | Forbidden |
| `replace` | Case-sensitive literal replacement of every nonoverlapping match, left to right | Required `old` and `new` strings |

```json
{"column":"status","op":"replace","old":"pending","new":"queued"}
```

Unicode behavior is pinned to version **15.0.0**. Trim removes U+0009–000D,
0020, 0085, 00A0, 1680, 2000–200A, 2028, 2029, 202F, 205F and 3000.
Zero-width space U+200B and BOM U+FEFF within a cell are preserved. Casing has
no locale/context rules, normalization or multi-character expansion: `ß` remains
`ß` under upper, and `Σ` becomes `σ` under lower. A Unicode-table upgrade requires
review; a mismatched worker returns `transform_unavailable` rather than silently
changing semantics.

Both replacement strings are limited to 1,024 UTF-8 bytes; `old` must be nonempty,
while empty `new` deletes matches. NUL is forbidden. Replacement text is literal:
`$1`, backslashes, formulas and instructions are data; inserted text is not
searched again. Regex, SQL, code, URLs, expressions and extra fields are rejected.

The 16,384-byte cell cap also applies after transformation, including UTF-8 case
expansion. Replacement expansion is checked before allocating it. The common
serialized-output byte and row caps apply to the complete result. Any row or
output failure returns only a fixed error, with no partial result. Existing
network-disabled worker, deadline, memory, cleanup and content-free logging rules
apply. Transform does not make hostile text safe for a model or spreadsheet.

## Streaming transform validation

`internal/tabular/stream_transform.go` processes one record at a time and shares
compiled options and cell transformations with the request-sized implementation.
It bounds raw fields/records before the CSV decoder allocates them. Input, rows,
logical output and encoded output have independent limits; callers must use
private staging and discard partial bytes on any error.

`cmd/csv-transform-trial/` is a synthetic-only validation binary, not a customer
API. Its fixed golden Unicode cases include quoted newlines, empty cells, formula
and instruction text, and unchanged columns. It stages deterministic gzip bytes,
closes and syncs the encoder, independently checks the entire decompressed
artifact, then renames the private staged result. It emits only bounded synthetic
metrics. The selected ARM worker installs a process-wide Linux filter before
reading data: sockets, io_uring, process execution/spawn and foreign descriptor
acquisition are denied. This is defense in depth, not an arbitrary-code execution
service or proof of the future credential-bearing transfer boundary.

The local driver is `benchmarks/transform_local.py`; the separately leased cloud
driver is `benchmarks/transform_control.py`. The old three-operation comparison
and its ledger remain unchanged. All four operations passed synthetic 1 GiB ARM
Fargate cases with byte-identical local/reference results; processing took 17–26
seconds, excluding startup, fixture generation, independent verification and
transfers. Fargate isolation, late expansion/output caps, OOM and cancellation
were checked. Real ENOSPC passed locally in a small private tmpfs. The first
cloud filesystem-full setup failed unverified and remains in its original ledger;
a fresh cloud cohort passed explicitly injected ENOSPC handling. Physical
exhaustion of the main Fargate disk is not claimed. No test fills the main task
or host filesystem. Public release still requires upload/resume, durable jobs,
payment/retrieval, pricing, monitoring and the shared production worker review.

## Errors

| HTTP | Meaning / example codes |
| --- | --- |
| 400 | Malformed request/CSV/options: `invalid_csv`, `invalid_options`, `invalid_parts` |
| 413 | Size, rows, groups or expansion bound: `file_limit`, `join_pair_limit`, `worker_memory_limit` |
| 422 | Invalid operation/schema/data or decimal precision: `invalid_columns`, `invalid_decimal`, `decimal_range`, `invalid_transform`, `output_column_collision` |
| 429 | Local job already admitted: `capacity_unavailable` with Retry-After |
| 503 | Missing worker image/runtime, invalid worker reply or unconfirmed cleanup |
| 504 | Worker deadline reached: `worker_timeout` |

The local server also uses 403 for nonlocal/browser-origin requests, 404 for
unknown routes, 405 for non-POST operations, 415 for unsupported encoding/media,
and 408 when a cancelled request can still receive a response. Parser messages
never echo content. Exact error code spellings are implemented in `internal`.

## Security and privacy design

The local supervisor binds only to a literal loopback address, rejects browser
Origin headers and nonloopback Host values, disables caching and bounds body,
header, connection and read durations. Multipart data remains in memory and is
never handed to a disk-spilling form parser. One job runs at a time.

Every job uses a disposable scratch-image container: nonroot UID 65532,
read-only root filesystem, no network or IPC/shared-memory mount, no host/source/socket mounts, no credentials,
all capabilities dropped, no-new-privileges, 64 PIDs and core dumps disabled.
Only fixed Go runtime variables and `PATH=/nonexistent` are supplied. Images must already
exist locally, are pinned to an inspected image ID, and cannot add other environment,
volumes, alternate commands or entrypoints. Workers never receive Docker access.
The host supervisor's Docker access is a local trusted-operator boundary; this
is not yet a production isolation architecture or a public authenticated service.

Worker stdout is a bounded result pipe, stderr is discarded and Docker logging
is disabled. Request logs contain only fixed operation/status/error and duration
bucket fields plus standard time/level/message. Contents, headers, names, keys,
values and correlation hashes are absent. This is application-level ephemerality,
not a promise of cryptographic RAM erasure: host swap, crash capture and Docker
operator access require separate production controls and a disclosed policy.

On success, rejection, timeout, cancellation or OOM, the supervisor kills any
remaining owned worker and prunes only stopped containers with both its prototype
label and unique job label. Cleanup is verified independently; unconfirmed cleanup
fails the request and quarantines the supervisor against further jobs; health
also fails. An operator must reconcile remaining workers before restarting it.
Cleanup has a separate bounded grace period after the worker
deadline. No customer bytes are placed in container configuration or commands.

## Run locally

Requires Go 1.26.10 and a local Docker daemon (Docker Desktop or the default Colima VM on this arm64 Mac). The supervisor rejects `DOCKER_HOST` and `DOCKER_CONTEXT` overrides, verifies that the selected context uses `/var/run/docker.sock`, `~/.docker/run/docker.sock`, or `~/.colima/default/docker.sock`, and pins every job command (including cleanup) to that local socket. Remote Docker contexts are unsupported. A trusted local operator controls the daemon and socket; this does not protect against an operator deliberately forwarding that socket elsewhere. No new dependencies,
network image pulls, production configuration, IAM, payment or funded settlement.

```sh
sh scripts/build.sh
./build/csv-prototype
# In another terminal:
python3 scripts/demo.py
go test -race ./...
go vet ./...
CSV_DOCKER_TESTS=1 go test -race ./internal/api -run Docker -v
go test ./internal/tabular -run '^$' -bench . -benchtime=3x -benchmem
```

The build uses a minimal context containing only the compiled worker and Dockerfile.
The demo generates synthetic data in memory and exercises all four real HTTP
endpoints, including a 50,000-row aggregate; it prints responses and byte reduction.
Docker integration tests verify real nonroot/network/read-only/cgroup controls,
absence of inherited canary credentials, exact arithmetic, cleanup, cancellation,
deadlines and a deliberate worker OOM. Probe commands are local test modes and
cannot be selected by HTTP requests. Stop the supervisor with Ctrl-C.

## Release and Parquet gates

The table operations are separated from CSV decoding so the semantics can be
reused. Parquet still needs a bounded decoder and explicit types/nulls, compressed
and decoded-size caps, dictionary/nesting limits and decimal/key compatibility.
It is deferred, rather than advertised as an implemented copy.

Before public release: validate an actual restricted agent's raw attachment and
payment flow without file bytes in model arguments; benchmark realistic jobs
against its existing tools with latency, peak memory, task success and total cost;
demonstrate repeat demand and margin; review cloud isolation, abuse controls,
privacy and recovery; and integrate the existing payment contract without extra
charges on uncertain retries. Local byte reduction is only one feasibility metric.

Optional fixed-schema synthetic backend diagnostics and pinned-rate cost calculations are in [benchmarks](benchmarks/). They are separate from the HTTP prototype. Their cloud controller accepts only the fixed synthetic trial plan and requires operator-provisioned resources.

The cloud smoke runner uses only fixed synthetic 1 MiB inputs and checks dedupe,
join and aggregate against an independent oracle. A dependency-free wheel lets
Glue run the same sources without downloading packages. The runtime request
builder defines four separate Fargate tiers and two Glue tiers in the isolated
trial network, with private storage and no credentials in a Fargate task role.
The request builder does not provision resources. A separate operator-only controller can dispatch the six fixed smoke tiers after fresh live admission.

The worker supervisor bounds execution to 15 minutes and discards worker stderr.
It emits only validated metrics, source hashes and a synthetic-workload label.
Scratch uses disposable provider storage; terminal job state must be confirmed
separately. A passing worker does not prove cloud cleanup, billing, large-file
capacity or production isolation. Glue still has a service identity. The controller records the full cost reservation and a one-time S3 lease before
its first dispatch, then records each submission before calling the provider. It
runs one job at a time, observes terminal state and validates metrics before the
next job. Uncertain starts stop dispatch and trigger owned-worker reconciliation;
there is no automatic lease takeover or retry. Runtime IAM and network drift
checks run before every job. These are controller bounds, not an AWS-enforced
spending cap. Provider cleanup and paid endpoint removal still need independent
verification; the S3 replay record and zero-cost task-definition metadata can
remain after the trial. Existing shared log-group settings are
preserved. No CSV routes are publicly released by this benchmark preparation.

The regional S3 alias `s3-r-w.us-east-2.amazonaws.com` is explicitly allowed
for AWS's CNAME chain; other external names remain blocked. A startup DNS failure
still consumes one attempt. An explicit operator recovery path accepts only the
first known stopped ARM-small DNS failure with matching task evidence and a
reviewed source revision. It retains the same S3 lease and full reservation and
runs only the five unattempted tiers. It cannot retry that tier, reset the count
or resume an uncertain submission.

Glue can retain its network interface for several minutes after a successful
job. The trial waits up to ten minutes for release. If that wait ends early,
operator review can accept the already validated Glue-small result only after
fresh phase-one network checks confirm cleanup, preserving its original
provider evidence and all five attempt records. Only the last unattempted
Glue-large tier may then run; no job or reservation is reset.
