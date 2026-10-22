# Local synthetic CSV upload-to-download rehearsal

This is an explicitly enabled, loopback-only, **8 MiB per input** protocol
prototype. It is not the 1 GiB streaming worker, an AWS/S3/DynamoDB/SQS transfer
implementation, a funded payment test, or a customer-ready service. Nothing links
these routes into the public PDF/HTML service. CSV remains unlaunched.

Run `cmd/csv-flow` only with `--enable-synthetic-flow`, an existing absolute 0700
state directory and a separate owned 0600 `--mock-key-file` containing a random
64-hex synthetic key. The prebuilt local Docker image is required. There is no
real wallet, facilitator URL, AWS credential or outbound payment implementation.
The mock signature format is deliberately different from x402.

## Client contract

All JSON is strict: duplicate/unknown/case-mismatched fields, nulls, invalid
Unicode and extra instruction fields fail. The complete JSON envelope is limited
to 32 KiB. Options use the existing four operation schemas. Join defaults and
aggregate grouping defaults are explicit in the canonical private binding.

| Request | Behavior |
| --- | --- |
| `POST /csv/uploads` | Exact operation/options, ordered file slots, positive exact byte counts, full-file SHA256, `put`/`multipart` mode and `delivery:"gzip"`. Without proof: 402 admission challenge; no job or customer content allocation. |
| Repeat admission | Synthetic `Payment-Signature`, 64-hex `Idempotency-Key` and client-generated 256-bit `Recovery-Secret` headers. Verify payer/nonce, then create one intent. Return job ID, secret capability and constrained upload grants. Never settle admission. |
| `PUT /csv/uploads/{id}/parts/{slot}/{part}` | Raw bytes, `application/octet-stream`, `X-Upload-Grant` header. PUT mode has one part; multipart uses 4 MiB parts (local rehearsal choice). Exact declared length; each stored part is immutable. Completion belongs to the controller. |
| `POST /csv/uploads/{id}/grants` | Capability header and `{}`. At most three renewals, no later than original intent expiry. Recovery returns existing grants without renewing them. |
| `POST /csv/uploads/{id}/finalize` | Capability and `{}`. Verify all parts, exact full length and full hash; fence further writes. Mismatch erases staged bytes, never queues or charges. Repeat successful finalize returns the same intent. |
| `POST /csv/dedupe`, `/csv/join`, `/csv/aggregate`, `/csv/transform` | Capability and only `{"job_id":"..."}`. Operation/options belong to the intent; no second options value. Submit once into the durable queue; repeat returns the same job, with 202/Retry-After. |
| `GET /csv/jobs/{id}` | Header capability required. Fixed artifact/financial state, expiry, safe counters and download allowance. No owner or source preview. Only PAID owners receive checksummed result manifest details. |
| `POST /csv/jobs/{id}/payment` | Capability and `{}`. After durable verified result preparation, return a fresh job/result-bound 402 challenge. Resubmit a fresh synthetic proof from the same payer. Persist the unique settlement reservation before calling the mock. |
| `POST /csv/jobs/{id}/reconcile` | Capability and `{}`. Look up that exact reservation; never call settlement again. Unknown outcome grants no result access or replacement proof. |
| `GET /csv/jobs/{id}/result` | PAID, capability, unique 64-hex `Download-Attempt`, and `Accept-Encoding: gzip`. `text/csv` with gzip HTTP encoding. Exact stored gzip, no ranges on this route. |
| `GET /csv/jobs/{id}/result.gz` | Same paid capability and attempt requirement. `application/gzip`, no HTTP content encoding, one compressed-byte Range supported. Save/reassemble the complete file before decoding. |
| `GET /csv/jobs/{id}/downloads/{attempt}` | Capability required; recover reserved byte count and active status after a lost response. Never refunds or authorizes replay of the stream. |
| `HEAD` / conditional GET | PAID and capability still required. HEAD, 304 and invalid range 416 consume zero download bytes. An If-Range mismatch selects the full immutable artifact. |
| `POST /csv/jobs/{id}/ack` | Capability, `complete:true`, exact manifest `version` and `encoded_sha256`. This is the client's assertion of verified complete receipt, not server proof of persistence. Starts deletion; a first/partial GET never does. |
| `DELETE /csv/jobs/{id}` | Capability. Fence work/new writes/streams; relinquish content after worker/stream termination. Does not reverse payment or resolve an unknown outcome. |

The client must keep its idempotency/recovery secrets, proof, job/capability,
part progress and compressed-download progress outside model context. Job IDs
alone authorize nothing. Capabilities, grants and proofs use headers, never query
strings. Neither raw capabilities/recovery secrets nor raw payment proofs are
persisted by the server. Recovery authenticates the original payer/nonce and
protected recovery verifier and reproducibly derives the same capability under
a versioned protected server key, even after the original proof expires. An
expired proof cannot create a new job. Key or nonce reuse cannot create another
intent. Binding drift under an existing key is 409.

## State, clocks and limits

Normal flow:

`UPLOAD_INCOMPLETE/UNPAID -> UPLOAD_VERIFIED/UNPAID -> QUEUED/UNPAID ->
RUNNING/UNPAID -> RESULT_PREPARED/AWAITING_PAYMENT ->
RESULT_PREPARED/SETTLEMENT_PENDING -> RETRIEVABLE/PAID -> DELETING/PAID -> ERASED/PAID`

Ambiguity:

`SETTLEMENT_PENDING -> QUARANTINED/PAYMENT_UNKNOWN ->
RETRIEVABLE/PAID (confirmed in time) OR ERASED/PAYMENT_UNKNOWN (24-hour cap)`

A crash after reservation is unknown, even if it occurred before the provider
call. Never infer unpaid from a missing reply. Reconciliation queries only the
exact provider reservation. A later PAID finding after erasure sets
`remedy_required_if_paid`; there is no recompute, replacement charge or invented
result. The local candidate deliberately permits only one settlement reservation
per job; definitive rejection erases content and does not authorize another proof.
It does not implement the optional second-proof retry from the broader proposal.

- Intent: fixed 30 minutes; grants at most five minutes and never past intent.
- Prepared result: fixed 30 minutes from preparation. New settlement requires at
  least five minutes left. Status, retries, payments and recovery do not extend it.
- Unknown outcome: content quarantined at most 24 hours from the reservation's
  first possible ambiguous outcome. Authoritative PAID before that cap grants
  one 30-minute retrieval window from confirmation; at the exact cap, erasure wins.
- Two content reservations, 32 total metadata records, one worker. Current small
  worker limits remain 8 MiB/file, 50,000 rows and bounded output; no large-file
  support is implied by multipart transport.
- Upload retries consume at most twice the declared input bytes in total.
- One active download/job, two globally, 90-second leases with a 45-second HTTP
  write deadline, at most 128 attempts/job. One shared allowance of three complete
  **compressed** artifacts covers both routes and overlapping/repeated ranges.
  Reserve before headers. Failed/partial/ambiguous transfers keep their full debit.
  Reusing an attempt ID returns 409 and never opens a second stream. Status exposes
  the remaining aggregate allowance; the reservation route recovers each attempt outcome.
- `control.json` and `control.next` are each capped at 46 MiB. The hard aggregate
  is 96 MiB across every owned state file, including old+next+lock. The state
  directory accepts only those three names. Capacity checks include serialized
  base64 expansion before writing; replacement fsyncs the file and directory.
  Input parts and results live inside the bounded snapshot, not additional files.
  The Docker parser uses bounded RAM/pipes and read-only/no-host-mount storage;
  Docker's pre-existing image/runtime storage is outside this application budget.

The derivation key is plaintext inside `control.json`, protected only by local
file permissions and the trusted operator boundary. Snapshot disclosure exposes
both the key and verifiers/content; this prototype provides no cryptographic
verifier confidentiality against snapshot disclosure. This key-storage scheme
must not transfer to production. The client-readable synthetic signing key is a
different key in an owned 0600 file whose resolved path must be outside the state
directory; hard-linked key files and final-component symlinks are rejected.

The local store is synthetic plaintext on a trusted operator disk. Atomic logical
removal from the current snapshot is distinct from physical-media erasure: old
filesystem blocks, caches, host swap and operator backups are not sanitized here.
Do not use this prototype for customer or confidential data. Protected job/payment
metadata, canonical options, private hashes and synthetic payer/nonce identifiers
remain bounded until the operator disposes of the rehearsal state. No 30-day
production retention schedule is selected; field-level privacy approval and a
manual-remedy retention policy are still required before cloud implementation.

## Failure and privacy boundary

Finalize, upload commit, cancellation and expiry serialize under a single
process-owned store lock; epoch/grant checks fence late writers. The queue is the
transactional QUEUED record itself, so duplicate polling/submit never dispatches
a second task. Each worker has a durable token, checked on publication. Restart
with RUNNING state blocks all dispatch/admission as `cleanup_uncertain`; there is
no automatic replacement until an operator independently proves termination.
There is intentionally no automatic quarantine-clearing endpoint.

Before payment the controller verifies immutable inputs again, serializes a
complete deterministic gzip, verifies full decompression including trailer/CRC,
logical/encoded bounds and hashes, and durably publishes an opaque version plus
manifest. Provider/queue/worker responsibilities remain separate; queue and parser
code never settle. Mock payment outcomes are independently durable, allowing
accepted-but-reply-lost and crash-before-paid-write tests across restart.

Telemetry includes only fixed route templates/status/category. Admission quote,
result challenge, malformed/duplicate payment header, invalid signature, verified
proof rejection (owner/binding/expiry), definitive provider rejection, actual provider attempt,
pending settlement, unknown outcome and confirmed PAID are distinct. No job IDs, payer/nonce, proofs,
secrets, options, content, filename or content hash enter logs. Request error
responses are fixed codes, never parser/provider diagnostics. The executable
bounds pre-header connections as well as active requests and job resources.

Representative errors: 409 `binding_conflict`, `admission_nonce_used`,
`immutable_part_conflict`, `attempt_replayed`; 410 `upload_closed` or
`result_expired`; 402 `result_unpaid`/`invalid_mock_payment`; 429
`capacity_unavailable`/`download_budget_exhausted`; 503 `cleanup_uncertain`.
Pending/unknown result requests return 409 `settlement_pending`/`payment_unknown`,
never 402 `result_unpaid`. Status and reconciliation telemetry preserve this
distinction. A payment-unknown status is never evidence of no charge.

## Run and verify

From `prototypes/csv`, build the existing worker with `scripts/build.sh`, create a
private synthetic state directory and a separate private synthetic key file, then:

```sh
go run ./cmd/csv-flow --enable-synthetic-flow \
  --state /absolute/private/state --mock-key-file /absolute/private/mock.key
python3 scripts/flow_demo.py --mock-key-file /absolute/private/mock.key
```

`go test -race ./...` tests strict bindings, multipart/finalize races, restart,
expiry, stale workers, input/result corruption, payment crashes/ambiguity,
compressed range budgets, disconnects and telemetry. Opt in to actual isolated
local-worker end-to-end tests with:

```sh
CSV_DOCKER_TESTS=1 go test -race ./internal/flow -run TestDockerEndToEndFlow -v
```

The standard-library Python client verifies independently expected results for
all four tools, answers the second challenge, reassembles gzip ranges and checks
both hash domains before acknowledgement. It uses no AWS SDK or wallet. This
is a local agent-like client proof, not evidence that a particular restricted
customer environment can upload, persist secrets, pay and resume.

AWS storage/queue/compute/transfer adapters, final production image isolation,
real x402 integration, retention/remedy policy, measured retry-inclusive pricing,
monitoring, intended-client validation and owner launch approval remain gates.
