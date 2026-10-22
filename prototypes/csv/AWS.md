# Unreleased CSV AWS adapter contract

CSV is not available at utils.bot. These source adapters have no public routes,
production configuration, deployed resources or enabled payment/dispatch/logging
sink. PDF and URL-to-Markdown continue to use their existing implementations.
The local synthetic HTTP flow is described in [FLOW.md](FLOW.md).

## Components

`internal/csvcloud` provides S3 storage, DynamoDB job transactions, an SQS outbox,
one-attempt ECS Fargate dispatch, artifact verification, real-signature payment
coordination, finalized-chain reconciliation, controlled download ranges and
verified cleanup. `internal/cdp/tabular.go` reuses the authenticated fixed-origin
CDP transport with an explicitly configured CSV amount. It does not change the
PDF/HTML payment price selection. `Gate{}` disables every operation; dispatch and
settlement require separate flags even when the base adapter gate is enabled.

The AWS client factory reuses the existing no-proxy/no-redirect credential policy,
requires Ohio, rejects endpoint overrides, disables SDK request logging and sets
one SDK attempt. Source construction itself does not call AWS. The source tests
use generated unfunded signing keys, fake HTTP transports and atomic fake provider
transactions. They do not prove deployment IAM, bucket policy, isolation, service
behavior under real failures, performance or large-file throughput.

## Uploads, jobs and results

Unsigned admission challenges are stateless. A verified signed admission proof
can be bound to one intent by the job-create transaction: job, admission nonce,
idempotency tombstone and global active-capacity reservation commit together.
The controller remains responsible for authenticating recovery/capabilities and
constructing the canonical operation/input binding using the strict CSV contract.
No HTTP controller connects these adapters to the existing prototype yet.

Objects have server-derived unique keys. Multipart grants bind a specific part,
byte count, SHA-256 and upload ID, with at most five minutes of validity and no
renewal past intent expiry. There are at most 128 parts and 1 GiB per input.
Completion lists exact part sizes/checksums, conditionally creates the unique
object, then streams its full bytes and SHA-256. An S3 multipart checksum is not
the full-file hash; ETags are opaque concurrency fences. A lost create response
can only be recovered by reading the exact reserved key; zero/multiple MPUs stay
unknown. A lost complete response requires inspecting the original object, never
a blind completion retry. Stale events cannot manufacture verified input state. Explicit artifact and
financial transition maps reject skipped states. Input identities, byte counts
and hashes remain frozen; only upload-acceptance ETags may advance. Settlement
states are closed enums consistent with the financial state. Generic database
replacement is limited to challenge updates and marking deletion. It cannot
change input, result, dispatch, download or settlement evidence, financial state
or deadlines. Dedicated operations accept uploads, reserve work, publish verified
results, manage download leases and record uncertainty. The package-private
resolution operation calls the trusted chain reader itself and requires a
transaction hash for PAID. Queued/running states require the corresponding
dispatch record; prepared results must be awaiting payment or pending settlement.

The queue transaction commits the job, a single-use outbox and a cumulative cost
reservation. Duplicate sends/receives cannot create a second automatic ECS start.
An uncertain queue send remains unknown. An uncertain task start preserves the
original client token and exact request hash; reconciliation only lists/describes
original tasks. At or beyond 24 hours it requires operator reconciliation, with
no replacement token or automatic redrive. The cost reservation is a conservative
cumulative budget debit, not a refundable active-slot counter.

Dispatch pins the full reviewed task-definition hash and a non-root, read-only
credential-free parser profile with dropped capabilities and no public IP.
The default single-container profile rejects secrets, ports and logging. A
separate explicit synthetic-only `WireReview` permits exactly three containers:
CHOWN-only FIFO init, UID 65532 TLS transport, and UID 65533 parser. Only the
transport receives one exact per-run SSM TLS identity reference. Task role and
shared PID mode remain absent; no extra containers, ports, environment, mounts,
capabilities, image digests or logging sinks are accepted. Fargate's default
20 GiB allocation is retained without requesting expanded ephemeral storage.

The private wire protocol carries strict operation/options and immutable bounded
bytes, never job capabilities, source URLs, payment proofs or AWS credentials.
The parser installs `seccomp-no-paths-v1` process-wide before its ready marker and
input, verifies existing/new thread restrictions, and admits only exact Go runtime
clone flags. This in-memory profile handles all four operations at 8 MiB per file
and 8 MiB CSV/gzip output. It does not provide the later spill-to-disk worker.
The local opt-in ARM64 Docker test exercises the actual init/FIFO/parser/transport
path and per-job TLS authentication, including shared sibling networking.

`Processor` durably claims one transfer attempt, reads immutable S3 inputs,
independently verifies complete gzip/CSV/hash/count evidence, and requires worker
stop plus separate ENI-absence verification before result publication.
`PrivateWorker` observes only the original ECS task and pins its token, definition,
subnet and private endpoint. Lifecycle IAM must be exact-task and exact-cluster.
Its `NetworkGone` dependency must use a separate short-lived verifier identity;
there is deliberately no default using broker credentials. EC2 ENI read permission
is region-wide metadata access, even when source queries only exact attachment
IDs. External verifier transport, effective IAM, private broker/controller assembly,
VPC/endpoint policies and actual Fargate kernel/runtime behavior remain preflight
gates. No production writer-fence implementation is supplied; cleanup cannot
release capacity without an independent proof covering every writer/capability.

A result is conditionally stored as gzip. The adapter streams compressed and
logical bytes, checks both byte counts and SHA-256 domains, validates gzip/CRC and
bounds logical output to 1 GiB before publishing the immutable result manifest.
The prepared-result window is at most 30 minutes. This is an adapter bound, not
a measured claim that all four operations handle 1 GiB on deployed hardware.

## Payment binding and finality

The `csv-binding-v1` x402 v2 extension advertises a server-issued EIP-3009 nonce.
A protected, externally supplied versioned 32-byte key derives that nonce over the
quote ID, stage, expiry, payment domain and canonical intent. The result challenge
also commits to the payer, job and exact immutable result manifest. Admission
precedes job creation and does not require knowing the payer. No key, raw proof
or signature is persisted to DynamoDB. Old key versions must remain available
through outstanding quotes; an unknown key fails closed.

Clients must echo the extension and sign the required nonce. Generic clients that
choose a random nonce are incompatible. `csvcloud.SignBound` is the supported
source adapter for the official x402 `evm.ClientEvmSigner` interface. It accepts
an authenticated server quote and independently trusted payment configuration,
constructs `TransferWithAuthorization` typed data, signs with the required nonce
and returns the payment header without sending a transaction. Tests round-trip
through the official x402 EOA signer and EIP-712 verifier. Contract-wallet,
multisig and EIP-6492 signatures are not supported by this adapter. An externally packaged
agent client and validation on an intended restricted machine remain required.

The server verifies that signature and binding before CDP verification. Admission
never settles. Only an intact prepared result can reserve a result nonce and make
one CDP settlement attempt. The facilitator receives canonical transfer fields,
not private job URLs, manifest hashes or custom extension metadata. Provider
success is not finalized payment. A crash, pending transaction, lost reply or
RPC failure keeps `PAYMENT_UNKNOWN` and locks download. Reconciliation never calls
settle again.

The read-only chain adapter accepts only the exact pinned Base public RPC origins
`https://mainnet.base.org` and `https://sepolia.base.org`. No request-selected RPC
endpoint is accepted. A different provider requires a reviewed source change and
preflight. Finality checks chain ID, canonical finalized blocks, authorization
nonce state, receipt success and exactly one payer authorization plus one exact
token transfer. Ambiguous batched transfers, missing/conflicting evidence and
oversized lookback stay unknown. Definitive nonpayment requires a finalized
block timestamp after authorization expiry with the nonce still unused.

## Download, deletion and evidence

Downloads use a broker, not an unrestricted presigned GET. A durable CAS reserves
an exact compressed byte range and charges it to a three-times-compressed-size
budget before one-use claim. At most two streams are active globally. A permit
cannot be reused, even after a lost response. Streams are bounded by their
90-second lease and result expiry. Capacity is released after the broker closes
the stream; an uncertain broker must be reconciled first.

Artifact expiry moves a job to deletion. Unknown payments quarantine artifacts
for at most 24 hours, then require deletion/manual remedy. Late confirmed payment
after deletion cannot resurrect the result. Cleanup first requires independent
proof that tasks/writers have stopped and outstanding writes cannot finish. It
then aborts owned MPUs, deletes exact owned keys conditionally and independently
lists both prefixes again. Pagination, extra keys or uncertain absence block
completion. Only then does one transaction mark `ERASED`, decrement active job
capacity once and scrub input/result hashes, object references, quotes, dispatch
metadata and normal capabilities. Duplicate cleanup cannot decrement twice.

Opaque nonce/idempotency tombstones retain replay protection; their intent-binding
field is removed on cleanup. An erased job retains only ID, version, artifact and
financial state, a recovery verifier, remedy status and any minimum settlement
record. Financial fields are authorization nonce, payer, receiver, token/network,
amount, validity/start/finality lookup boundary and known transaction reference.
These are sensitive records, not telemetry. They require encrypted DynamoDB and
restricted controller/reconciliation access. Unresolved evidence has no TTL and
must survive until authoritative resolution or manual remedy. Settled/rejected
financial retention, backups and remedy procedures require a separate policy.

## Telemetry and remaining integration boundaries

The optional event sink is disabled. Its exact event record is
`{schema:1,event:<fixed enum>,count:1,payer_rejected:<boolean>}`. Categories separate
initial quotes, re-quotes, malformed headers, payment rejection, provider verify
and settle failures, unknown payment, document failure, infrastructure failure
and finalized payment. Only an explicit provider rejection sets `payer_rejected=true`. Initial quotes,
re-quotes, malformed headers, provider errors and unknown outcomes set it false.
There are no paths, IDs, wallets, transaction references, hashes, IPs, cookies,
user agents, raw proofs, file names, document content or free-form diagnostics.
The PO accepted a seven-day maximum for these encrypted, operator-only records,
with export/subscriptions disabled. No log sink or cloud retention is configured
by this source; those controls must be verified before enabling one. CloudFront
must retain its separate strict field allowlist; best-effort edge logs cannot
prove exact request totals.

Before cloud use, the remaining boundaries include controller/event wiring with
existing strict operations, authentication and abuse quotas; actual writer and
transfer isolation; private unversioned storage and backup/access controls;
cleanup/timeout/stream reconciliation; an approved bounded cloud preflight;
restricted-client validation; retry-inclusive prices; and explicit launch
approval. CSV launch and funded payment testing remain separate authorizations.
