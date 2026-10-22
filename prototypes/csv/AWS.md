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
`PrivateWorker` observes only the original ECS task and pins its token and immutable definition revision,
subnet and private endpoint. Lifecycle IAM must be exact-task and exact-cluster.
Its `NetworkGone` dependency must use a separate short-lived verifier identity;
there is deliberately no default using broker credentials. EC2 ENI read permission
is region-wide metadata access, even when source queries only exact attachment
IDs. The source now supplies a separate local verifier executable, authenticated
proof channel and private synthetic broker/controller assembly. Effective IAM,
VPC/endpoint policies and actual Fargate kernel/runtime behavior remain preflight
gates. A two-minute durable `TransferUntil` claim also survives a lost claim response
or broker crash. Failed transfers move to `PROCESSING_UNKNOWN`. `Recover` handles
expired RUNNING claims, unknown processing and interrupted deletion without
redispatch or settlement. The CAS pins the exact job version and its immutable
original token/deadline; a recovery transition fences all later publication.
It stops/verifies the original worker, requires a separate broker/upload writer
fence, erases both full job prefixes (including orphan results from ambiguous
PutResult/final-CAS responses), and releases capacity only after fresh absence
proof. Lost successful publication remains payment-eligible and is not erased as
a failed unpaid transfer. Unknown writer/storage evidence retains capacity and
requires bounded repeated recovery/operator attention. The private reaper uses a durable scheduled record, three cleanup attempts,
90-second claims and 45-second recovery callbacks. The record must exist before
either task starts. Deploying or independently invoking its scheduler remains a
preflight requirement; source entrypoints alone do not supply a running scheduler. Runner
performs the broad read-only definition inspection before dispatch; LifecycleAPI
contains only exact-task DescribeTasks/StopTask, not DescribeTaskDefinition.

No production writer-fence implementation is supplied. The new destructive
fence is exclusively for one synthetic run, one job and its never-reused private
unversioned bucket. It stops both original task ARNs and obtains signed ENI
absence proofs. If the broker never started, a conditional `NEVER_STARTED`
tombstone excludes a late broker start; a STARTING/ambiguous record instead
requires exact-token reconciliation. Cleanup races with the broker's conditional
start reservation and the job-version check.

The first recovery phase checks privacy/ownership/encryption, rejects foreign
objects and MPUs, erases the complete owned prefixes and requires a successful
DeleteBucket reply. It records DELETED and yields. A later claimed recovery
performs one independent absence convergence, records a short-lived CONFIRMED
receipt and releases capacity only while that receipt remains fresh. The verifier
requires at least 15 seconds of continuous explicit NoSuchBucket responses with
bounded backoff and a 30-second limit. A 403, timeout, contradictory visibility
or missing delete acknowledgement holds capacity for operator reconciliation.
The local delayed-write model is not proof of AWS deletion propagation; the real
late-PUT race remains an unrun cloud gate. Never reuse this bucket name.

## Private synthetic run assembly

The broker executable processes exactly one synthetic 1 MiB two-file join. It
reads the immutable inputs, uses the per-job TLS channel and verifies the gzip
result; it has no public route or payment/RPC client. Its task role can read this
job's inputs, write its results, transact only its job/request rows, read signed
proofs and stop/describe the exact original worker. It has no EC2 inspection,
SSM read, AssumeRole, task-start or bucket-create permission. Worker and broker
execution roles receive different exact SSM references. The credential-free
parser remains separate from the broker and TLS transport.

The independent verifier runs outside the broker task with short-lived read-only
credentials. It independently observes the exact original STOPPED task and ENI,
then signs proofs bound to run, job, task, nonce, interfaces and expiry. The broker
can request/read a proof but cannot write it. The signing key travels through a
private pipe, not environment or argv. Linux executes the verified open binary
inode through fd3. Darwin uses an explicit owned, read-only binary in an owned
0700 directory, with an immediate inode recheck; this is a host-account trust
boundary, not a defense against compromise of that same host account.

RunPlan durably binds pinned image digests, exact isolated subnet and task SG,
a 10-minute run, a $10 conservative reservation and a two-hour resource lifetime.
These are source admission bounds, not AWS-enforced spending caps. Lost RunTask
responses consume the original attempt and are reconciled read-only; no retry or
replacement token is allowed. The original broker request hash, definition hash,
network and ARN are durable and checked again on controller assembly. An inspected,
never-settled synthetic result may be explicitly retired without replaying work;
pending, unknown or funded settlements are not eligible for this path.

IAM policy documents stay in the operator conversation and are not generated as
files. The temporary setup principal is trusted: direct role creation, image
upload, family revision registration and task starts can bypass source preflight.
Its cleanup StopTask grant covers tagged tasks in the isolated cluster, rather
than just the two original ARNs. The actual broker role is exact-worker-ARN bound.
The temporary recursive SSM path-read deny also affects this setup principal's
unrelated recursive reads; existing live runtime roles are unchanged.

Before any AWS task starts: validate the full effective IAM/trust, materialize and
review the isolated network change set (private ECR API/DKR, SSM, ECS and DynamoDB
endpoints, exact endpoint policies/DNS allowlist and task-to-task TLS rule), verify
bucket protections before input upload, and arrange independent controller/reaper
invocation and cleanup. No public CSV launch or funded settlement is authorized.
Current source processing remains **8 MiB per input and 8 MiB CSV/gzip result**.
The **1 GiB upload bound is not a validated processing capability**. That requires
a separate streaming/spill architecture and scale tests.

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
