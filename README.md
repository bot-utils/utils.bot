# utils.bot source for security review

This repository contains the service's Go request handler and payment code,
native PDF worker sources, build configuration, and tests. It implements PDF
text extraction and x402 payment handling, with PDFium and Poppler workers.
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
go test ./...
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
