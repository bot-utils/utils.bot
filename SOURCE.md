# Source review guide

This repository contains application and native source, tests, build inputs,
public service assets and third-party notices. Deployment configuration,
operational records and release approvals are maintained privately.

The service and API reference are at https://utils.bot/ and
https://utils.bot/docs. CSV code is an unreleased candidate.

Use the Go version in `go.mod`. Local unit tests run with:

```sh
go test ./cmd/... ./internal/...
```

Build and release checks require their separately reviewed inputs. Missing
private approval or scan inputs block release; this source snapshot is not a
deployment authorization. Test fixtures and fixture signing keys are synthetic
and must never be funded or reused for real credentials.

Original application code is all rights reserved. GitHub platform viewing and
forking rights and applicable legal exceptions remain. Auditors seeking
permission to compile, execute or modify original material should contact
info@utils.bot. Third-party components retain their applicable licenses and
notices; see COPYRIGHT, THIRD_PARTY.md and DEPENDENCIES.md.
