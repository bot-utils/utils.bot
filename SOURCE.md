# Source review guide

Source and tests for PDF text extraction and URL-to-Markdown are included with
required build inputs, public API assets and third-party notices.

Use the Go version in `go.mod`. Local unit tests run with:

```sh
go test ./cmd/... ./internal/...
```

Test fixtures and fixture signing keys are synthetic and must never be funded
or reused as real credentials.

Original application code is all rights reserved. GitHub platform viewing and
forking rights and applicable legal exceptions remain. Auditors seeking
permission to compile, execute or modify original material should contact
info@utils.bot. Third-party components retain their applicable licenses and
notices; see COPYRIGHT, THIRD_PARTY.md and DEPENDENCIES.md.
