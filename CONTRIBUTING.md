# Contributing

## Development setup

AnyAPI requires Go 1.27. Clone the repository and run:

```bash
go mod download
./scripts/check.sh
```

Useful targets:

```bash
make build
make test
make test-race
make e2e
make vet
make dist VERSION=0.1.0-dev
```

## Change expectations

- Keep the builder and generated runtime fully local-first.
- Do not execute imported cURL text, Postman scripts, schema extensions, or other definition content.
- Preserve strict input bounds and deterministic artifact encoding.
- Do not add secrets or secret-like fixture values without a test proving they are removed from serialized documents.
- Add focused unit tests and extend the real generated-binary integration test when runtime behavior changes.
- Document lossy importer behavior with a diagnostic and update `docs/compatibility.md`.
- Run `gofmt`, `go vet`, race tests, and relevant fuzz targets before submitting a pull request.

## Pull requests

Keep changes scoped and explain observable behavior, security implications, compatibility changes, and verification performed. Generated binaries and `.anyapi` working files under `bin/` and `dist/` are ignored and should not be committed.

Security issues belong in a private advisory as described in [SECURITY.md](SECURITY.md).
