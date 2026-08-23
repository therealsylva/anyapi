# AnyAPI

[![CI](https://github.com/therealsylva/anyapi/actions/workflows/ci.yml/badge.svg)](https://github.com/therealsylva/anyapi/actions/workflows/ci.yml)

```text
                                                       ███
                                                     ░░░
  ██████   ████████   █████ ████  ██████   ████████  ████
 ░░░░░███ ░░███░░███ ░░███ ░███  ░░░░░███ ░░███░░███░░███
  ███████  ░███ ░███  ░███ ░███   ███████  ░███ ░███ ░███
 ███░░███  ░███ ░███  ░███ ░███  ███░░███  ░███ ░███ ░███
░░████████ ████ █████ ░░███████  ░░████████ ░███████  █████
 ░░░░░░░░ ░░░░ ░░░░░   ░░░░░███  ░░░░░░░░  ░███░░░  ░░░░░
                       ███ ░███               ░███
                      ░░██████                █████
                       ░░░░░░                ░░░░░
```

AnyAPI turns an HTTP API definition into a native command-line application. Import cURL, OpenAPI, Swagger, or Postman; review the generated `.anyapi` contract; run it directly; then package it into one executable that no longer needs AnyAPI or the source specification.

AnyAPI is local-first: there is no account, daemon, telemetry, hosted compiler, or runtime control plane.

## Quick start

Build AnyAPI with Go 1.27 or download a release binary:

```bash
make build VERSION=0.1.0
./bin/anyapi --version
```

Turn one cURL request into a CLI:

```bash
anyapi import \
  --curl 'curl -H "Accept: application/json" https://api.github.com/users/{username}' \
  --name github \
  --output github.anyapi

anyapi lint github.anyapi
anyapi run github.anyapi users get octocat
anyapi build github.anyapi --output github
./github users get octocat --output json
```

Import a complete definition instead:

```bash
anyapi import ./openapi.yaml --output service.anyapi
anyapi import ./collection.postman_collection.json --output service.anyapi --force
anyapi import https://example.test/openapi.json --output service.anyapi
```

Remote imports require HTTPS unless `--allow-http` is explicitly supplied.

## Two ways to work

The direct mode is deterministic and automation-friendly:

```bash
anyapi import <source> --output api.anyapi
anyapi lint api.anyapi
anyapi inspect api.anyapi
anyapi run api.anyapi <generated command>
anyapi build api.anyapi --output api
anyapi verify api
```

The console supports discovery and iterative editing:

```text
$ anyapi console
anyapi > import ./openapi.yaml
anyapi(my-api)* > show commands
anyapi(my-api)* > use users.get
anyapi(my-api/users.get)* > show request
anyapi(my-api/users.get)* > test usr_42
anyapi(my-api/users.get)* > rename users describe
anyapi(my-api/users.describe)* > undo
anyapi(my-api/users.get)* > save my-api.anyapi
anyapi(my-api/users.get) > build --output my-api
```

The console includes history, completion, quoted argument parsing, selection-aware `run` and `test`, undo/redo, and an unsaved-change guard. Run `help` inside the console for the complete command set. Set `ANYAPI_BANNER=plain` for a plain-text banner.

## Generated CLI behavior

Every generated command gets a consistent runtime surface:

```text
--server <name-or-url>    choose a declared server or override it
--profile <name>          load a local profile
--output <format>         auto, raw, json, yaml, or table
--output-file <path>      write the raw response body atomically
--header 'Name: Value'    add a request header; repeatable
--timeout 30s             bound request duration
--retries 2               retry idempotent transient failures
--max-response <bytes>    bound response memory
--dry-run                 print a redacted request without sending it
--no-auth                 skip configured authentication
--insecure                explicitly disable TLS verification
--verbose                 print status and timing to stderr
```

Path parameters become positional arguments. Query, header, cookie, and body fields become typed, documented flags. JSON, form-urlencoded, multipart, raw, and file-backed request bodies are supported.

Generated CLIs also include:

```bash
./service about
./service auth list
./service auth set bearer
./service auth delete bearer
./service completion bash
```

Secrets resolve from environment variables first and the operating-system keyring second. Non-interactive keyring writes require `--secret-stdin`.

Exit statuses are stable for automation: `0` success, `1` general/output failure, `2` usage, `3` document validation, `4` transport, `5` non-2xx HTTP response, `6` authentication, and `7` artifact integrity.

### Local profiles

Profiles select a server and add non-sensitive headers without changing the compiled CLI. Run `anyapi doctor` to see the platform-specific profile pattern and target cache. A CLI named `github` reads `github.yaml` from the AnyAPI directory under the operating system's user configuration directory.

```yaml
profiles:
  staging:
    server: https://staging.example.test
    headers:
      X-Tenant: platform
```

Use it with `./github users get octocat --profile staging`. Profile files are strict YAML, limited to 1 MiB, and reject credential-like headers; credentials belong in environment variables or the OS keyring.

## Cross-platform builds

Native builds use the running AnyAPI executable as the runtime stub. Supported targets are:

- `linux-amd64`
- `linux-arm64`
- `darwin-amd64`
- `darwin-arm64`
- `windows-amd64`
- `windows-arm64`

Cross-compilation remains fully local. Download a clean AnyAPI release binary for the target, then either install it as an offline runtime or pass it directly:

```bash
anyapi targets install ./anyapi-windows-amd64.exe
anyapi build service.anyapi --target windows-amd64 --output service.exe

anyapi build service.anyapi \
  --target darwin-arm64 \
  --runtime ./anyapi-darwin-arm64 \
  --output service
```

Compiled API artifacts are rejected as runtime stubs.

## The `.anyapi` contract

`.anyapi` is strict YAML with a versioned schema. It is intended to be readable, editable, diffable, and safe to commit after review.

```yaml
apiVersion: anyapi.dev/v1alpha1
kind: API
metadata:
  name: users
  version: 1.0.0
  description: Users service CLI
defaultServer: production
servers:
  production:
    url: https://api.example.test/v1
commands:
  - id: users.get
    path: [users, get]
    summary: Get a user
    operation:
      transport: http
      method: GET
      path: /users/{id}
    parameters:
      - name: id
        flag: id
        in: path
        type: string
        required: true
        positional: true
```

Unknown YAML fields are rejected. `anyapi lint` validates executable semantics, while `anyapi schema` prints the embedded JSON Schema. See [the format reference](docs/format.md).

## Design and security

The generated executable is the target AnyAPI runtime followed by canonical-CBOR metadata compressed with Zstandard and a fixed integrity footer. At startup, the binary validates the footer, size bounds, codec, and SHA-256 digest before decoding the API manifest. Builds are deterministic for the same runtime, manifest, and tool version.

- [Architecture](docs/architecture.md)
- [Format and artifact specification](docs/format.md)
- [Importer compatibility](docs/compatibility.md)
- [Security model](docs/security.md)
- [Security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Project status

The `v1alpha1` contract supports local HTTP API compilation. gRPC, WebSocket-native commands, executable Postman scripts, automatic OAuth browser flows, and external OpenAPI `$ref` fetching are outside the current contract; import diagnostics identify lossy conversions.

No software license has been selected for this repository yet. Copyright remains with the repository owner until a license is added.
