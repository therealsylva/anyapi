# `.anyapi` and compiled artifact format

## Document versioning

The current document identity is:

```yaml
apiVersion: anyapi.dev/v1alpha1
kind: API
```

Readers reject an unsupported `apiVersion` or `kind`. Additive fields require a new tool release; incompatible semantic changes require a new API version. YAML decoding rejects unknown fields so a misspelling cannot silently change runtime behavior.

The authoritative JSON Schema is embedded in every builder and available with:

```bash
anyapi schema > anyapi-v1.schema.json
```

## Complete structural example

```yaml
apiVersion: anyapi.dev/v1alpha1
kind: API
metadata:
  name: users
  version: 1.4.0
  description: Users service
  source: openapi.yaml
defaultServer: production
servers:
  production:
    url: https://api.example.test/{version}
    variables:
      version: v1
auth:
  token:
    type: bearer
    env: USERS_TOKEN
commands:
  - id: users.update
    path: [users, update]
    summary: Update a user
    operation:
      transport: http
      method: PATCH
      path: /users/{id}
      server: production
    parameters:
      - name: id
        flag: id
        in: path
        type: string
        required: true
        positional: true
      - name: verbose
        flag: verbose
        in: query
        type: boolean
        default: false
    body:
      contentType: application/json
      required: true
      fields:
        - name: displayName
          flag: display-name
          in: body
          type: string
          required: true
          jsonPath: displayName
    auth: [token]
    responses:
      - status: "200"
        description: Updated user
        contentType: application/json
```

## Runtime mapping

| Document field | Generated CLI behavior |
|---|---|
| `command.path` | Nested command words |
| Path parameter with `positional: true` | Positional argument and a named flag |
| Query/header/cookie parameter | Repeatable named flag |
| Body field | Named flag; prefixed with `body-` if needed to avoid collision |
| `default` | Runtime default; string defaults may expand environment references |
| `enum` and scalar `type` | Input validation |
| `jsonPath` | Nested JSON object placement |
| `auth` | Ordered authentication schemes applied to the request |
| `operation.server` | Per-command server selection |

Supported scalar types are `string`, `integer`, `number`, `boolean`, `array`, and `object`. Flags are accepted as strings and validated or converted immediately before request construction. Repeat a flag to supply multiple values.

Environment-backed defaults are treated as sensitive in query, header, and body dry runs. They are forbidden for path parameters because a path is routinely included in transport diagnostics. Prefer explicit runtime flags for non-authentication values and dedicated auth scheme environment fields for credentials.

## Authentication schemes

| Type | Required metadata | Runtime behavior |
|---|---|---|
| `bearer` | Optional `env` | `Authorization: Bearer <token>` |
| `oauth2` / `openidconnect` | Optional `env`, informational scopes | Pre-issued bearer token |
| `apiKey` | `in`, `name`, optional `env` | Header, query, or cookie API key |
| `basic` | Optional `usernameEnv`, `passwordEnv` | HTTP Basic authentication |

If environment variables are unset, the generated CLI checks its operating-system keyring namespace.

## Import metadata

Imported documents record the source format, a sanitized source identifier, SHA-256 source fingerprint, and diagnostics. These fields are provenance, not executable instructions. Import diagnostics are preserved by round trips and shown by `lint`.

## Compiled binary format version 1

The file layout is the unmodified target runtime, followed by a compressed payload and a fixed 64-byte big-endian footer.

| Offset in footer | Bytes | Field |
|---:|---:|---|
| 0 | 8 | Magic: `41 4e 59 41 50 49 00 01` (`ANYAPI`, NUL, format marker) |
| 8 | 2 | Artifact format version (`1`) |
| 10 | 2 | Codec (`1` = canonical CBOR + Zstandard) |
| 12 | 8 | Compressed payload size |
| 20 | 32 | SHA-256 of compressed payload |
| 52 | 12 | Reserved, zero-filled |

The CBOR envelope contains its own format version, AnyAPI tool version, and normalized document. Canonical CBOR, single-threaded deterministic Zstandard settings, and fixed footer encoding make the payload repeatable for identical inputs.

Current safety limits:

| Object | Limit |
|---|---:|
| Imported source | 50 MiB |
| `.anyapi` document | 32 MiB |
| Commands per document | 10,000 |
| Parameters or body fields per command | 2,048 |
| Compressed artifact payload | 64 MiB |
| Decompressed artifact document | 128 MiB |
| Runtime stub | 512 MiB |
| Request body | 128 MiB |
| Default response body | 64 MiB |

Use `anyapi verify <binary>` to check and decode the payload. Use `anyapi inspect <binary> --json` to inspect its embedded manifest.
