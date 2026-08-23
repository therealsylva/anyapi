# Security model

AnyAPI processes definitions that may contain credentials, local file paths, untrusted descriptions, and attacker-controlled schema structure. Its security model treats imports and compiled artifacts as untrusted input.

## Local-first behavior

AnyAPI has no telemetry, account, hosted build, update check, or background service. It performs network access only when the user:

- imports an explicit HTTP(S) URL; or
- executes an API command.

Remote definitions require HTTPS by default. Redirects are bounded and cannot downgrade to HTTP unless `--allow-http` was supplied.

## Import safety

- cURL text is tokenized, never shell-executed.
- Postman scripts are skipped, never evaluated.
- Input documents, compressed payloads, request bodies, uploads, and responses have explicit size limits.
- Recursive OpenAPI references and CBOR nesting are bounded.
- Unknown `.anyapi` YAML fields are rejected.
- Imported secrets in authentication, sensitive headers/query/cookies, recognized secret variables, and recognized JSON/form fields are removed and diagnosed.

Secret detection is deliberately defensive but cannot prove that arbitrary example data is non-secret. Review a generated `.anyapi` file before committing or distributing it. Mark manually authored sensitive parameters with `sensitive: true`; executable validation rejects compiled defaults on those parameters.

## Credential handling

Generated CLIs resolve credentials from named environment variables first, then the operating-system keyring. AnyAPI does not write credentials into `.anyapi` files or generated payloads through its auth commands.

Interactive `auth set` reads secrets without terminal echo. Pipelines must opt into `--secret-stdin`. Profiles reject headers whose names appear credential-bearing; profiles are for server selection and non-sensitive headers.

The console persists navigation and editing history with owner-only permissions where supported. It does not persist `run`, `test`, `import`, or `set` lines, or lines containing credential-like terms. This is a defensive filter rather than a secret detector; use environment variables or the keyring instead of typing secrets into commands.

Dry-run output redacts authorization, cookie, token, secret, and API-key headers. A dry run can still expose non-header values and sanitized request bodies, so treat its output as operational data.

Defaults that contain environment references are redacted in query, header, and structured-body previews. Environment-expanded path defaults are rejected because request paths can appear in transport diagnostics.

## HTTP behavior

- TLS certificate validation is enabled and TLS 1.2 is the minimum.
- Disabling certificate checks requires explicit `--insecure` on each invocation.
- Default request timeout is 30 seconds.
- Retries apply only to idempotent methods and transient failures.
- Responses default to a 64 MiB in-memory limit; request bodies default to 128 MiB.
- Go's redirect policy limits redirect chains and avoids forwarding sensitive headers to unrelated domains.

Spec authors control server URLs. Running an untrusted manifest can therefore send user-provided flags or configured credentials to a server named in that manifest. Inspect and lint manifests before execution.

## Artifact integrity

Packed binaries contain a SHA-256 digest over the compressed manifest. The loader validates magic, format, codec, size, digest, decompression limits, and decoder limits before constructing commands.

This checksum detects damage and naive payload modification. It is not a cryptographic signature: an attacker who can rewrite the executable can also replace the digest or runtime. Verify release checksums and obtain binaries from a trusted channel.

## Filesystem behavior

Documents, response files, generated artifacts, and installed target runtimes are written through same-directory temporary files and replacement-safe publication. `.anyapi` documents and response files use owner-only permissions on Unix. Existing outputs require `--force` in non-interactive builder commands.

Symlink, directory, and filesystem permissions remain governed by the invoking user and operating system. Avoid running AnyAPI with elevated privileges.
