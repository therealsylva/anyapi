# Importer compatibility

Import is intentionally conservative. AnyAPI preserves behavior it can execute safely and emits diagnostics for behavior that needs review.

## cURL

Supported request inputs include:

- one or more `curl` invocations;
- `--request`, `--url`, headers, cookies, and basic authentication;
- `--data`, `--data-raw`, `--data-ascii`, `--data-binary`, and `--json`;
- multipart `--form` and `--form-string` fields;
- `--get`, `--head`, and common presentation/transport switches;
- URL query values and `{parameter}`, `${VARIABLE}`, or `{{variable}}` placeholders.

The importer never executes shell expansion, command substitution, environment access, file reads, or the cURL command. File arguments become runtime file inputs. Unsupported cURL switches produce warnings.

## OpenAPI and Swagger

Supported inputs:

- OpenAPI 3.0 and 3.1 JSON or YAML;
- Swagger 2.0 JSON or YAML;
- internal JSON Pointer `$ref` values;
- servers and server-variable defaults;
- paths, operations, tags, operation IDs, path-level parameters, and operation parameters;
- JSON, multipart, and form-urlencoded request bodies;
- scalar schemas, top-level object properties, required fields, defaults, examples, enums, and common formats;
- OpenAPI path `simple`, `label`, and `matrix` serialization; query `form`, `deepObject`, `spaceDelimited`, and `pipeDelimited`; header `simple`; and cookie `form`;
- API key, bearer, basic, OAuth2-token, and OpenID-token authentication metadata;
- response status, description, and content type;
- `x-anyapi-command` as a string or path array.

Current intentional reductions:

- External `$ref` values are diagnosed but not fetched. Bundle the specification first.
- A single preferred request content type is selected per operation.
- Content-specific encoding objects, `allowReserved`, and custom serialization outside the listed styles require manual review.
- Multiple alternative OpenAPI security requirements are reduced to the first alternative.
- OAuth2 and OpenID Connect use a pre-issued bearer token; AnyAPI does not run browser or authorization-code flows.
- Nested object bodies remain available through `--body` or `--body-file`; only top-level properties become individual flags.
- Callbacks, links, webhooks, examples collections, and vendor extensions other than `x-anyapi-command` are not executable runtime behavior.
- Mutual TLS and uncommon HTTP authentication schemes are imported with diagnostics but fail executable validation until manually adapted.

## Postman Collection v2

Supported inputs:

- nested folders and request names;
- collection variables and URL variables;
- string and structured URLs, query values, path variables, and headers;
- raw JSON/text, multipart, form-urlencoded, GraphQL-over-HTTP, and file body modes;
- bearer, OAuth2 token, API key, and basic authentication metadata;
- collection, folder, and request descriptions.

Postman pre-request scripts and tests are never executed or compiled. Dynamic values, scripts, cookies, and unsupported authentication such as AWS v4, Hawk, NTLM, or Digest require manual review. Secret-typed and recognizably sensitive variables are replaced or redacted.

## Transport scope

The current runtime contract is HTTP request/response. GraphQL can run over HTTP. Native gRPC, WebSocket sessions, server-sent event streaming, and arbitrary Postman script execution are not implemented in `v1alpha1`.
