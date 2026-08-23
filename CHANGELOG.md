# Changelog

All notable changes to AnyAPI are documented here. The project follows semantic versioning for releases; the `.anyapi` document and packed-artifact formats have their own explicit versions.

## Unreleased

### Added

- Local importers for cURL, OpenAPI 3.x, Swagger 2.0, and Postman Collection v2.
- Strict, editable `anyapi.dev/v1alpha1` YAML contract and embedded JSON Schema.
- Direct execution and an interactive console with history, completion, selection, undo, and redo.
- Standalone native CLI packaging using canonical CBOR, Zstandard, and an integrity footer.
- Linux, macOS, and Windows targets for amd64 and arm64.
- Environment and OS-keyring credentials, bounded HTTP execution, TLS policy, retries, and redacted dry runs.
- Unit, fuzz, race, cross-platform, vulnerability, and generated-binary integration coverage.
