#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "error: this smoke test must run inside GitHub Actions" >&2
  exit 1
fi

if [[ -z "${RUNNER_OS:-}" ]]; then
  echo "error: RUNNER_OS is unavailable" >&2
  exit 1
fi

command -v go >/dev/null 2>&1 || {
  echo "error: Go toolchain is unavailable" >&2
  exit 1
}

go version

go_os="$(go env GOOS)"
go_arch="$(go env GOARCH)"

if [[ -z "$go_os" || -z "$go_arch" ]]; then
  echo "error: Go target information is unavailable" >&2
  exit 1
fi

printf 'AnyAPI CI smoke test passed on %s (%s/%s)\n' "$RUNNER_OS" "$go_os" "$go_arch"
