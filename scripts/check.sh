#!/usr/bin/env bash
set -euo pipefail

unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  printf 'The following Go files are not formatted:\n%s\n' "$unformatted" >&2
  exit 1
fi

go mod verify
go vet ./...
go test -race -count=1 ./...
