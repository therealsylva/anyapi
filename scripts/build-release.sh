#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-dev}"
commit="${COMMIT:-none}"
build_date="${BUILD_DATE:-unknown}"
dist_dir="${DIST_DIR:-dist}"

if [[ "$dist_dir" == "/" || -z "$dist_dir" ]]; then
  printf 'error: refusing unsafe DIST_DIR %q\n' "$dist_dir" >&2
  exit 1
fi

mkdir -p "$dist_dir"

targets=(
  linux-amd64
  linux-arm64
  darwin-amd64
  darwin-arm64
  windows-amd64
  windows-arm64
)

ldflags="-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${build_date}"
outputs=()

for target in "${targets[@]}"; do
  target_os="${target%-*}"
  target_arch="${target#*-}"
  output="${dist_dir}/anyapi-${target}"
  if [[ "$target_os" == "windows" ]]; then
    output+=".exe"
  fi
  outputs+=("$output")
  printf 'Building %s\n' "$target"
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$output" ./cmd/anyapi
done

checksum_file="${dist_dir}/SHA256SUMS"
: >"$checksum_file"
for path in "${outputs[@]}"; do
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$dist_dir" && sha256sum "$(basename "$path")") >>"$checksum_file"
  else
    (cd "$dist_dir" && shasum -a 256 "$(basename "$path")") >>"$checksum_file"
  fi
done

printf 'Wrote %s release binaries and %s\n' "${#targets[@]}" "$checksum_file"
