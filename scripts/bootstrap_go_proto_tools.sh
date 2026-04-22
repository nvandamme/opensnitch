#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_MOD_PATH="${ROOT_DIR}/daemon/go.mod"

if [[ ! -f "${GO_MOD_PATH}" ]]; then
  echo "bootstrap-go-proto-tools: missing ${GO_MOD_PATH}" >&2
  exit 1
fi

require_module_version() {
  local module="$1"

  awk -v mod="${module}" '
    $1 == "require" && $2 == mod { print $3; exit }
    $1 == "require" && $2 == "(" { in_req = 1; next }
    in_req && $1 == ")" { in_req = 0; next }
    in_req && $1 == mod { print $2; exit }
  ' "${GO_MOD_PATH}"
}

strip_v() {
  local v="$1"
  echo "${v#v}"
}

semver_lt() {
  local a b
  a="$(strip_v "$1")"
  b="$(strip_v "$2")"

  [[ "${a}" != "${b}" ]] && [[ "$(printf '%s\n%s\n' "${a}" "${b}" | sort -V | head -n1)" == "${a}" ]]
}

grpc_version="$(require_module_version "google.golang.org/grpc")"
protobuf_version="$(require_module_version "google.golang.org/protobuf")"

if [[ -z "${grpc_version}" ]]; then
  echo "bootstrap-go-proto-tools: unable to detect google.golang.org/grpc version in daemon/go.mod" >&2
  exit 1
fi

if [[ -z "${protobuf_version}" ]]; then
  echo "bootstrap-go-proto-tools: unable to detect google.golang.org/protobuf version in daemon/go.mod" >&2
  exit 1
fi

# Keep protoc-gen-go aligned with daemon-side protobuf module unless overridden.
protoc_gen_go_version="${BOOTSTRAP_PROTOC_GEN_GO_VERSION:-${protobuf_version}}"

if [[ -n "${BOOTSTRAP_PROTOC_GEN_GO_GRPC_VERSION:-}" ]]; then
  protoc_gen_go_grpc_version="${BOOTSTRAP_PROTOC_GEN_GO_GRPC_VERSION}"
elif semver_lt "${grpc_version}" "v1.64.0"; then
  # Legacy grpc baselines need pre-generics stubs (SupportPackageIsVersion7).
  protoc_gen_go_grpc_version="v1.3.0"
else
  protoc_gen_go_grpc_version="v1.6.1"
fi

go_bin_dir="$(go env GOPATH)/bin"

echo "bootstrap-go-proto-tools: daemon grpc=${grpc_version} protobuf=${protobuf_version}"
echo "bootstrap-go-proto-tools: installing protoc-gen-go@${protoc_gen_go_version} protoc-gen-go-grpc@${protoc_gen_go_grpc_version}"

go install "google.golang.org/protobuf/cmd/protoc-gen-go@${protoc_gen_go_version}"
go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@${protoc_gen_go_grpc_version}"

echo "bootstrap-go-proto-tools: done (ensure ${go_bin_dir} is ahead in PATH when invoking protoc)"
