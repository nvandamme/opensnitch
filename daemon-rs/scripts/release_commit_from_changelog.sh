#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Automate release commit message generation from daemon-rs/CHANGELOG.md.

Usage:
  scripts/release_commit_from_changelog.sh <version> [options]

Arguments:
  version                  Version tag to embed, for example: v0.5.0

Options:
  --push                   Force-push branch and force-push version tag
  --remote <name>          Remote name for push operations (default: origin)
  --dry-run                Print the generated release message and exit
  -h, --help               Show this help text

Behavior:
  1) Extract the full changelog section for <version> from daemon-rs/CHANGELOG.md
  2) Build a clean commit message:
       release: <version>

       Full changelog entry:
       ...section...
  3) Amend current commit message with that content
  4) Force-move tag <version> to amended commit
  5) Optionally force-push branch and tag (with --push)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

version="$1"
shift

remote="origin"
do_push=0
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --push)
      do_push=1
      shift
      ;;
    --remote)
      [[ $# -ge 2 ]] || { echo "missing value for --remote" >&2; exit 1; }
      remote="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

repo_root="$(git rev-parse --show-toplevel)"
changelog="$repo_root/daemon-rs/CHANGELOG.md"

if [[ ! -f "$changelog" ]]; then
  echo "CHANGELOG not found at $changelog" >&2
  exit 1
fi

section="$(awk -v target="## [$version]" '
  index($0, target) == 1 {in_section=1}
  in_section && $0 ~ /^## \[/ && index($0, target) != 1 {exit}
  in_section {print}
' "$changelog")"

if [[ -z "$section" ]]; then
  echo "version section not found in changelog: $version" >&2
  exit 1
fi

msg_file="$(mktemp)"
trap 'rm -f "$msg_file"' EXIT

{
  printf 'release: %s\n\n' "$version"
  printf 'Full changelog entry:\n\n'
  printf '%s\n' "$section"
} > "$msg_file"

if LC_ALL=C grep -qP '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' "$msg_file"; then
  echo "generated message contains control characters; aborting" >&2
  exit 1
fi

if [[ $dry_run -eq 1 ]]; then
  cat "$msg_file"
  exit 0
fi

git commit --amend -F "$msg_file"
git tag -f "$version"

echo "amended HEAD and moved tag $version"

if [[ $do_push -eq 1 ]]; then
  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  git push --force-with-lease "$remote" "$current_branch"
  git push --force "$remote" "$version"
  echo "pushed $current_branch and $version to $remote"
fi
