#!/usr/bin/env bash
set -euo pipefail

SITEPKG_DIR="/usr/lib/python3.14/site-packages"
PKG_NAME="opensnitch"
DST_PATH="${SITEPKG_DIR}/${PKG_NAME}"
BACKUP_PATH="${SITEPKG_DIR}/${PKG_NAME}.bak-copilot"
WORKSPACE_PKG_DEFAULT="/home/nvand/Workspace/Dev/opensnitch/ui/opensnitch"
WORKSPACE_PKG="${2:-$WORKSPACE_PKG_DEFAULT}"

usage() {
  cat <<'EOF'
Usage:
  sudo ./utils/scripts/sitepkg_swap_opensnitch.sh swap [workspace_pkg_path]
  sudo ./utils/scripts/sitepkg_swap_opensnitch.sh restore
  ./utils/scripts/sitepkg_swap_opensnitch.sh status

Examples:
  sudo ./utils/scripts/sitepkg_swap_opensnitch.sh swap
  sudo ./utils/scripts/sitepkg_swap_opensnitch.sh swap /home/me/dev/opensnitch/ui/opensnitch
  sudo ./utils/scripts/sitepkg_swap_opensnitch.sh restore
  ./utils/scripts/sitepkg_swap_opensnitch.sh status
EOF
}

require_sudo() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "This action must run as root (use sudo)." >&2
    exit 1
  fi
}

status_cmd() {
  echo "site-packages target: ${DST_PATH}"
  if [[ -L "${DST_PATH}" ]]; then
    echo "status: symlink"
    echo "-> $(readlink -f "${DST_PATH}")"
  elif [[ -d "${DST_PATH}" ]]; then
    echo "status: real directory"
  else
    echo "status: missing"
  fi

  if [[ -e "${BACKUP_PATH}" ]]; then
    echo "backup: present at ${BACKUP_PATH}"
  else
    echo "backup: not present"
  fi
}

swap_cmd() {
  require_sudo

  if [[ ! -d "${WORKSPACE_PKG}" ]]; then
    echo "Workspace package path does not exist: ${WORKSPACE_PKG}" >&2
    exit 1
  fi

  mkdir -p "${SITEPKG_DIR}"

  if [[ -e "${BACKUP_PATH}" ]]; then
    echo "Backup already exists: ${BACKUP_PATH}" >&2
    echo "Run restore first or manually remove the backup if intentional." >&2
    exit 1
  fi

  if [[ -L "${DST_PATH}" ]]; then
    echo "Removing existing symlink at ${DST_PATH}"
    rm -f "${DST_PATH}"
  elif [[ -e "${DST_PATH}" ]]; then
    echo "Moving current install to backup: ${BACKUP_PATH}"
    mv "${DST_PATH}" "${BACKUP_PATH}"
  else
    echo "No existing installed package at ${DST_PATH}; creating symlink only."
  fi

  ln -s "${WORKSPACE_PKG}" "${DST_PATH}"
  echo "Swapped successfully."
  echo "${DST_PATH} -> $(readlink -f "${DST_PATH}")"
}

restore_cmd() {
  require_sudo

  if [[ -L "${DST_PATH}" ]]; then
    echo "Removing symlink ${DST_PATH}"
    rm -f "${DST_PATH}"
  elif [[ -e "${DST_PATH}" ]]; then
    echo "Current ${DST_PATH} is not a symlink; leaving it untouched."
  fi

  if [[ -e "${BACKUP_PATH}" ]]; then
    echo "Restoring backup from ${BACKUP_PATH}"
    mv "${BACKUP_PATH}" "${DST_PATH}"
    echo "Restore complete."
  else
    echo "No backup found at ${BACKUP_PATH}; nothing to restore."
  fi
}

main() {
  action="${1:-}"
  case "${action}" in
    swap)
      swap_cmd
      ;;
    restore)
      restore_cmd
      ;;
    status)
      status_cmd
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
