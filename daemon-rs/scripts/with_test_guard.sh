#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

readonly SERVICES=(
  opensnitchd-rs
  opensnitchd
  opensnitch-ui
)

restart_requested="${OPENSNITCH_TEST_GUARD_RESTART_SERVICES:-1}"
original_privileged_tests="${OPENSNITCH_RUN_PRIVILEGED_TESTS-}"
had_original_privileged_tests=0
if [[ -v OPENSNITCH_RUN_PRIVILEGED_TESTS ]]; then
  had_original_privileged_tests=1
fi
declare -a stopped_services=()

action_log() {
  printf '[test-guard] %s\n' "$*" >&2
}

# Returns the best command for running system-privileged operations:
#   ""       — already running as root, run directly
#   "pkexec" — desktop session detected; polkit will show a graphical auth dialog
#   "sudo"   — non-desktop or pkexec unavailable; fall back to sudo
pick_priv_cmd() {
  if [[ "$(id -u 2>/dev/null)" == "0" ]]; then
    echo ""
    return
  fi
  if [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
    if command -v pkexec >/dev/null 2>&1; then
      echo "pkexec"
      return
    fi
  fi
  echo "sudo"
}

PRIV_CMD="$(pick_priv_cmd)"

# Run a command with the appropriate privilege escalation.
# pkexec is tried first on desktop.  We only fall back to sudo when pkexec
# *itself* failed to dispatch (exit 126 = auth not obtained, 127 = binary
# not found); if the underlying command failed that is not our problem.
# sudo is always run with -n (non-interactive) to avoid terminal prompts.
run_privileged() {
  if [[ -z "${PRIV_CMD}" ]]; then
    "$@" >/dev/null 2>&1 || true
    return
  fi
  if [[ "${PRIV_CMD}" == "pkexec" ]]; then
    pkexec "$@" >/dev/null 2>&1
    local rc=$?
    if (( rc == 126 || rc == 127 )); then
      sudo -n -- "$@" >/dev/null 2>&1 || true
    fi
    return
  fi
  sudo -n -- "$@" >/dev/null 2>&1 || true
}

# More reliable than is-active --quiet: returns exactly "active" or not.
service_is_active() {
  local scope="$1" service="$2"
  local -a base=(systemctl)
  [[ "$scope" == "user" ]] && base+=(--user)
  "${base[@]}" show --property=ActiveState "$service" 2>/dev/null \
    | grep -q '^ActiveState=active$'
}

try_stop_service() {
  local scope="$1"
  local service="$2"

  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  if ! service_is_active "$scope" "$service"; then
    return 0
  fi

  if [[ "$scope" == "user" ]]; then
    if systemctl --user stop "$service" >/dev/null 2>&1; then
      stopped_services+=("$scope:$service")
      action_log "stopped user service $service"
    else
      action_log "warning: failed to stop user service $service"
    fi
    return 0
  fi

  if run_privileged systemctl stop "$service"; then
    stopped_services+=("$scope:$service")
    action_log "stopped system service $service (via ${PRIV_CMD:-direct})"
  else
    action_log "warning: failed to stop system service $service"
  fi
}

restart_services() {
  local entry scope service
  if [[ "$restart_requested" != "1" ]]; then
    return 0
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  for (( idx=${#stopped_services[@]}-1; idx>=0; idx-- )); do
    entry="${stopped_services[$idx]}"
    scope="${entry%%:*}"
    service="${entry#*:}"

    if [[ "$scope" == "user" ]]; then
      if systemctl --user start "$service"; then
        action_log "restarted user service $service"
      else
        action_log "warning: failed to restart user service $service"
      fi
      continue
    fi

    if run_privileged systemctl start "$service"; then
      action_log "restarted system service $service (via ${PRIV_CMD:-direct})"
    else
      action_log "warning: failed to restart system service $service"
    fi
  done
}

cleanup() {
  restart_services
  if [[ "$had_original_privileged_tests" == "1" ]]; then
    export OPENSNITCH_RUN_PRIVILEGED_TESTS="$original_privileged_tests"
  else
    unset OPENSNITCH_RUN_PRIVILEGED_TESTS || true
  fi
  # Compatibility alias kept in sync for this shell process.
  if [[ -v OPENSNITCH_RUN_PRIVILEGED_TESTS ]]; then
    export OPENSNITCH_RUN_PRIVILEDGED_TESTS="$OPENSNITCH_RUN_PRIVILEGED_TESTS"
  else
    unset OPENSNITCH_RUN_PRIVILEDGED_TESTS || true
  fi
}

kill_standalone_processes() {
  # Daemons run as root, so killing them requires privilege.
  local procs=(opensnitchd-rs opensnitchd)
  for proc in "${procs[@]}"; do
    if pgrep -x "$proc" >/dev/null 2>&1; then
      run_privileged pkill -x "$proc"
      action_log "killed standalone process $proc (via ${PRIV_CMD:-direct})"
    fi
  done

  # opensnitch-ui typically runs as: python /usr/bin/opensnitch-ui
  # It runs as the current user, so no privilege needed.
  if pgrep -f '(^|[[:space:]]|/)opensnitch-ui([[:space:]]|$)' >/dev/null 2>&1; then
    pkill -f '(^|[[:space:]]|/)opensnitch-ui([[:space:]]|$)' >/dev/null 2>&1 || true
    action_log "killed standalone process opensnitch-ui"
  fi
}

trap cleanup EXIT

for service in "${SERVICES[@]}"; do
  try_stop_service "system" "$service"
  try_stop_service "user" "$service"
done

kill_standalone_processes

if [[ "$(id -u)" == "0" ]]; then
  export OPENSNITCH_RUN_PRIVILEGED_TESTS=1
  # Compatibility alias.
  export OPENSNITCH_RUN_PRIVILEDGED_TESTS=1
fi

action_log "running: $*"
"$@"
