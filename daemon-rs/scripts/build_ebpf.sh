#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
workspace_root=$(cd -- "$script_dir/.." && pwd)
target_root=${CARGO_TARGET_DIR:-$workspace_root/target}

toolchain=${DAEMON_RS_EBPF_TOOLCHAIN:-nightly}
target=${DAEMON_RS_EBPF_TARGET:-bpfel-unknown-none}
package=${DAEMON_RS_EBPF_PACKAGE:-opensnitch-ebpf}

if [[ "$(id -u)" != "0" ]]; then
    echo "eBPF build requires root to keep artifact ownership consistent under target-kernel." >&2
    echo "rerun with sudo, for example: sudo make daemon-rs-ebpf-build" >&2
    exit 1
fi

resolve_bpf_linker() {
    if command -v bpf-linker >/dev/null 2>&1; then
        command -v bpf-linker
        return 0
    fi

    # When invoked via `sudo make ...`, secure_path may hide the caller's cargo bin.
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_home
        sudo_home=$(getent passwd "$SUDO_USER" | cut -d: -f6 || true)
        if [[ -n "$sudo_home" ]]; then
            local candidate="$sudo_home/.cargo/bin/bpf-linker"
            if [[ -x "$candidate" ]]; then
                printf '%s\n' "$candidate"
                return 0
            fi
        fi
    fi

    return 1
}

if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup is required to build ${package} for ${target}." >&2
    exit 1
fi

if ! bpf_linker_bin=$(resolve_bpf_linker); then
    echo "missing linker 'bpf-linker'." >&2
    echo "install it with: cargo install bpf-linker" >&2
    echo "if you run via sudo, either preserve user PATH or install bpf-linker for the sudo target user." >&2
    exit 1
fi

# Pin linker path explicitly so bpf builds work even under sudo secure_path.
export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="$bpf_linker_bin"

if ! rustup toolchain list | grep -Eq "^${toolchain}([- ].*)?$"; then
    echo "missing Rust toolchain '${toolchain}'." >&2
    echo "install it with: rustup toolchain install ${toolchain}" >&2
    exit 1
fi

if rustup target list --toolchain "$toolchain" | grep -Fxq "$target"; then
    if ! rustup target list --toolchain "$toolchain" --installed | grep -Fxq "$target"; then
        echo "missing Rust target '${target}' for toolchain '${toolchain}'." >&2
        echo "install it with: rustup target add ${target} --toolchain ${toolchain}" >&2
        exit 1
    fi
else
    echo "warning: Rust target '${target}' has no prebuilt rustup artifacts for toolchain '${toolchain}'; continuing with -Z build-std" >&2
fi

cd "$workspace_root"

cargo +"$toolchain" rustc \
    -Z build-std=core \
    --target "$target" \
    --manifest-path "$workspace_root/Cargo.toml" \
    -p "$package" \
    "$@" \
    -- \
    --crate-type=cdylib \
    -C panic=abort

profile_dir=debug
for arg in "$@"; do
    if [[ "$arg" == "--release" ]]; then
        profile_dir=release
        break
    fi
done

target_dir="$target_root/$target/$profile_dir"
normalized_artifact="$target_dir/$package"
quirks_check_script="$script_dir/check_quirks_relocations.sh"
for candidate in \
    "$target_dir/libopensnitch_ebpf.so" \
    "$target_dir/libopensnitch_ebpf.a" \
    "$target_dir/libopensnitch_ebpf.rlib" \
    "$target_dir/$package.o" \
    "$target_dir/$package"
do
    if [[ -f "$candidate" ]]; then
        cp -f "$candidate" "$normalized_artifact"
        if [[ "${DAEMON_RS_EBPF_SKIP_QUIRKS_CHECK:-0}" != "1" ]]; then
            "$quirks_check_script" "$normalized_artifact" "$profile_dir"
        fi
        echo "built ${package}: ${normalized_artifact}" 
        exit 0
    fi
done

echo "build completed but no normalized artifact was found under ${target_dir}" >&2
echo "expected one of: libopensnitch_ebpf.so, libopensnitch_ebpf.a, libopensnitch_ebpf.rlib, ${package}.o, ${package}" >&2
exit 1