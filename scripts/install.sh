#!/usr/bin/env bash
# MinervaDB PostgreSQL Profiler - Installation Script
# Copyright (c) 2026 MinervaDB Inc.
# SPDX-License-Identifier: MIT
#
# Usage:
#   sudo bash scripts/install.sh
#   sudo bash scripts/install.sh --check-only
#   sudo bash scripts/install.sh --uninstall

set -euo pipefail

PROFILER_VERSION='1.0.0'
REPO_URL='https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler'
INSTALL_PREFIX='/usr/local'
CONFIG_DIR='/etc/minervadb'
LOG_DIR='/var/log/minervadb'
DATA_DIR='/var/lib/minervadb'
SYSTEMD_DIR='/etc/systemd/system'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "${CYAN}${BOLD}[STEP]${NC}  $*"; }
log_success() { echo -e "${GREEN}${BOLD}[OK]${NC}    $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error 'This installer requires root privileges.'
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        log_info "OS: ${NAME:-unknown} ${VERSION_ID:-}"
    fi
}

detect_kernel() {
    KERNEL_VER=$(uname -r)
    KERNEL_MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VER" | cut -d. -f2)
    log_info "Kernel: $KERNEL_VER"
    if [[ $KERNEL_MAJOR -ge 5 && $KERNEL_MINOR -ge 8 ]]; then
        log_success 'Kernel meets minimum requirements (5.8+)'
    else
        log_warn 'Kernel older than 5.8 - some features may be unavailable'
    fi
}

check_ebpf() {
    log_step 'Checking eBPF support...'
    [[ -f /sys/kernel/btf/vmlinux ]] && log_success 'BTF: available' || log_warn 'BTF: not available'
    [[ -d /sys/kernel/debug/tracing/kprobes ]] && log_success 'kprobes: available' || log_warn 'kprobes: check manually'
}

detect_postgresql() {
    PG_BINARY=''
    for v in 17 16 15 14 13 12; do
        for path in "/usr/lib/postgresql/$v/bin/postgres" "/usr/pgsql-$v/bin/postgres"; do
            if [[ -f "$path" ]]; then PG_BINARY="$path"; break 2; fi
        done
    done
    PG_BINARY="${PG_BINARY:-$(which postgres 2>/dev/null || echo '')}"
    if [[ -n "$PG_BINARY" ]]; then
        log_success "Found PostgreSQL at: $PG_BINARY"
        PROBE_COUNT=$(readelf -n "$PG_BINARY" 2>/dev/null | grep -c 'stapsdt' || echo 0)
        if [[ $PROBE_COUNT -gt 0 ]]; then
            log_success "PostgreSQL has $PROBE_COUNT USDT probes"
        else
            log_warn 'No USDT probes found. Recompile with --enable-dtrace for full profiling.'
        fi
    else
        log_warn 'PostgreSQL binary not found - will auto-detect at runtime'
    fi
}

install_deps() {
    log_step 'Installing system dependencies...'
    case "${OS_ID:-}" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y --no-install-recommends \
                clang llvm libbpf-dev linux-headers-$(uname -r) \
                libelf-dev zlib1g-dev make python3 python3-pip \
                python3-bpfcc bpfcc-tools linux-perf-$(uname -r | cut -d- -f1) \
                2>/dev/null || apt-get install -y --no-install-recommends \
                clang llvm libbpf-dev python3 python3-pip python3-bpfcc || true
            ;;
        centos|rhel|rocky|almalinux|fedora)
            DNF=$(command -v dnf 2>/dev/null || echo yum)
            $DNF install -y clang llvm libbpf-devel kernel-devel \
                elfutils-libelf-devel python3 python3-pip bcc-tools python3-bcc || true
            ;;
        *)
            log_warn 'Unknown OS - please install dependencies manually'
            log_warn 'Required: clang, llvm, libbpf-dev, python3-bpfcc'
            ;;
    esac
    log_success 'System dependencies installed'
}

install_python_deps() {
    log_step 'Installing Python dependencies...'
    if [[ -f requirements.txt ]]; then
        pip3 install --quiet -r requirements.txt || log_warn 'Some Python deps failed to install'
    fi
    log_success 'Python dependencies installed'
}

compile_ebpf() {
    log_step 'Compiling eBPF programs...'
    if ! command -v clang &>/dev/null; then
        log_warn 'clang not found - skipping eBPF compilation'
        return
    fi
    ARCH=$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
    # Generate vmlinux.h
    if [[ -f /sys/kernel/btf/vmlinux ]] && command -v bpftool &>/dev/null; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h 2>/dev/null || touch ebpf/vmlinux.h
    else
        touch ebpf/vmlinux.h
    fi
    mkdir -p build
    COMPILED=0; FAILED=0
    for src in ebpf/*.bpf.c; do
        obj="build/$(basename "${src%.c}").o"
        if clang -g -O2 -target bpf -D__TARGET_ARCH_"$ARCH" \
                 -I ebpf -I /usr/include \
                 -c "$src" -o "$obj" 2>/dev/null; then
            COMPILED=$((COMPILED+1))
        else
            FAILED=$((FAILED+1))
            log_warn "Failed to compile: $(basename $src) (may need target kernel headers)"
        fi
    done
    log_success "eBPF: $COMPILED compiled, $FAILED failed"
}

install_files() {
    log_step 'Installing files...'
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR/flamegraphs" "$DATA_DIR/ebpf" "$DATA_DIR/reports"
    ls build/*.bpf.o 2>/dev/null && cp build/*.bpf.o "$DATA_DIR/ebpf/" || true
    [[ -d collector ]] && cp -r collector/ "$DATA_DIR/collector/"
    install -m 755 collector/profiler_main.py "$INSTALL_PREFIX/bin/minervadb-profiler"
    for tool in tools/pg-*; do
        [[ -f "$tool" ]] && install -m 755 "$tool" "$INSTALL_PREFIX/bin/" || true
    done
    if [[ -f config/profiler.yaml ]]; then
        install -m 644 config/profiler.yaml "$CONFIG_DIR/profiler.yaml.example"
        [[ ! -f "$CONFIG_DIR/profiler.yaml" ]] && install -m 644 config/profiler.yaml "$CONFIG_DIR/profiler.yaml"
    fi
    log_success 'Files installed'
}

install_systemd() {
    log_step 'Installing systemd service...'
    cat > "$SYSTEMD_DIR/minervadb-profiler.service" << 'SVCEOF'
[Unit]
Description=MinervaDB PostgreSQL Profiler
After=network.target postgresql.service

[Service]
Type=simple
ExecStart=/usr/local/bin/minervadb-profiler --prometheus
Restart=on-failure
User=root
LimitMEMLOCK=infinity
StandardOutput=append:/var/log/minervadb/profiler.log
StandardError=append:/var/log/minervadb/profiler.err

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    log_success 'systemd service installed. Enable: systemctl enable --now minervadb-profiler'
}

print_success() {
    echo ''
    echo -e "${GREEN}${BOLD}MinervaDB PostgreSQL Profiler v$PROFILER_VERSION Installed!${NC}"
    echo ''
    echo '  Quick Start:'
    echo '    sudo minervadb-profiler --duration 60'
    echo '    sudo pg-query-profiler --top 20 --min-duration 100ms'
    echo '    sudo pg-lock-profiler --watch'
    echo '    sudo pg-cpu-profiler --flamegraph --duration 30'
    echo ''
    echo "  Config: $CONFIG_DIR/profiler.yaml"
    echo "  Docs:   $REPO_URL"
    echo ''
}

# Parse args
SKIP_EBPF=false; CHECK_ONLY=false; UNINSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-ebpf)    SKIP_EBPF=true   ;;
        --check-only) CHECK_ONLY=true  ;;
        --uninstall)  UNINSTALL=true   ;;
        --prefix)     INSTALL_PREFIX="$2"; shift ;;
        --help|-h)    echo "Usage: $0 [--no-ebpf] [--check-only] [--uninstall]"; exit 0 ;;
    esac
    shift
done

# Main
echo -e "${CYAN}${BOLD}MinervaDB PostgreSQL Profiler v$PROFILER_VERSION Installer${NC}"
check_root
detect_os
detect_kernel
detect_postgresql
check_ebpf

if [[ "$CHECK_ONLY" == 'true' ]]; then
    log_info 'Check complete. Run without --check-only to install.'
    exit 0
fi

if [[ "$UNINSTALL" == 'true' ]]; then
    log_step 'Uninstalling...'
    systemctl stop minervadb-profiler 2>/dev/null || true
    rm -f "$INSTALL_PREFIX/bin/minervadb-profiler" "$INSTALL_PREFIX/bin/pg-query-profiler"
    rm -f "$INSTALL_PREFIX/bin/pg-lock-profiler" "$INSTALL_PREFIX/bin/pg-io-profiler"
    rm -f "$INSTALL_PREFIX/bin/pg-cpu-profiler" "$INSTALL_PREFIX/bin/pg-wait-profiler"
    rm -f "$SYSTEMD_DIR/minervadb-profiler.service"
    systemctl daemon-reload 2>/dev/null || true
    log_success 'Uninstalled. Config/data preserved.'
    exit 0
fi

install_deps
install_python_deps
[[ "$SKIP_EBPF" == 'false' ]] && compile_ebpf
install_files
command -v systemctl &>/dev/null && install_systemd
print_success
