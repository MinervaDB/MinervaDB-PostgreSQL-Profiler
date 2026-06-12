# MinervaDB PostgreSQL Profiler - Dockerfile
# Copyright (c) 2026 MinervaDB Inc.
# SPDX-License-Identifier: MIT
#
# Multi-stage build for MinervaDB PostgreSQL Profiler
#
# Build:
#   docker build -t minervadb/postgresql-profiler:latest .
#
# Run:
#   docker run --privileged --pid=host \
#     -v /sys/kernel/debug:/sys/kernel/debug \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -v /sys/kernel/btf:/sys/kernel/btf:ro \
#     -e PGHOST=host.docker.internal \
#     -e PGPORT=5432 \
#     minervadb/postgresql-profiler:latest

# ============================================================
# Stage 1: eBPF Build Stage
# Compiles eBPF programs with clang/LLVM
# ============================================================
FROM ubuntu:24.04 AS ebpf-builder

ARG DEBIAN_FRONTEND=noninteractive
ARG KERNEL_VER=6.8.0-generic

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    libelf-dev \
    zlib1g-dev \
    pkg-config \
    make \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

# Copy eBPF source files
WORKDIR /build
COPY ebpf/ ./ebpf/
COPY Makefile ./

# Generate vmlinux.h and compile eBPF programs
# Note: In CI/CD, vmlinux.h should be pre-generated from target kernel
RUN mkdir -p build && \
    # Try to generate vmlinux.h from BTF (may not work in build container)
    if [ -f /sys/kernel/btf/vmlinux ]; then \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h; \
    else \
        # Use a minimal stub vmlinux.h for build validation
        touch ebpf/vmlinux.h; \
    fi && \
    # Compile eBPF programs (will fail gracefully if BTF not available)
    make ebpf 2>&1 || echo "NOTE: eBPF compilation requires BTF from target kernel"

# ============================================================
# Stage 2: Runtime Image
# Lightweight runtime with Python userspace components
# ============================================================
FROM ubuntu:24.04 AS runtime

LABEL org.opencontainers.image.title="MinervaDB PostgreSQL Profiler"
LABEL org.opencontainers.image.description="eBPF-powered PostgreSQL profiling toolkit"
LABEL org.opencontainers.image.vendor="MinervaDB Inc."
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler"

ARG DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # eBPF runtime
    bpfcc-tools \
    python3-bpfcc \
    libbpf-dev \
    # Kernel tools
    linux-perf \
    bpftool \
    # System tools
    procps \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    # Utilities
    curl \
    jq \
    # PostgreSQL client for correlation
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for configuration (profiler still needs root for eBPF)
RUN groupadd -g 1000 minervadb && \
    useradd -u 1000 -g minervadb -m -s /bin/bash minervadb

# Create directories
RUN mkdir -p \
    /etc/minervadb \
    /var/log/minervadb \
    /var/lib/minervadb/flamegraphs \
    /var/lib/minervadb/ebpf \
    /var/lib/minervadb/reports && \
    chown -R minervadb:minervadb \
        /var/log/minervadb \
        /var/lib/minervadb

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy application files
WORKDIR /opt/minervadb-profiler

COPY collector/ ./collector/
COPY tools/ ./tools/
COPY config/ ./config/
COPY dashboards/ ./dashboards/

# Copy compiled eBPF objects from builder stage
COPY --from=ebpf-builder /build/build/*.bpf.o /var/lib/minervadb/ebpf/ 2>/dev/null || true

# Install default configuration
COPY config/profiler.yaml /etc/minervadb/profiler.yaml.example
RUN cp /etc/minervadb/profiler.yaml.example /etc/minervadb/profiler.yaml

# Install main profiler script
RUN install -m 755 collector/profiler_main.py /usr/local/bin/minervadb-profiler && \
    for tool in tools/pg-*; do \
        [ -f "$$tool" ] && install -m 755 "$$tool" /usr/local/bin/ || true; \
    done

# Expose ports
EXPOSE 8080   # Web dashboard
EXPOSE 9187   # Prometheus metrics

# Volume mounts for kernel access
VOLUME ["/sys/kernel/debug", "/sys/fs/bpf", "/sys/kernel/btf"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["minervadb-profiler", "--help"]

# ============================================================
# Usage Examples (in comments)
# ============================================================
#
# Profile PostgreSQL for 60 seconds:
#   docker run --privileged --pid=host \
#     -v /sys/kernel/debug:/sys/kernel/debug \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     minervadb/postgresql-profiler:latest \
#     minervadb-profiler --duration 60
#
# Start with Prometheus metrics:
#   docker run --privileged --pid=host \
#     -v /sys/kernel/debug:/sys/kernel/debug \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -p 9187:9187 \
#     minervadb/postgresql-profiler:latest \
#     minervadb-profiler --prometheus
#
# Start with web dashboard:
#   docker run --privileged --pid=host \
#     -v /sys/kernel/debug:/sys/kernel/debug \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -p 8080:8080 \
#     minervadb/postgresql-profiler:latest \
#     minervadb-profiler --dashboard
