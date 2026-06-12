# MinervaDB PostgreSQL Profiler

<p align="center">
  <img src="https://img.shields.io/badge/PostgreSQL-Profiler-blue?style=for-the-badge&logo=postgresql" alt="PostgreSQL Profiler"/>
  <img src="https://img.shields.io/badge/eBPF-Powered-orange?style=for-the-badge" alt="eBPF Powered"/>
  <img src="https://img.shields.io/badge/Linux-Kernel-yellow?style=for-the-badge&logo=linux" alt="Linux Kernel"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"/>
  <img src="https://img.shields.io/badge/Version-1.0.0-purple?style=for-the-badge" alt="Version"/>
</p>

> **MinervaDB PostgreSQL Profiler** is an advanced, production-grade observability and troubleshooting toolkit for PostgreSQL databases, leveraging eBPF (Extended Berkeley Packet Filter) and Linux Kernel profiling technologies to provide deep, zero-overhead insights into PostgreSQL internals.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Profiling Modules](#profiling-modules)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Profiling Subsystems](#profiling-subsystems)
- [Output Formats](#output-formats)
- [Dashboards](#dashboards)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Performance Impact](#performance-impact)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

MinervaDB PostgreSQL Profiler combines the power of **eBPF**, **perf_events**, **ftrace**, **uprobe/kprobe**, **USDT (User Statically Defined Tracing)**, and traditional Linux kernel profiling tools to deliver comprehensive observability for PostgreSQL 12+ deployments.

Unlike traditional monitoring tools that rely on pg_stat_* views (sampling-based), MinervaDB PostgreSQL Profiler instruments PostgreSQL at the kernel level, capturing every query execution, lock acquisition, buffer access, network I/O, and system call with sub-microsecond resolution and less than 1% overhead.

### Why eBPF for PostgreSQL?

| Capability | Traditional Monitoring | MinervaDB Profiler (eBPF) |
|---|---|---|
| Query latency granularity | Millisecond | Nanosecond |
| Lock contention visibility | Limited (pg_locks) | Full kernel-level |
| Overhead | 5-15% | < 1% |
| Buffer cache visibility | Approximate | Exact per-operation |
| Network stack profiling | None | Full TCP/socket level |
| Kernel scheduler impact | None | Full context-switch tracking |
| USDT probes | No | Yes (PostgreSQL built-in) |
| Memory allocator profiling | No | Yes (palloc/pfree) |
| WAL write profiling | Coarse | Per-record precision |
| CPU flame graphs | No | Yes |

---

## Architecture

```
+---------------------------------------------------------------------+
|                    MinervaDB PostgreSQL Profiler                     |
+---------------------------------------------------------------------+
|  +-------------+  +-------------+  +-------------+  +-----------+  |
|  |  Query      |  |  Lock &     |  |  I/O &      |  |  Memory   |  |
|  |  Profiler   |  |  Wait Event |  |  Buffer     |  |  Profiler |  |
|  |  (eBPF)     |  |  Profiler   |  |  Profiler   |  |  (eBPF)   |  |
|  +------+------+  +------+------+  +------+------+  +-----+-----+  |
|         |                |                |               |         |
|  +------v---------------------------------------------------------v-+|
|  |              eBPF Program Loader & Map Manager                    ||
|  |         (BCC / libbpf / BTF CO-RE Support)                       ||
|  +------+------------------------------------------------------------+|
|         |                                                             |
|  +------v-------------------------------------------------------------+|
|  |                    Linux Kernel Interface                           ||
|  |  +----------+ +----------+ +----------+ +-------------------+    ||
|  |  | kprobes  | | uprobes  | |  USDT    | |   perf_events /   |    ||
|  |  | kretprob | | uretprob | |  Probes  | |   tracepoints     |    ||
|  |  +----------+ +----------+ +----------+ +-------------------+    ||
|  +------+------------------------------------------------------------+|
|         |                                                             |
|  +------v-------------------------------------------------------------+|
|  |                     PostgreSQL Process                              ||
|  |  +--------+ +--------+ +--------+ +--------+ +-------------+      ||
|  |  |Executor| |Planner | |  Lock  | |  WAL   | |   Buffer    |      ||
|  |  |        | |        | |Manager | |Manager | |   Manager   |      ||
|  |  +--------+ +--------+ +--------+ +--------+ +-------------+      ||
|  +--------------------------------------------------------------------+|
|                                                                       |
|  +--------------------------------------------------------------------+|
|  |                    Output & Visualization                           ||
|  |  +----------+ +----------+ +----------+ +-------------------+    ||
|  |  | JSON/CSV | |Prometheus| | Grafana  | |  Flame Graphs     |    ||
|  |  | Reports  | | Metrics  | |Dashboard | |  (SVG/HTML)       |    ||
|  |  +----------+ +----------+ +----------+ +-------------------+    ||
|  +--------------------------------------------------------------------+|
+---------------------------------------------------------------------+
```

---

## Features

### Core Profiling Capabilities

- **Query-Level Profiling**: Full execution lifecycle tracing via PostgreSQL USDT probes
- **Lock Profiling**: Kernel-level lock acquisition, hold time, and contention analysis
- **I/O Profiling**: Block device I/O tracing per PostgreSQL relation file
- **Buffer Cache Profiling**: Shared buffer hit/miss/eviction tracking with palloc instrumentation
- **WAL Profiling**: Write-Ahead Log write amplification, fsync latency, and checkpoint duration analysis
- **Memory Profiling**: PostgreSQL memory context tracking, palloc/pfree call sites, and OOM pressure analysis
- **Connection Profiling**: TCP connection lifecycle, authentication time, and connection pool saturation
- **CPU Profiling**: Per-process CPU flame graphs, scheduler latency, and context-switch analysis
- **Wait Event Profiling**: Real-time wait event sampling matching PostgreSQL 14+ wait event taxonomy
- **Vacuum & Autovacuum Profiling**: Tuple visibility scanning rate, dead tuple accumulation, and bloat tracking
- **Index Profiling**: B-tree traversal depth, index scan selectivity, and index bloat detection
- **Replication Profiling**: WAL sender/receiver lag, streaming replication throughput, and apply latency

### Advanced Kernel-Level Features

- **BTF CO-RE Support**: Compile-Once, Run-Everywhere eBPF programs with kernel type information
- **Adaptive Sampling**: Configurable sampling rates to tune between resolution and overhead
- **Stack Trace Capture**: Kernel and userspace stack traces for every profiled event
- **cgroup-Aware**: Filter profiling to specific PostgreSQL clusters in containerized environments
- **NUMA-Aware**: Memory locality analysis for multi-socket PostgreSQL deployments
- **Network Stack**: TCP socket buffer pressure, receive/send queue depth, and network-induced latency

---

## Profiling Modules

| Module | File | Kernel Mechanism | PostgreSQL Component |
|--------|------|------------------|----------------------|
| Query Profiler | ebpf/query_profiler.bpf.c | USDT probes | Executor, Parser, Planner |
| Lock Profiler | ebpf/lock_profiler.bpf.c | kprobes + USDT | Lock Manager |
| I/O Profiler | ebpf/io_profiler.bpf.c | tracepoints | Buffer Manager, Relation |
| Memory Profiler | ebpf/memory_profiler.bpf.c | uprobes | MemoryContext |
| WAL Profiler | ebpf/wal_profiler.bpf.c | uprobes + tracepoints | WAL Manager |
| Connection Profiler | ebpf/conn_profiler.bpf.c | kprobes (tcp_*) | Postmaster |
| CPU Profiler | ebpf/cpu_profiler.bpf.c | perf_events | All backends |
| Wait Profiler | ebpf/wait_profiler.bpf.c | USDT | Wait Event Infrastructure |
| Vacuum Profiler | ebpf/vacuum_profiler.bpf.c | USDT | AutoVacuum |
| Replication Profiler | ebpf/repl_profiler.bpf.c | uprobes | WAL Sender/Receiver |

---

## Requirements

### System Requirements

- **OS**: Linux kernel 5.8+ (5.15+ recommended for full BTF support)
- **Architecture**: x86_64, ARM64
- **Kernel Config**: CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_BPF_JIT=y, CONFIG_BPF_EVENTS=y, CONFIG_KPROBES=y, CONFIG_UPROBES=y, CONFIG_DEBUG_INFO_BTF=y

### PostgreSQL Requirements

- PostgreSQL 12+ (compiled with --enable-dtrace for USDT support)
- PostgreSQL 14+ for full wait event USDT probes
- pg_stat_statements extension (optional, for correlation)

### Software Dependencies

```bash
# Core dependencies
apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
apt-get install -y libbpf-dev clang llvm libelf-dev zlib1g-dev

# Python dependencies
pip3 install bcc prometheus-client flask psycopg2-binary rich click
```

---

## Installation

### Quick Install

```bash
git clone https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler.git
cd MinervaDB-PostgreSQL-Profiler
sudo make install
```

### Build from Source

```bash
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) libelf-dev zlib1g-dev python3-pip
git clone https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler.git
cd MinervaDB-PostgreSQL-Profiler
make ebpf
pip3 install -r requirements.txt
sudo make install
```

### Docker

```bash
docker run --privileged --pid=host \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    minervadb/postgresql-profiler:latest
```

---

## Configuration

Create /etc/minervadb/profiler.yaml:

```yaml
profiler:
  version: "1.0"
postgresql:
  host: "localhost"
  port: 5432
  database: "postgres"
  binary: "/usr/lib/postgresql/16/bin/postgres"
ebpf:
  cpu_sample_hz: 99
  max_stack_depth: 127
  map_max_entries: 65536
profiling:
  query_profiler: true
  lock_profiler: true
  io_profiler: true
  memory_profiler: true
  wal_profiler: true
  wait_profiler: true
  vacuum_profiler: true
  query_slow_threshold_ms: 100
  lock_min_wait_us: 100
output:
  format: "json"
  prometheus:
    enabled: true
    port: 9187
  flamegraph:
    enabled: true
    output_dir: "/var/lib/minervadb/flamegraphs"
```

---

## Usage

```bash
# Profile all PostgreSQL activity for 60 seconds
sudo minervadb-profiler --duration 60 --output /tmp/profile.json

# Top slow queries
sudo minervadb-profiler query --top 20 --min-duration 100ms

# Real-time lock profiling
sudo minervadb-profiler locks --watch --interval 1s

# I/O profiling per relation
sudo minervadb-profiler io --relations --database mydb

# CPU flame graph
sudo pg-cpu-profiler --flamegraph --duration 30 --output /tmp/pg_cpu.svg

# Real-time wait event analysis
sudo pg-wait-profiler --watch --interval 1s
```

---

## Profiling Subsystems

### eBPF Programs (Kernel Space)

All eBPF programs in ebpf/ are compiled with clang/LLVM and use BTF CO-RE for portability across kernel versions.

**Probe Types Used:**
- **USDT probes**: PostgreSQL DTrace probe points (query__start, query__done, lock__wait__start, etc.)
- **uprobes/uretprobes**: LockAcquire, LockRelease, palloc, pfree, XLogWrite, XLogFlush
- **kprobes/kretprobes**: tcp_connect, tcp_close, sys_read, sys_write
- **Tracepoints**: block_rq_issue, block_rq_complete, sched_switch, sched_wakeup
- **perf_events**: PERF_COUNT_SW_CPU_CLOCK for CPU sampling

### Userspace Collector (Python)

- **profiler_main.py**: Main orchestrator, eBPF program loading, ring buffer management
- **query_collector.py**: Query event aggregation and histogram computation
- **metrics_exporter.py**: Prometheus metrics exposition
- **flamegraph_gen.py**: Flame graph SVG generation from kernel + userspace stacks
- **alert_manager.py**: Threshold-based alerting

### Linux Kernel Profiler Integration

- **perf(1)**: CPU cycles, cache misses, branch mispredictions per PostgreSQL PID
- **ftrace**: Function graph tracing for kernel path analysis
- **SystemTap**: Alternative for older kernels (3.x - 4.x)
- **/proc filesystem**: /proc/[pid]/smaps memory maps, /proc/[pid]/io counters
- **cgroups v2**: Resource controller metrics for containerized PostgreSQL
- **numastat**: NUMA memory access patterns

---

## Output Formats

### JSON Report

```json
{
  "profiler": "MinervaDB PostgreSQL Profiler v1.0",
  "timestamp": "2026-06-12T10:00:00Z",
  "duration_s": 60,
  "postgresql": { "version": "16.2", "pid": 12345 },
  "query_profile": {
    "total_queries": 142891, "slow_queries": 23,
    "p50_ms": 0.8, "p95_ms": 45.2, "p99_ms": 234.1
  },
  "lock_profile": {
    "total_lock_waits": 1203, "deadlocks_detected": 0
  },
  "io_profile": {
    "buffer_hit_ratio": 0.942, "wal_bytes_written": 234567890
  }
}
```

### Prometheus Metrics

```
pg_profiler_query_duration_seconds_bucket{database="production",le="0.001"} 89231
pg_profiler_buffer_hit_ratio{database="production"} 0.942
pg_profiler_lock_waits_total{lock_type="ExclusiveLock"} 1203
pg_profiler_wal_bytes_written_total 234567890
```

---

## Performance Impact

| Profiling Mode | CPU Overhead | Memory Overhead | Latency Impact |
|----------------|-------------|-----------------|----------------|
| Query Profiler | < 0.5% | 50-100MB | < 5us per query |
| Lock Profiler | < 0.2% | 20-50MB | < 1us per lock |
| I/O Profiler | < 0.3% | 30-80MB | None |
| CPU Flame Graph (99Hz) | < 1% | 100-200MB | None |
| Full Suite | < 2% | 200-500MB | < 10us per query |

---

## Project Structure

```
MinervaDB-PostgreSQL-Profiler/
+-- ebpf/                    # eBPF kernel-space programs
|   +-- query_profiler.bpf.c
|   +-- lock_profiler.bpf.c
|   +-- io_profiler.bpf.c
|   +-- memory_profiler.bpf.c
|   +-- wal_profiler.bpf.c
|   +-- conn_profiler.bpf.c
|   +-- cpu_profiler.bpf.c
|   +-- wait_profiler.bpf.c
|   +-- vacuum_profiler.bpf.c
|   +-- repl_profiler.bpf.c
|   +-- common.h
+-- collector/               # Userspace Python collectors
|   +-- profiler_main.py
|   +-- query_collector.py
|   +-- lock_collector.py
|   +-- io_collector.py
|   +-- metrics_exporter.py
|   +-- flamegraph_gen.py
|   +-- alert_manager.py
+-- tools/                   # Standalone CLI tools
|   +-- pg-query-profiler
|   +-- pg-lock-profiler
|   +-- pg-io-profiler
|   +-- pg-cpu-profiler
|   +-- pg-wait-profiler
|   +-- pg-memory-profiler
|   +-- pg-vacuum-profiler
|   +-- pg-repl-profiler
+-- dashboards/grafana/      # Grafana dashboard JSONs
+-- config/                  # Configuration templates
|   +-- profiler.yaml
|   +-- alerts.yaml
+-- docs/                    # Documentation
|   +-- architecture.md
|   +-- ebpf-internals.md
|   +-- usdt-probes.md
|   +-- tuning-guide.md
|   +-- troubleshooting.md
+-- scripts/
|   +-- install.sh
|   +-- check-requirements.sh
|   +-- pg-compile-with-dtrace.sh
+-- tests/
+-- Makefile
+-- requirements.txt
+-- Dockerfile
```

---

## Contributing

1. Fork the repository
2. Create your feature branch: git checkout -b feature/amazing-profiler
3. Commit your changes: git commit -m 'Add amazing profiler feature'
4. Push to the branch: git push origin feature/amazing-profiler
5. Open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## About MinervaDB

[MinervaDB](https://minervadb.com) - Data Architecture, Engineering and Operations for SQL, NoSQL, NewSQL, Cloud Native Data Platforms, Analytics and AI.

- Twitter: [@WebScaleDBA](https://twitter.com/WebScaleDBA)
- GitHub: [@MinervaDB](https://github.com/MinervaDB)
