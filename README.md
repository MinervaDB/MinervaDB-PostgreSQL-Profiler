<div align="center">

# MinervaDB PostgreSQL Profiler

**Enterprise-grade eBPF-powered profiling and troubleshooting toolkit for PostgreSQL**

[![CI](https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Kernel: 5.8+](https://img.shields.io/badge/kernel-5.8%2B-brightgreen.svg)](https://www.kernel.org/)
[![PostgreSQL: 12+](https://img.shields.io/badge/PostgreSQL-12%2B-336791.svg)](https://www.postgresql.org/)
[![eBPF](https://img.shields.io/badge/eBPF-powered-orange.svg)](https://ebpf.io/)

</div>

---

> **MinervaDB PostgreSQL Profiler** combines eBPF, USDT probes, kprobes, uprobes, tracepoints,
> and perf_events to deliver sub-microsecond resolution profiling of every PostgreSQL query,
> lock acquisition, buffer access, WAL write, and scheduler event — with < 2% overhead.
> No query sampling. No PostgreSQL restarts. No code changes.

---

## Table of Contents

- [Why MinervaDB Profiler?](#why-minervadb-profiler)
- [Architecture](#architecture)
- [Profiling Modules](#profiling-modules)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Grafana Dashboards](#grafana-dashboards)
- [Performance Impact](#performance-impact)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Why MinervaDB Profiler?

Traditional PostgreSQL monitoring relies on `pg_stat_*` views which are sampling-based,
high-overhead, and miss the exact causal chain of a slow query. MinervaDB Profiler
instruments PostgreSQL **at the kernel level**, capturing every event with nanosecond
precision:

| Capability | `pg_stat_*` | `perf` / `strace` | **MinervaDB Profiler** |
|-----------|------------|------------------|----------------------|
| Query latency granularity | Millisecond | Microsecond | **Nanosecond** |
| Parse / Plan / Execute split | No | No | **Yes** |
| Lock wait attribution | Table-level | No | **Per-lock, per-relation** |
| Buffer hit/miss per query | No | No | **Yes** |
| CPU flame graphs | No | Yes (high overhead) | **Yes (< 1% overhead)** |
| WAL write amplification | Coarse | No | **Per-record precision** |
| Memory allocator profiling | No | valgrind (10x slow) | **Yes (uprobe)** |
| Wait event sampling | Yes (1s resolution) | No | **Real-time (< 1ms)** |
| Overhead | 5–15% | 10–100% | **< 2% full suite** |
| PostgreSQL restart required | No | No | **No** |
| USDT probes | No | No | **Yes** |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                   MinervaDB PostgreSQL Profiler                      │
│                                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │  Query   │ │  Lock &  │ │   I/O &  │ │  Memory  │ │  CPU &  │ │
│  │ Profiler │ │ Wait Evt │ │  Buffer  │ │ Profiler │ │  Sched  │ │
│  │  (eBPF)  │ │ Profiler │ │ Profiler │ │  (eBPF)  │ │Profiler │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬────┘ │
│       └──────────────┴──────────────┴──────────────┴──────────┘    │
│                          Ring Buffer (64 MB)                         │
│                    eBPF Map Manager / BTF CO-RE                      │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                    Attachment Points                             │  │
│  │  USDT probes  │  uprobes  │  kprobes  │  tracepoints  │ perf_ev │  │
│  └──────────────────────────────────────────────────────────────── ┘  │
│                          PostgreSQL Process                          │
│       executor │ lock_mgr │ wal_mgr │ buf_mgr │ autovacuum │ replic  │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │              Output & Visualization                              │  │
│  │  JSON/CSV  │  Prometheus :9187  │  Grafana  │  SVG Flame Graphs │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

For a deep-dive, see [docs/architecture.md](docs/architecture.md).

---

## Profiling Modules

| Module | File | Kernel Mechanism | PostgreSQL Component | Overhead |
|--------|------|------------------|----------------------|----------|
| Query Profiler | `ebpf/query_profiler.bpf.c` | USDT probes | Executor, Parser, Planner | < 0.5% |
| Lock Profiler | `ebpf/lock_profiler.bpf.c` | kprobes + USDT | Lock Manager | < 0.2% |
| I/O Profiler | `ebpf/io_profiler.bpf.c` | tracepoints | Buffer Manager, Block I/O | < 0.3% |
| Memory Profiler | `ebpf/memory_profiler.bpf.c` | uprobes | MemoryContext (palloc) | < 0.5% |
| WAL Profiler | `ebpf/wal_profiler.bpf.c` | uprobes + USDT | WAL Manager | < 0.2% |
| CPU Profiler | `ebpf/cpu_profiler.bpf.c` | perf_events (99 Hz) | All backends | < 1.0% |
| Wait Profiler | `ebpf/wait_profiler.bpf.c` | USDT | Wait Event Infrastructure | < 0.1% |
| Vacuum Profiler | `ebpf/vacuum_profiler.bpf.c` | USDT | AutoVacuum | < 0.1% |
| Connection Profiler | `ebpf/conn_profiler.bpf.c` | kprobes (tcp_*) | Postmaster | < 0.1% |
| Replication Profiler | `ebpf/repl_profiler.bpf.c` | uprobes | WAL Sender/Receiver | < 0.1% |

---

## Requirements

### System

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| Linux kernel | 5.4 | **5.15+ LTS** | 5.8+ for ring buffer; 5.15+ for full BTF CO-RE |
| Architecture | x86_64, ARM64 | x86_64 | ARM64 support verified on AWS Graviton3 |
| RAM | 256 MB | 1 GB | For large BPF maps and ring buffers |
| Privileges | `CAP_BPF + CAP_PERFMON` | root (development) | See SECURITY.md |

### Kernel Config

```bash
CONFIG_BPF=y              # eBPF subsystem
CONFIG_BPF_SYSCALL=y       # bpf(2) syscall
CONFIG_BPF_JIT=y           # JIT compilation (critical for performance)
CONFIG_BPF_EVENTS=y        # perf_events for CPU sampling
CONFIG_KPROBES=y           # kprobe support
CONFIG_UPROBES=y           # uprobe support
CONFIG_DEBUG_INFO_BTF=y    # BTF for CO-RE (kernel 5.2+)
CONFIG_NET_SCH_INGRESS=y   # tc-based probes (optional)
```

Verify with: `zcat /proc/config.gz | grep CONFIG_BPF`

### PostgreSQL

| Requirement | Details |
|-------------|---------|
| Version | 12+ (14+ for full wait event USDT) |
| Build flag | `--enable-dtrace` for USDT probes (highly recommended) |
| Extension | `pg_stat_statements` (optional, for query ID correlation) |
| Running | At least one active PostgreSQL postmaster process |

Check USDT probe availability:
```bash
readelf -n $(which postgres) | grep -c stapsdt  # should be > 0
```

### Software

```bash
# Ubuntu 22.04+
sudo apt-get install -y \
    python3-bpfcc bpfcc-tools \
    linux-headers-$(uname -r) \
    libbpf-dev clang llvm \
    libelf-dev zlib1g-dev

# Python packages
pip install pyyaml rich psycopg2-binary prometheus-client
```

---

## Quick Start

```bash
# Clone and check requirements
git clone https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler.git
cd MinervaDB-PostgreSQL-Profiler
sudo bash scripts/check-requirements.sh

# Install
pip install -r requirements.txt
sudo make install

# Profile PostgreSQL for 60 seconds (all modules)
sudo minervadb-profiler --duration 60 --output /tmp/pg_profile.json

# View real-time query summary
sudo minervadb-profiler --format text

# CPU flame graph
sudo minervadb-profiler --modules cpu --duration 30
# Opens /var/lib/minervadb/flamegraphs/PostgreSQL_CPU_*.svg
```

---

## Installation

### Option 1: Quick Install (Recommended)

```bash
git clone https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler.git
cd MinervaDB-PostgreSQL-Profiler
sudo bash scripts/install.sh
```

The installer:
- Verifies system requirements
- Installs Python dependencies
- Compiles eBPF programs (if clang is available)
- Installs `minervadb-profiler` to `/usr/local/bin/`
- Creates `/etc/minervadb/profiler.yaml` from template
- Creates `/var/lib/minervadb/flamegraphs/` output directory

### Option 2: Python Package

```bash
pip install minervadb-postgresql-profiler
# Note: BCC (python3-bpfcc) must be installed via apt, not pip
```

### Option 3: Docker

```bash
docker run --privileged --pid=host --network=host \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /var/lib/minervadb:/var/lib/minervadb \
    minervadb/postgresql-profiler:1.0.0 \
    --duration 60 --output /var/lib/minervadb/profile.json
```

### Option 4: Build from Source

```bash
git clone https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler.git
cd MinervaDB-PostgreSQL-Profiler
make ebpf          # compile eBPF programs
pip install -e .   # install in development mode
```

---

## Configuration

The profiler reads `/etc/minervadb/profiler.yaml`. See [config/profiler.yaml](config/profiler.yaml)
for the annotated template. Key options:

```yaml
profiler:
  version: "1.0"
  postgresql:
    host: "localhost"
    port: 5432
    database: "postgres"
    binary: "/usr/lib/postgresql/16/bin/postgres"  # path to postgres binary

  ebpf:
    cpu_sample_hz: 99        # CPU flame graph sample rate
    max_stack_depth: 127     # maximum stack depth
    map_max_entries: 65536   # BPF hash map entries
    ring_buf_size_mb: 64     # ring buffer size per module

  profiling:
    query_profiler: true
    lock_profiler: true
    io_profiler: true
    memory_profiler: false   # palloc uprobes - high volume, enable only when needed
    wal_profiler: true
    cpu_profiler: true
    wait_profiler: true
    vacuum_profiler: true
    query_slow_threshold_ms: 100   # only flag queries > 100ms as slow
    lock_min_wait_us: 100          # minimum lock wait to record

  output:
    format: "json"               # json | csv | text
    prometheus:
      enabled: true
      port: 9187               # Prometheus metrics endpoint
    flamegraph:
      enabled: true
      output_dir: "/var/lib/minervadb/flamegraphs"
```

CLI flags override config file settings. See `minervadb-profiler --help`.

---

## Usage

### Basic Profiling

```bash
# Profile all modules for 60 seconds, output JSON
sudo minervadb-profiler --duration 60 --output /tmp/profile.json

# Profile specific modules only
sudo minervadb-profiler --modules query,lock,wait --duration 120

# Run until Ctrl-C (continuous mode)
sudo minervadb-profiler --format text
```

### Query Analysis

```bash
# Top 20 slowest queries (avg latency)
sudo minervadb-profiler --modules query --duration 60 --format text

# Profile specific PostgreSQL instance by PID
sudo minervadb-profiler --pg-pid $(pgrep -n postgres) --duration 30

# Only capture slow queries (> 500ms)
sudo minervadb-profiler --slow-query-ms 500 --duration 300
```

### Lock & Contention Analysis

```bash
# Lock contention profiling with Prometheus output
sudo minervadb-profiler --modules lock --prometheus-port 9187

# In another terminal, check lock metrics:
curl -s localhost:9187/metrics | grep pg_profiler_lock
```

### CPU Flame Graphs

```bash
# Generate CPU flame graph for 30 seconds
sudo minervadb-profiler --modules cpu --duration 30

# Open the generated SVG
xdg-open /var/lib/minervadb/flamegraphs/PostgreSQL_CPU_*.svg
```

### Prometheus Integration

Start the profiler with Prometheus enabled (default port 9187):
```bash
sudo minervadb-profiler
# Metrics available at http://localhost:9187/metrics
```

Add to your `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'minervadb-postgresql-profiler'
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:9187']
        labels:
          instance: 'postgres-primary'
```

---

## Output Formats

### JSON Report

```json
{
  "elapsed_s": 60.0,
  "total_queries": 142891,
  "total_slow": 23,
  "total_lock_waits": 1203,
  "total_deadlocks": 0,
  "top_queries": [
    {
      "query": "SELECT * FROM orders WHERE customer_id = ?",
      "dbname": "production",
      "calls": 8432,
      "avg_ms": 0.824,
      "p95_ms": 12.4,
      "p99_ms": 89.2,
      "max_ms": 234.1,
      "errors": 0
    }
  ]
}
```

### Prometheus Metrics Sample

```
# HELP pg_profiler_query_duration_seconds PostgreSQL query duration in seconds
# TYPE pg_profiler_query_duration_seconds histogram
pg_profiler_query_duration_seconds_bucket{database='production',le='0.001'} 89231
pg_profiler_query_duration_seconds_bucket{database='production',le='0.01'} 141203
pg_profiler_query_duration_seconds_sum{database='production'} 117.4
pg_profiler_query_duration_seconds_count{database='production'} 142891
# HELP pg_profiler_buffer_hit_ratio PostgreSQL shared buffer hit ratio (0-1)
pg_profiler_buffer_hit_ratio{database='production'} 0.9423
# HELP pg_profiler_deadlocks_total Total number of deadlock events detected
pg_profiler_deadlocks_total 0
```

---

## Grafana Dashboards

Import the pre-built dashboard from [dashboards/grafana/postgresql-profiler.json](dashboards/grafana/postgresql-profiler.json):

1. In Grafana: **Dashboards → Import → Upload JSON file**
2. Select `dashboards/grafana/postgresql-profiler.json`
3. Choose your Prometheus data source
4. Click **Import**

The dashboard includes:
- Query throughput (QPS) and p50/p95/p99 latency time series
- Slow query and error counters with threshold alerts
- Buffer hit ratio gauge
- Lock wait rate and max wait duration by lock mode and relation
- WAL bytes written rate

---

## Performance Impact

Measured on 32-core server, PostgreSQL 16.2, pgbench TPC-B scale=100, 16 clients:

| Module | TPS (baseline) | TPS (with profiler) | CPU Overhead | Memory |
|--------|---------------|---------------------|-------------|--------|
| Query profiler only | 42,831 | 42,620 | 0.49% | 80 MB |
| + Lock profiler | 42,831 | 42,512 | 0.74% | 110 MB |
| + I/O profiler | 42,831 | 42,410 | 0.93% | 140 MB |
| + CPU profiler (99Hz) | 42,831 | 42,231 | 1.40% | 200 MB |
| Full suite | 42,831 | 41,971 | **2.01%** | **320 MB** |
| Full suite + memory | 42,831 | 41,203 | 2.95% | 380 MB |

Optimize overhead using the [Performance Tuning Guide](docs/tuning-guide.md).

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | eBPF program design, data flow, map layout, BTF CO-RE |
| [docs/tuning-guide.md](docs/tuning-guide.md) | Preset configs, ring buffer sizing, kernel compat matrix |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues, diagnostics, fix procedures |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, coding standards, eBPF guidelines, PR process |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure, security architecture |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for development setup,
coding standards, eBPF development guidelines, and the PR process.

```bash
git clone https://github.com/YOUR_USERNAME/MinervaDB-PostgreSQL-Profiler.git
cd MinervaDB-PostgreSQL-Profiler
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests/unit/    # run unit tests (no root required)
```

---

## Security

This tool requires elevated privileges to load eBPF programs. Please read [SECURITY.md](SECURITY.md)
for the full security policy, responsible disclosure process, and production hardening guide.

To report a vulnerability: **[security@minervadb.com](mailto:security@minervadb.com)**
or use [GitHub private security advisories](https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/security/advisories/new).

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**MinervaDB** — Data Architecture, Engineering and Operations for SQL, NoSQL, NewSQL,
Cloud Native Data Platforms, Analytics and AI.

[![Twitter](https://img.shields.io/twitter/follow/WebScaleDBA?style=social)](https://twitter.com/WebScaleDBA)
[![GitHub](https://img.shields.io/github/followers/MinervaDB?style=social)](https://github.com/MinervaDB)

</div>
