# Performance Tuning Guide

> MinervaDB PostgreSQL Profiler v1.0

## Table of Contents

- [Preset Configurations](#preset-configurations)
- [Module Selection by Use Case](#module-selection-by-use-case)
- [Ring Buffer Sizing](#ring-buffer-sizing)
- [BPF Map Sizing](#bpf-map-sizing)
- [CPU Profiler Tuning](#cpu-profiler-tuning)
- [Kernel Compatibility Matrix](#kernel-compatibility-matrix)
- [Memory Footprint Reduction](#memory-footprint-reduction)
- [High-Throughput OLTP Tuning](#high-throughput-oltp-tuning)
- [Prometheus Scrape Interval](#prometheus-scrape-interval)
- [Flame Graph Performance](#flame-graph-performance)
- [Operating System Tuning](#operating-system-tuning)
- [Overhead Estimation Formula](#overhead-estimation-formula)

---

## Preset Configurations

The following presets are tested on pgbench TPC-B (scale=100, 16 clients) on a 32-core server running PostgreSQL 16. Copy the relevant block into `/etc/minervadb/profiler.yaml`.

### Preset A: Minimal Overhead (< 0.5%)

Use when you need near-zero production overhead and only care about slow query identification.

```yaml
profiling:
  query_profiler: true
  lock_profiler: false
  io_profiler: false
  memory_profiler: false
  wal_profiler: false
  cpu_profiler: false
  wait_profiler: false
  vacuum_profiler: false
  query_slow_threshold_ms: 500   # only capture queries > 500ms
  lock_min_wait_us: 10000        # not used, lock_profiler disabled

ebpf:
  ring_buf_size_mb: 16
  map_max_entries: 16384
  cpu_sample_hz: 99              # not used, cpu_profiler disabled
```

Expected overhead: **0.3-0.5% CPU, 60 MB memory**.

### Preset B: Standard Monitoring (< 1%)

Daily production monitoring covering queries, locks, wait events, and WAL.

```yaml
profiling:
  query_profiler: true
  lock_profiler: true
  io_profiler: false
  memory_profiler: false
  wal_profiler: true
  cpu_profiler: false
  wait_profiler: true
  vacuum_profiler: true
  query_slow_threshold_ms: 100
  lock_min_wait_us: 500

ebpf:
  ring_buf_size_mb: 32
  map_max_entries: 32768
  cpu_sample_hz: 99
```

Expected overhead: **0.7-1.0% CPU, 180 MB memory**.

### Preset C: Full Profiling Suite (< 2%)

For root-cause analysis and detailed performance investigations. Enable for time-boxed intervals (15-60 minutes).

```yaml
profiling:
  query_profiler: true
  lock_profiler: true
  io_profiler: true
  memory_profiler: false   # keep false unless you specifically need palloc tracing
  wal_profiler: true
  cpu_profiler: true
  wait_profiler: true
  vacuum_profiler: true
  query_slow_threshold_ms: 50
  lock_min_wait_us: 100

ebpf:
  ring_buf_size_mb: 64
  map_max_entries: 65536
  cpu_sample_hz: 99
```

Expected overhead: **1.5-2.0% CPU, 320 MB memory**.

### Preset D: Memory Profiling (< 3%)

Enables palloc/palloc0 uprobes for MemoryContext analysis. Very high event volume. Use for 5-15 minute windows.

```yaml
profiling:
  query_profiler: true
  lock_profiler: false
  io_profiler: false
  memory_profiler: true
  wal_profiler: false
  cpu_profiler: true
  wait_profiler: false
  vacuum_profiler: false
  query_slow_threshold_ms: 0     # capture all queries during memory profiling

ebpf:
  ring_buf_size_mb: 128          # large buffer needed for high palloc event rate
  map_max_entries: 131072
  cpu_sample_hz: 49              # reduce CPU profiler rate to offset memory profiler overhead
```

Expected overhead: **2.5-3.0% CPU, 500 MB memory**.

---

## Module Selection by Use Case

| Symptom / Goal | Recommended Modules |
|---|---|
| Slow queries (p99 > SLA) | query_profiler |
| Lock contention / deadlocks | query_profiler + lock_profiler |
| High I/O wait | io_profiler + wait_profiler |
| CPU spike without query load | cpu_profiler |
| WAL latency / replication lag | wal_profiler |
| autovacuum bloat / table churn | vacuum_profiler + io_profiler |
| Memory leak / OOM in backend | memory_profiler + cpu_profiler |
| Connection storm / pgbouncer impact | query_profiler (conn_profiler built-in) |
| Full root-cause analysis | All modules (Preset C) |
| Continuous production monitoring | Preset B |

---

## Ring Buffer Sizing

The ring buffer is the primary backpressure point. If the userspace collector cannot drain events fast enough, events are dropped. Drops are visible in Prometheus:

```bash
curl -s localhost:9187/metrics | grep profiler_ringbuf_drops_total
```

### Sizing Guidelines

| QPS (PostgreSQL) | Events/sec (estimated) | Recommended ring_buf_size_mb |
|---|---|---|
| < 1,000 | ~5,000 | 16 |
| 1,000 - 10,000 | ~50,000 | 32 |
| 10,000 - 50,000 | ~250,000 | 64 |
| 50,000 - 100,000 | ~500,000 | 128 |
| > 100,000 | ~1,000,000+ | 256 |

**Rule of thumb:** Ring buffer should buffer at least 500ms of peak event rate.

```
buffer_size_bytes = events_per_second * avg_event_bytes * 0.5
avg_event_bytes   = ~200 bytes (query event) to ~80 bytes (lock event)
```

If you see drops, increase `ebpf.ring_buf_size_mb` in steps of 2x. The kernel allocates this as physically contiguous memory; very large values (> 512 MB) may fail on systems with memory fragmentation. Check `dmesg` for `BPF ringbuf alloc failed`.

---

## BPF Map Sizing

BPF hash maps pre-allocate memory at load time. Overflow (inserting more keys than `map_max_entries`) causes silent key eviction in the kernel.

### Signs of map overflow

- Profiler shows fewer unique queries than expected
- Lock profiler misses lock acquisitions on high-concurrency tables
- Prometheus metric `profiler_map_overflow_total > 0`

### Sizing formula

```
map_max_entries = max_concurrent_backends * 4
# Example: 500 max_connections -> 2048 minimum, set to 4096 for safety
```

For analytical workloads with many unique query patterns, increase `map_max_entries` to 131072.

Memory cost per map: approximately 100 bytes per entry (key + value + htab overhead).

---

## CPU Profiler Tuning

### Sample Rate

The default 99 Hz sample rate provides statistical accuracy while avoiding synchronization with 100 Hz system timers. For finer-grained flame graphs at the cost of slightly higher overhead, increase to 499 Hz.

```yaml
ebpf:
  cpu_sample_hz: 499   # 0.1-0.2% additional CPU overhead
```

For minimal overhead CPU profiling (identifying hot functions without fine-grained timing), reduce to 49 Hz.

### Stack Depth

Maximum stack depth (default 127) affects flame graph fidelity. Deep PostgreSQL call stacks (executor -> planner -> sort -> heap_fetch) typically require 60-80 frames. 127 is sufficient for all known PostgreSQL code paths.

Reducing to 64 saves ~30% of the `stack_traces` map memory with minimal practical impact.

```yaml
ebpf:
  max_stack_depth: 64
```

### Kernel vs. Userspace Stacks

The CPU profiler captures both kernel and userspace stacks by default. To capture only userspace stacks (reduces `stack_traces` map usage):

```bash
sudo minervadb-profiler --cpu-user-stacks-only --modules cpu --duration 30
```

---

## Kernel Compatibility Matrix

| Kernel Version | Ring Buffer | BTF CO-RE | USDT | perf_events | CAP_BPF/CAP_PERFMON | Notes |
|---|---|---|---|---|---|---|
| 5.4 LTS | No (falls back to perf array) | Partial | Yes | Yes | No (root required) | Minimum supported |
| 5.8 | Yes | Yes | Yes | Yes | Yes | Ring buffer + capability split |
| 5.10 LTS | Yes | Yes | Yes | Yes | Yes | Recommended minimum for production |
| 5.15 LTS | Yes | Yes | Yes | Yes | Yes | Full BTF CO-RE, best compatibility |
| 6.1 LTS | Yes | Yes | Yes | Yes | Yes | Improved BPF verifier performance |
| 6.6 LTS | Yes | Yes | Yes | Yes | Yes | Latest stable; all features verified |

### Checking your kernel

```bash
uname -r
# Check BTF
ls /sys/kernel/btf/vmlinux
# Check ring buffer support
grep BPF_RINGBUF /boot/config-$(uname -r) 2>/dev/null ||   zcat /proc/config.gz 2>/dev/null | grep BPF_RINGBUF
```

### Distribution Kernel Packages

| Distribution | Recommended Kernel Package | Notes |
|---|---|---|
| Ubuntu 22.04 LTS | Default (5.15.x) | Full support out of the box |
| Ubuntu 20.04 LTS | linux-image-5.15 (HWE) | Upgrade from 5.4 for ring buffer |
| RHEL/Rocky/AlmaLinux 9 | Default (5.14.x) | Full support |
| RHEL 8 | kernel-5.14 (from UBI) | Upgrade recommended |
| Amazon Linux 2023 | Default (6.1.x) | Full support |
| Amazon Linux 2 | kernel-5.10 | Upgrade from 4.14 required |
| Debian 12 (Bookworm) | Default (6.1.x) | Full support |

---

## Memory Footprint Reduction

If the 250-320 MB default memory footprint is too large for your system, apply these reductions:

```yaml
ebpf:
  ring_buf_size_mb: 16          # reduce from 64 -> saves ~48 MB kernel memory
  map_max_entries: 16384        # reduce from 65536 -> saves ~50 MB kernel memory
  max_stack_depth: 64           # reduce from 127 -> saves ~40 MB in stack_traces map
```

With these settings and Preset A, total memory usage drops to approximately **80-90 MB**.

---

## High-Throughput OLTP Tuning

For systems running > 50,000 QPS (pgbench, OLTP workloads):

1. **Raise the slow query threshold** to reduce ring buffer pressure:
   ```yaml
   profiling:
     query_slow_threshold_ms: 200   # only capture truly slow queries
   ```

2. **Disable memory and I/O profilers** during peak load windows.

3. **Use Prometheus-only output** (no JSON file writes during peak load):
   ```bash
   sudo minervadb-profiler --format none --prometheus-port 9187
   ```

4. **Pin the collector process to an isolated CPU core** to avoid L3 cache eviction:
   ```bash
   sudo taskset -c 31 minervadb-profiler
   ```

5. **Increase ring buffer to 128-256 MB** for burst headroom.

---

## Prometheus Scrape Interval

The default Prometheus exposition loop runs at 1-second resolution. Aggregation windows can be configured:

```yaml
output:
  prometheus:
    enabled: true
    port: 9187
    aggregation_window_s: 10   # aggregate over 10s windows (default)
```

Recommended Prometheus `scrape_interval` values:

| Use Case | scrape_interval | retention |
|---|---|---|
| Real-time debugging | 5s | 15d |
| Production monitoring | 15s | 90d |
| Capacity planning | 60s | 1y |

Alerting rule examples (paste into your Prometheus rules file):

```yaml
groups:
  - name: minervadb_postgresql_profiler
    rules:
      - alert: PostgreSQLSlowQueriesHigh
        expr: rate(pg_profiler_slow_queries_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High slow query rate on {{ $labels.instance }}"

      - alert: PostgreSQLLockWaitHigh
        expr: pg_profiler_lock_wait_duration_seconds{quantile="0.99"} > 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "p99 lock wait > 1s on {{ $labels.instance }}"

      - alert: PostgreSQLDeadlockDetected
        expr: increase(pg_profiler_deadlocks_total[5m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "Deadlock detected on {{ $labels.instance }}"

      - alert: PostgreSQLBufferHitRatioLow
        expr: pg_profiler_buffer_hit_ratio < 0.85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Buffer hit ratio below 85% on {{ $labels.instance }}"
```

---

## Flame Graph Performance

Flame graphs are generated as SVG files in `/var/lib/minervadb/flamegraphs/`. Generation is CPU-intensive during the folding step (pure Python). Tuning options:

**Reduce sample collection time** — a 15-second window is usually enough to identify hotspots:

```bash
sudo minervadb-profiler --modules cpu --duration 15
```

**Increase sample rate for shorter windows** — if profiling for only 10 seconds, raise `cpu_sample_hz` to 199 to maintain statistical significance.

**Limit stack depth in the SVG** — the default 127-frame depth produces very wide SVGs. For quick visual inspection, limit to 40 frames:

```bash
sudo minervadb-profiler --modules cpu --duration 30 --flame-max-depth 40
```

---

## Operating System Tuning

These kernel parameters can reduce profiler overhead on busy systems.

```bash
# Increase perf_events buffer to reduce sample loss at high sample rates
echo 524288 > /proc/sys/kernel/perf_event_mlock_kb

# Allow unprivileged perf_events access (useful for CI/testing, not for production)
# echo 1 > /proc/sys/kernel/perf_event_paranoid

# Increase BPF JIT limit (default 264MB on some distros, may need increase for all modules)
echo 1 > /proc/sys/net/core/bpf_jit_enable
echo 268435456 > /proc/sys/net/core/bpf_jit_limit   # 256 MB
```

To persist these settings across reboots, add to `/etc/sysctl.d/99-minervadb-profiler.conf`:

```
kernel.perf_event_mlock_kb = 524288
net.core.bpf_jit_enable = 1
net.core.bpf_jit_limit = 268435456
```

---

## Overhead Estimation Formula

Use this formula to estimate overhead before deploying on a new system:

```
overhead_pct = base_overhead + sum(module_overhead[i]) + ringbuf_drain_overhead

Where:
  base_overhead          = 0.1%   (map manager, event loop)
  query_profiler         = 0.5%   per 10K QPS
  lock_profiler          = 0.2%   per 10K QPS
  io_profiler            = 0.3%   per 10K IOPS
  memory_profiler        = 0.5%   per 100K palloc/sec
  wal_profiler           = 0.2%   per 10K WAL records/sec
  cpu_profiler (99Hz)    = 1.0%   flat (independent of QPS)
  wait_profiler          = 0.1%   flat
  ringbuf_drain_overhead = 0.1%   per 100K events/sec drained
```

Example for a 50K QPS OLTP system with Preset B:

```
overhead = 0.1 + (0.5*5) + (0.2*5) + 0.0 + 0.0 + (0.2*5) + 0.0 + 0.1 + (0.1*3)
         = 0.1 + 2.5 + 1.0 + 1.0 + 0.1 + 0.3
         = 5.0%   <-- exceeds 2% budget; apply Preset A for this QPS
```

At 50K QPS, use Preset A with `query_slow_threshold_ms: 100` to stay under 1% overhead.

---

*See also: [Architecture](architecture.md) | [Troubleshooting](troubleshooting.md) | [Back to README](../README.md)*

*MinervaDB — Data Architecture, Engineering and Operations*
