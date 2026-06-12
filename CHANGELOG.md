# Changelog

All notable changes to MinervaDB PostgreSQL Profiler.
Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

### Added
- GitHub Actions CI/CD pipeline
- Grafana dashboard JSON for Prometheus metrics
- `tools/` directory with standalone CLI scripts
- `docs/` directory with architecture and tuning guides

---

## [1.0.0] - 2026-06-12

Initial public release.

### Added

#### eBPF Modules
- `query_profiler.bpf.c`: Full query lifecycle via USDT probes
- `lock_profiler.bpf.c`: Lock contention via LockAcquire/LockRelease uprobes + USDT
- `io_profiler.bpf.c`: Block I/O via block_rq_issue/block_rq_complete tracepoints
- `memory_profiler.bpf.c`: palloc/pfree uprobes with call-site tracking
- `wal_profiler.bpf.c`: WAL write amplification and fsync latency
- `cpu_profiler.bpf.c`: CPU flame graph sampling at configurable Hz
- `wait_profiler.bpf.c`: Real-time wait event sampling via USDT
- `vacuum_profiler.bpf.c`: Autovacuum progress via USDT
- `conn_profiler.bpf.c`: Connection lifecycle via tcp_connect/tcp_close kprobes
- `repl_profiler.bpf.c`: Replication lag via WAL sender/receiver uprobes
- `common.h`: Shared data structures and helper macros

#### Userspace Collector
- `profiler_main.py`: Main orchestrator with BCC/libbpf backend detection,
  `ProfilingModule` enum flags, thread-safe `EventAggregator`, and rich CLI
- `metrics_exporter.py`: Pure-stdlib Prometheus HTTP exporter with histogram support
- `flamegraph_gen.py`: Pure-Python interactive SVG flame graph generator

#### Infrastructure
- `Makefile`, `Dockerfile`, `requirements.txt`, `config/profiler.yaml`
- `scripts/install.sh`: Installation script with dependency checks
- `pyproject.toml`: PEP 517 packaging with black/ruff/mypy/pytest config

#### Documentation
- `README.md`: Enterprise documentation with architecture diagram, comparison table,
  installation guide, usage examples, and performance overhead benchmarks
- `CONTRIBUTING.md`: Dev setup, coding standards, eBPF guidelines, PR checklist
- `SECURITY.md`: Vulnerability disclosure policy and security architecture
- `CHANGELOG.md`: This file

### Fixed
- Corrected BCC Python import from `bpf` to `bcc` module name

### Security
- eBPF programs pass Linux kernel verifier (memory-safe, read-only)
- Query text redaction options documented
- Minimum capability set documented (`CAP_BPF + CAP_PERFMON`)

---

## [0.9.0-beta] - 2026-05-01

Internal beta release (MinervaDB Engineering only).

### Added
- Initial eBPF prototypes for query and lock profiling
- Proof-of-concept Python collector with BCC backend
- Performance validation: < 2% overhead on TPC-B workload confirmed

---

[Unreleased]: https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/releases/tag/v1.0.0
[0.9.0-beta]: https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/releases/tag/v0.9.0-beta
