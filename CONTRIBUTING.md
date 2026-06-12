# Contributing to MinervaDB PostgreSQL Profiler

Thank you for your interest in contributing! Please read this guide before submitting PRs.

## Prerequisites

| Component | Minimum | Purpose |
|-----------|---------|---------|
| Linux kernel | 5.8 | eBPF ring buffer + BTF CO-RE |
| clang/LLVM | 12 | eBPF compilation |
| Python | 3.9 | Userspace collector |
| BCC | 0.25 | eBPF Python bindings |
| PostgreSQL | 12 | Profiling target |

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/MinervaDB-PostgreSQL-Profiler.git
cd MinervaDB-PostgreSQL-Profiler
git remote add upstream https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler.git

# Python environment
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Build eBPF programs
make ebpf
```

## Coding Standards

### Python
- Formatter: `black` (line length 100)
- Linter: `ruff`
- Type checker: `mypy --strict` for new modules
- Docstrings: Google style

```bash
black collector/ && ruff check collector/ --fix && mypy collector/
```

### eBPF C
- Include `// SPDX-License-Identifier: Dual MIT/GPL` header
- Use `BPF_CORE_READ()` for all kernel struct access
- Use `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()` pattern
- Check all `bpf_map_lookup_elem()` return values before use
- Stack size limit: 512 bytes per BPF program

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `perf`, `ci`, `chore`
Scopes: `ebpf`, `collector`, `metrics`, `flamegraph`, `docs`, `ci`, `config`

## Testing

```bash
# Unit tests (no root required)
pytest tests/unit/ -v --cov=collector

# eBPF compilation check
make ebpf-verify
```

## Pull Request Checklist

- [ ] Tests added/updated
- [ ] `black` and `ruff` clean
- [ ] `mypy --strict` passes
- [ ] eBPF verifier passes for `.bpf.c` changes
- [ ] CHANGELOG.md entry added under `[Unreleased]`
- [ ] Documentation updated

## eBPF Development Guidelines

- Never dereference kernel pointers directly — always use `BPF_CORE_READ()`
- Bounded loops only — use `#pragma unroll` or bounded iteration
- Use `BPF_MAP_TYPE_PERCPU_HASH` for hot-path per-PID state
- Prefer `BPF_MAP_TYPE_RINGBUF` over `PERF_EVENT_ARRAY` for kernel 5.8+

## Questions?

Open a [GitHub Discussion](https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/discussions)
or email [engineering@minervadb.com](mailto:engineering@minervadb.com).
