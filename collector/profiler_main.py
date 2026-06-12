#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MinervaDB PostgreSQL Profiler - Main Orchestrator
=================================================

Enterprise-grade PostgreSQL profiling via eBPF, USDT, kprobes,
uprobes, tracepoints, and perf_events. Provides sub-microsecond
query latency tracing, lock contention analysis, I/O profiling,
CPU flame graphs, wait event sampling, and Prometheus metrics.

Supports:
  - BCC (python3-bpfcc) for kernel 4.x-5.x
  - libbpf CO-RE for kernel 5.8+
  - Graceful degradation when probes are unavailable

Usage:
  sudo minervadb-profiler [OPTIONS] [COMMAND]
  sudo minervadb-profiler query --top 20 --min-duration 100ms
  sudo minervadb-profiler locks --watch
  sudo minervadb-profiler io --relations

Copyright (c) 2026 MinervaDB Inc.
License: MIT
Author: MinervaDB Engineering <engineering@minervadb.com>
"""

from __future__ import annotations

import os
import sys
import time
import signal
import ctypes
import logging
import argparse
import threading
import subprocess
import json
import yaml
import struct
import hashlib
import socket
import textwrap
from typing import Dict, List, Optional, Any, Tuple, Callable
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict, deque
from threading import Lock, Event, Thread
from contextlib import contextmanager, suppress
import statistics
import re
import enum

# ---------------------------------------------------------------------------
# eBPF library detection with graceful fallback
# ---------------------------------------------------------------------------
BPF_BACKEND: str = 'none'
BPF = None
USDT = None

try:
    from bcc import BPF, USDT
    BPF_BACKEND = 'bcc'
except ImportError:
    pass

if BPF_BACKEND == 'none':
    try:
        import libbpf  # type: ignore
        BPF_BACKEND = 'libbpf'
    except ImportError:
        pass

if BPF_BACKEND == 'none':
    print('[ERROR] Neither BCC (python3-bpfcc) nor libbpf Python bindings found.', file=sys.stderr)
    print('Install:  apt-get install python3-bpfcc linux-headers-$(uname -r)', file=sys.stderr)
    sys.exit(1)

# Optional rich terminal UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    class Console:  # type: ignore
        def print(self, *a, **kw): print(*a)
        def log(self, *a, **kw): print(*a)
    console = Console()

# Optional psycopg2 for metadata enrichment
try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROFILER_VERSION = '1.0.0'
EBPF_DIR = Path(__file__).parent.parent / 'ebpf'
DEFAULT_CONFIG = Path('/etc/minervadb/profiler.yaml')
DEFAULT_PG_BINARY = '/usr/lib/postgresql/16/bin/postgres'
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
RING_BUF_SIZE = 64 * 1024 * 1024  # 64 MB
PERF_SAMPLE_HZ = 99  # Relatively prime to most kernel timer frequencies
MAX_STACK_DEPTH = 127
SLOW_QUERY_US = 100_000  # 100 ms
HISTOGRAM_SLOTS = 26  # 2^0 us to 2^25 us (≈33 s)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)
log = logging.getLogger('minervadb.profiler')

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class QueryType(enum.IntEnum):
    UNKNOWN   = 0
    SELECT    = 1
    INSERT    = 2
    UPDATE    = 3
    DELETE    = 4
    DDL       = 5
    UTILITY   = 6

class LockMode(enum.IntEnum):
    ACCESS_SHARE           = 1
    ROW_SHARE              = 2
    ROW_EXCLUSIVE          = 3
    SHARE_UPDATE_EXCLUSIVE = 4
    SHARE                  = 5
    SHARE_ROW_EXCLUSIVE    = 6
    EXCLUSIVE              = 7
    ACCESS_EXCLUSIVE       = 8

class ProfilingModule(enum.Flag):
    QUERY      = enum.auto()
    LOCK       = enum.auto()
    IO         = enum.auto()
    MEMORY     = enum.auto()
    WAL        = enum.auto()
    CPU        = enum.auto()
    WAIT       = enum.auto()
    VACUUM     = enum.auto()
    CONN       = enum.auto()
    REPL       = enum.auto()
    ALL        = (QUERY | LOCK | IO | MEMORY | WAL | CPU | WAIT | VACUUM | CONN | REPL)

# ---------------------------------------------------------------------------
# ctypes structures mirroring eBPF common.h
# ---------------------------------------------------------------------------
class QueryEvent(ctypes.Structure):
    _fields_ = [
        ('timestamp_ns',     ctypes.c_uint64),
        ('start_ns',         ctypes.c_uint64),
        ('end_ns',           ctypes.c_uint64),
        ('parse_duration_ns',ctypes.c_uint64),
        ('plan_duration_ns', ctypes.c_uint64),
        ('exec_duration_ns', ctypes.c_uint64),
        ('total_duration_ns',ctypes.c_uint64),
        ('pid',              ctypes.c_uint32),
        ('tid',              ctypes.c_uint32),
        ('db_oid',           ctypes.c_uint32),
        ('user_oid',         ctypes.c_uint32),
        ('query_id',         ctypes.c_uint64),
        ('rows_returned',    ctypes.c_uint64),
        ('rows_affected',    ctypes.c_uint64),
        ('buffers_hit',      ctypes.c_uint64),
        ('buffers_read',     ctypes.c_uint64),
        ('buffers_dirtied',  ctypes.c_uint64),
        ('wal_bytes',        ctypes.c_uint64),
        ('dbname',           ctypes.c_char * 64),
        ('query',            ctypes.c_char * 4096),
        ('application_name', ctypes.c_char * 64),
        ('is_slow',          ctypes.c_uint8),
        ('had_error',        ctypes.c_uint8),
        ('query_type',       ctypes.c_uint8),
        ('_pad',             ctypes.c_uint8 * 5),
    ]

class LockEvent(ctypes.Structure):
    _fields_ = [
        ('timestamp_ns',   ctypes.c_uint64),
        ('wait_start_ns',  ctypes.c_uint64),
        ('wait_end_ns',    ctypes.c_uint64),
        ('hold_start_ns',  ctypes.c_uint64),
        ('hold_end_ns',    ctypes.c_uint64),
        ('wait_duration_ns',ctypes.c_uint64),
        ('hold_duration_ns',ctypes.c_uint64),
        ('pid',            ctypes.c_uint32),
        ('blocker_pid',    ctypes.c_uint32),
        ('lock_mode',      ctypes.c_uint32),
        ('lock_type',      ctypes.c_uint32),
        ('relation_oid',   ctypes.c_uint32),
        ('db_oid',         ctypes.c_uint32),
        ('dbname',         ctypes.c_char * 64),
        ('relation_name',  ctypes.c_char * 128),
        ('is_deadlock',    ctypes.c_uint8),
        ('_pad',           ctypes.c_uint8 * 7),
    ]

class IOEvent(ctypes.Structure):
    _fields_ = [
        ('timestamp_ns', ctypes.c_uint64),
        ('issue_ns',     ctypes.c_uint64),
        ('complete_ns',  ctypes.c_uint64),
        ('latency_ns',   ctypes.c_uint64),
        ('bytes',        ctypes.c_uint64),
        ('pid',          ctypes.c_uint32),
        ('dev',          ctypes.c_uint32),
        ('sector',       ctypes.c_uint64),
        ('rwflag',       ctypes.c_uint8),
        ('_pad',         ctypes.c_uint8 * 7),
        ('comm',         ctypes.c_char * 16),
    ]

class WaitEvent(ctypes.Structure):
    _fields_ = [
        ('timestamp_ns',    ctypes.c_uint64),
        ('wait_start_ns',   ctypes.c_uint64),
        ('wait_end_ns',     ctypes.c_uint64),
        ('wait_duration_ns',ctypes.c_uint64),
        ('pid',             ctypes.c_uint32),
        ('wait_event_type', ctypes.c_uint32),
        ('wait_event',      ctypes.c_uint32),
        ('_pad',            ctypes.c_uint32),
        ('dbname',          ctypes.c_char * 64),
    ]

# ---------------------------------------------------------------------------
# Data classes for aggregated statistics
# ---------------------------------------------------------------------------
@dataclass
class QueryStats:
    query_id:         int   = 0
    normalized_query: str   = ''
    dbname:           str   = ''
    call_count:       int   = 0
    total_us:         float = 0.0
    min_us:           float = float('inf')
    max_us:           float = 0.0
    samples:          list  = field(default_factory=list)  # sampled latencies (us)
    error_count:      int   = 0
    rows_total:       int   = 0
    buf_hit_total:    int   = 0
    buf_read_total:   int   = 0
    wal_bytes_total:  int   = 0

    @property
    def avg_us(self) -> float:
        return self.total_us / self.call_count if self.call_count else 0.0

    def percentile(self, p: float) -> float:
        if not self.samples:
            return 0.0
        s = sorted(self.samples)
        idx = max(0, int(len(s) * p / 100) - 1)
        return s[idx]

@dataclass
class LockStats:
    lock_mode:       str   = ''
    relation_name:   str   = ''
    dbname:          str   = ''
    wait_count:      int   = 0
    total_wait_us:   float = 0.0
    max_wait_us:     float = 0.0
    deadlock_count:  int   = 0
    blocker_pids:    set   = field(default_factory=set)

@dataclass
class IOStats:
    device:          str   = ''
    read_ops:        int   = 0
    write_ops:       int   = 0
    read_bytes:      int   = 0
    write_bytes:     int   = 0
    read_lat_us:     list  = field(default_factory=list)
    write_lat_us:    list  = field(default_factory=list)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class ProfilerConfig:
    # PostgreSQL connection
    pg_host:          str   = 'localhost'
    pg_port:          int   = 5432
    pg_database:      str   = 'postgres'
    pg_binary:        str   = DEFAULT_PG_BINARY
    pg_pid:           Optional[int] = None

    # eBPF tuning
    cpu_sample_hz:    int   = PERF_SAMPLE_HZ
    max_stack_depth:  int   = MAX_STACK_DEPTH
    map_max_entries:  int   = 65536
    ring_buf_size_mb: int   = 64

    # Profiling modules
    modules:          ProfilingModule = ProfilingModule.ALL

    # Thresholds
    slow_query_ms:    float = 100.0
    lock_min_wait_us: float = 100.0

    # Output
    output_format:    str   = 'json'       # json | csv | text
    output_path:      Optional[str] = None
    prometheus_port:  int   = 9187
    prometheus_enabled: bool = True
    flamegraph_dir:   str   = '/var/lib/minervadb/flamegraphs'

    # Sampling control
    sample_every_n:   int   = 1   # keep 1 of every N samples for histograms
    max_samples_kept: int   = 10000  # rolling window for percentile calculation

    @classmethod
    def from_yaml(cls, path: Path) -> 'ProfilerConfig':
        with open(path) as f:
            raw = yaml.safe_load(f)
        cfg = raw.get('profiler', {})
        pg  = cfg.get('postgresql', {})
        ebpf = cfg.get('ebpf', {})
        out  = cfg.get('output', {})
        thr  = cfg.get('profiling', {})
        obj  = cls()
        obj.pg_host          = pg.get('host', obj.pg_host)
        obj.pg_port          = pg.get('port', obj.pg_port)
        obj.pg_database      = pg.get('database', obj.pg_database)
        obj.pg_binary        = pg.get('binary', obj.pg_binary)
        obj.cpu_sample_hz    = ebpf.get('cpu_sample_hz', obj.cpu_sample_hz)
        obj.map_max_entries  = ebpf.get('map_max_entries', obj.map_max_entries)
        obj.slow_query_ms    = thr.get('query_slow_threshold_ms', obj.slow_query_ms)
        obj.lock_min_wait_us = thr.get('lock_min_wait_us', obj.lock_min_wait_us)
        obj.prometheus_port  = out.get('prometheus', {}).get('port', obj.prometheus_port)
        obj.prometheus_enabled = out.get('prometheus', {}).get('enabled', obj.prometheus_enabled)
        obj.flamegraph_dir   = out.get('flamegraph', {}).get('output_dir', obj.flamegraph_dir)
        return obj

# ---------------------------------------------------------------------------
# eBPF program loader
# ---------------------------------------------------------------------------
class EBPFLoader:
    """Loads and manages eBPF programs for all profiling modules."""

    def __init__(self, config: ProfilerConfig) -> None:
        self.config = config
        self._bpf_objects: Dict[str, Any] = {}
        self._usdt_contexts: List[Any] = []
        self._lock = Lock()

    def _read_source(self, filename: str) -> str:
        path = EBPF_DIR / filename
        if not path.exists():
            raise FileNotFoundError(f'eBPF source not found: {path}')
        return path.read_text()

    def _get_pg_pid(self) -> int:
        if self.config.pg_pid:
            return self.config.pg_pid
        result = subprocess.run(
            ['pgrep', '-f', self.config.pg_binary],
            capture_output=True, text=True, timeout=5
        )
        pids = [int(p) for p in result.stdout.split() if p.strip().isdigit()]
        if not pids:
            raise RuntimeError(f'PostgreSQL process not found: {self.config.pg_binary}')
        return pids[0]

    def load_module(self, module: str, source_file: str,
                    usdt_probes: Optional[List[Tuple[str, str]]] = None) -> Any:
        """
        Load an eBPF source file, optionally attaching USDT probes.
        Returns the BPF object.
        """
        if BPF_BACKEND != 'bcc':
            raise RuntimeError('BCC required for runtime eBPF loading')

        src = self._read_source(source_file)
        cflags = [
            f'-DMAX_ENTRIES={self.config.map_max_entries}',
            f'-DSLOW_QUERY_NS={int(self.config.slow_query_ms * 1_000_000)}',
            f'-DLOCK_MIN_WAIT_NS={int(self.config.lock_min_wait_us * 1000)}',
            '-DMINERVADB_PROFILER=1',
        ]

        usdt_ctx = None
        if usdt_probes:
            pg_pid = self._get_pg_pid()
            usdt_ctx = USDT(pid=pg_pid)
            for probe_name, fn_name in usdt_probes:
                try:
                    usdt_ctx.enable_probe(probe=probe_name, fn_name=fn_name)
                    log.debug('Enabled USDT probe: %s -> %s', probe_name, fn_name)
                except Exception as exc:
                    log.warning('USDT probe unavailable: %s (%s)', probe_name, exc)
            self._usdt_contexts.append(usdt_ctx)

        b = BPF(text=src, cflags=cflags, usdt_contexts=[usdt_ctx] if usdt_ctx else [])
        with self._lock:
            self._bpf_objects[module] = b
        log.info('Loaded eBPF module: %s (backend=%s)', module, BPF_BACKEND)
        return b

    def cleanup(self) -> None:
        with self._lock:
            self._bpf_objects.clear()
        log.info('eBPF programs unloaded')

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = time.monotonic() - self.start_time
            top_q = sorted(self.query_stats.values(), key=lambda q: q.total_us, reverse=True)[:50]
            snap = {}
            snap['elapsed_s'] = round(elapsed, 3)
            snap['total_queries'] = self.total_queries
            snap['total_slow'] = self.total_slow
            snap['total_lock_waits'] = self.total_lock_waits
            snap['total_deadlocks'] = self.total_deadlocks
            snap['top_queries'] = [
                {
                    'query': q.normalized_query[:200], 'dbname': q.dbname,
                    'calls': q.call_count, 'avg_ms': round(q.avg_us / 1000, 3),
                    'p95_ms': round(q.percentile(95) / 1000, 3),
                    'p99_ms': round(q.percentile(99) / 1000, 3),
                    'max_ms': round(q.max_us / 1000, 3), 'errors': q.error_count,
                }
                for q in top_q
            ]
            return snap

# ---------------------------------------------------------------------------
# Ring buffer callbacks
# ---------------------------------------------------------------------------
def make_query_callback(agg: EventAggregator) -> Callable:
    def handle_query(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(QueryEvent)).contents
        try:
            agg.record_query(event)
        except Exception as exc:
            log.error('Query event parse error: %s', exc, exc_info=False)
    return handle_query

def make_lock_callback(agg: EventAggregator) -> Callable:
    def handle_lock(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(LockEvent)).contents
        try:
            agg.record_lock(event)
        except Exception as exc:
            log.error('Lock event parse error: %s', exc, exc_info=False)
    return handle_lock

def make_io_callback(agg: EventAggregator) -> Callable:
    def handle_io(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(IOEvent)).contents
        try:
            agg.record_io(event)
        except Exception as exc:
            log.error('IO event parse error: %s', exc, exc_info=False)
    return handle_io

# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------
class Reporter:
    """Formats and writes profiling output in multiple formats."""

    def __init__(self, config: ProfilerConfig) -> None:
        self.config = config

    def write_json(self, data: dict, path: Optional[str] = None) -> None:
        out = json.dumps(data, indent=2, default=str)
        if path:
            Path(path).write_text(out)
            log.info('Report written to %s', path)
        else:
            print(out)

    def print_summary(self, data: dict) -> None:
        if not HAS_RICH:
            print(json.dumps(data, indent=2, default=str))
            return
        t = Table(title='MinervaDB PostgreSQL Profiler - Query Summary',
                  box=box.MINIMAL_DOUBLE_HEAD, show_header=True)
        t.add_column('Query (normalized)', style='cyan', max_width=60)
        t.add_column('DB', style='green')
        t.add_column('Calls', justify='right')
        t.add_column('Avg ms', justify='right')
        t.add_column('p95 ms', justify='right')
        t.add_column('p99 ms', justify='right')
        t.add_column('Max ms', justify='right')
        t.add_column('Errors', justify='right', style='red')
        for q in data.get('top_queries', [])[:20]:
            t.add_row(
                q['query'][:60], q['dbname'],
                str(q['calls']), str(q['avg_ms']),
                str(q['p95_ms']), str(q['p99_ms']),
                str(q['max_ms']), str(q['errors'])
            )
        console.print(t)
        console.print(f"[bold]Total queries:[/bold] {data['total_queries']} | "
                      f"[bold]Slow:[/bold] {data['total_slow']} | "
                      f"[bold]Lock waits:[/bold] {data['total_lock_waits']} | "
                      f"[bold]Deadlocks:[/bold] {data['total_deadlocks']}")

# ---------------------------------------------------------------------------
# Main profiler orchestrator
# ---------------------------------------------------------------------------
class MinervaDBProfiler:
    """
    Top-level profiler: loads eBPF programs, manages threads,
    aggregates events, and drives output.
    """

    QUERY_USDT = [
        ('query__start',         'trace_query_start'),
        ('query__done',          'trace_query_done'),
        ('query__parse__start',  'trace_parse_start'),
        ('query__parse__done',   'trace_parse_done'),
        ('query__plan__start',   'trace_plan_start'),
        ('query__plan__done',    'trace_plan_done'),
        ('query__execute__start','trace_exec_start'),
        ('query__execute__done', 'trace_exec_done'),
    ]

    LOCK_USDT = [
        ('lock__wait__start', 'trace_lock_wait_start'),
        ('lock__wait__done',  'trace_lock_wait_done'),
        ('deadlock__found',   'trace_deadlock'),
    ]

    def __init__(self, config: ProfilerConfig) -> None:
        self.config  = config
        self.loader  = EBPFLoader(config)
        self.agg     = EventAggregator(config)
        self.reporter = Reporter(config)
        self._stop_event = Event()
        self._threads: List[Thread] = []
        self._bpf_objects: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Startup / Shutdown
    # ------------------------------------------------------------------
    def start(self) -> None:
        log.info('MinervaDB PostgreSQL Profiler v%s starting (backend=%s)',
                 PROFILER_VERSION, BPF_BACKEND)
        self._load_modules()
        self._start_perf_readers()
        if self.config.prometheus_enabled:
            self._start_prometheus()
        signal.signal(signal.SIGINT,  self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        log.info('Profiler running. Press Ctrl-C to stop.')

    def stop(self) -> None:
        log.info('Stopping profiler...')
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=5)
        self.loader.cleanup()
        log.info('Profiler stopped')

    def _handle_signal(self, signum, frame) -> None:
        log.info('Signal %d received, shutting down', signum)
        self.stop()

    def run(self, duration_s: Optional[float] = None) -> dict:
        self.start()
        try:
            if duration_s:
                self._stop_event.wait(timeout=duration_s)
            else:
                self._stop_event.wait()
        finally:
            self.stop()
        return self.agg.snapshot()

    # ------------------------------------------------------------------
    # eBPF module loading
    # ------------------------------------------------------------------
    def _load_modules(self) -> None:
        mods = self.config.modules
        if ProfilingModule.QUERY in mods:
            self._safe_load('query', 'query_profiler.bpf.c', self.QUERY_USDT)
        if ProfilingModule.LOCK in mods:
            self._safe_load('lock', 'lock_profiler.bpf.c', self.LOCK_USDT)
        if ProfilingModule.IO in mods:
            self._safe_load('io', 'io_profiler.bpf.c')
        if ProfilingModule.MEMORY in mods:
            self._safe_load('memory', 'memory_profiler.bpf.c')
        if ProfilingModule.WAL in mods:
            self._safe_load('wal', 'wal_profiler.bpf.c')
        if ProfilingModule.CPU in mods:
            self._safe_load('cpu', 'cpu_profiler.bpf.c')
        if ProfilingModule.WAIT in mods:
            self._safe_load('wait', 'wait_profiler.bpf.c')
        if ProfilingModule.VACUUM in mods:
            self._safe_load('vacuum', 'vacuum_profiler.bpf.c')
        if ProfilingModule.CONN in mods:
            self._safe_load('conn', 'conn_profiler.bpf.c')
        if ProfilingModule.REPL in mods:
            self._safe_load('repl', 'repl_profiler.bpf.c')

    def _safe_load(self, name: str, source: str,
                   usdt: Optional[list] = None) -> None:
        try:
            b = self.loader.load_module(name, source, usdt)
            self._bpf_objects[name] = b
        except FileNotFoundError as exc:
            log.warning('eBPF source missing, skipping module %s: %s', name, exc)
        except Exception as exc:
            log.error('Failed to load eBPF module %s: %s', name, exc, exc_info=True)

    # ------------------------------------------------------------------
    # Perf buffer / ring buffer readers
    # ------------------------------------------------------------------
    def _start_perf_readers(self) -> None:
        if 'query' in self._bpf_objects:
            self._attach_perf('query', 'query_events', make_query_callback(self.agg))
        if 'lock' in self._bpf_objects:
            self._attach_perf('lock', 'lock_events', make_lock_callback(self.agg))
        if 'io' in self._bpf_objects:
            self._attach_perf('io', 'io_events', make_io_callback(self.agg))

    def _attach_perf(self, module: str, map_name: str, callback: Callable) -> None:
        b = self._bpf_objects[module]
        try:
            b[map_name].open_perf_buffer(callback, page_cnt=64)
            t = Thread(target=self._poll_loop, args=(b,), daemon=True,
                       name=f'perf-{module}')
            t.start()
            self._threads.append(t)
            log.debug('Perf reader started for map %s', map_name)
        except KeyError:
            log.warning('Map %s not found in module %s', map_name, module)
        except Exception as exc:
            log.error('Perf attach failed for %s: %s', map_name, exc)

    def _poll_loop(self, b: Any) -> None:
        while not self._stop_event.is_set():
            try:
                b.perf_buffer_poll(timeout=200)
            except Exception as exc:
                log.error('Perf poll error: %s', exc)
                break

    # ------------------------------------------------------------------
    # Prometheus exporter (background thread)
    # ------------------------------------------------------------------
    def _start_prometheus(self) -> None:
        try:
            from collector.metrics_exporter import MetricsExporter
            exp = MetricsExporter(self.agg, self.config)
            t = Thread(target=exp.run, daemon=True, name='prometheus-exporter')
            t.start()
            self._threads.append(t)
            log.info('Prometheus metrics on :%d/metrics', self.config.prometheus_port)
        except ImportError as exc:
            log.warning('Prometheus exporter unavailable: %s', exc)
        except Exception as exc:
            log.error('Failed to start Prometheus exporter: %s', exc)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='minervadb-profiler',
        description='MinervaDB PostgreSQL Profiler v' + PROFILER_VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        Examples:
          sudo minervadb-profiler --duration 60 --output /tmp/profile.json
          sudo minervadb-profiler query --top 20 --min-duration 100ms
          sudo minervadb-profiler locks --watch --interval 1s
          sudo minervadb-profiler io --relations --database mydb
          sudo minervadb-profiler cpu --flamegraph --duration 30
        ''')
    )
    p.add_argument('--version', action='version', version=PROFILER_VERSION)
    p.add_argument('--config', default=str(DEFAULT_CONFIG),
                   help='Path to profiler YAML config (default: /etc/minervadb/profiler.yaml)')
    p.add_argument('--pg-binary', help='Path to postgres binary')
    p.add_argument('--pg-pid',   type=int, help='PostgreSQL postmaster PID')
    p.add_argument('--duration', type=float, default=None,
                   help='Profiling duration in seconds (default: run until Ctrl-C)')
    p.add_argument('--output',   help='Output file path (default: stdout)')
    p.add_argument('--format',   choices=['json', 'csv', 'text'], default='json',
                   help='Output format (default: json)')
    p.add_argument('--modules',  default='all',
                   help='Comma-separated modules to enable: query,lock,io,memory,wal,cpu,wait,vacuum,conn,repl (default: all)')
    p.add_argument('--no-prometheus', action='store_true',
                   help='Disable Prometheus metrics exporter')
    p.add_argument('--prometheus-port', type=int, default=9187,
                   help='Prometheus exporter port (default: 9187)')
    p.add_argument('--slow-query-ms', type=float, default=100.0,
                   help='Slow query threshold in ms (default: 100)')
    p.add_argument('--verbose', '-v', action='store_true',
                   help='Enable verbose debug logging')
    return p

def parse_modules(spec: str) -> ProfilingModule:
    if spec.lower() == 'all':
        return ProfilingModule.ALL
    result = ProfilingModule(0)
    mapping = {
        'query':  ProfilingModule.QUERY,
        'lock':   ProfilingModule.LOCK,
        'io':     ProfilingModule.IO,
        'memory': ProfilingModule.MEMORY,
        'wal':    ProfilingModule.WAL,
        'cpu':    ProfilingModule.CPU,
        'wait':   ProfilingModule.WAIT,
        'vacuum': ProfilingModule.VACUUM,
        'conn':   ProfilingModule.CONN,
        'repl':   ProfilingModule.REPL,
    }
    for part in spec.split(','):
        part = part.strip().lower()
        if part in mapping:
            result |= mapping[part]
        else:
            log.warning('Unknown module: %s (choices: %s)', part, ', '.join(mapping))
    return result

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        log.error('Root privileges required for eBPF. Re-run with sudo.')
        return 1

    # Build config
    config_path = Path(args.config)
    if config_path.exists():
        config = ProfilerConfig.from_yaml(config_path)
        log.info('Loaded config from %s', config_path)
    else:
        config = ProfilerConfig()
        log.warning('Config not found at %s, using defaults', config_path)

    # Apply CLI overrides
    if args.pg_binary:
        config.pg_binary = args.pg_binary
    if args.pg_pid:
        config.pg_pid = args.pg_pid
    if args.no_prometheus:
        config.prometheus_enabled = False
    config.prometheus_port = args.prometheus_port
    config.output_format   = args.format
    config.output_path     = args.output
    config.slow_query_ms   = args.slow_query_ms
    config.modules         = parse_modules(args.modules)

    # Run profiler
    profiler = MinervaDBProfiler(config)
    try:
        result = profiler.run(duration_s=args.duration)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log.error('Profiler error: %s', exc, exc_info=True)
        return 2

    # Output result
    reporter = Reporter(config)
    if config.output_format == 'json':
        reporter.write_json(result, config.output_path)
    else:
        reporter.print_summary(result)
    return 0

if __name__ == '__main__':
    sys.exit(main())
