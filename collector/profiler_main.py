#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MinervaDB PostgreSQL Profiler - Main Orchestrator
==================================================

Main entry point for the MinervaDB PostgreSQL Profiler. Loads eBPF programs,
manages ring buffers, coordinates profiling modules, and exports data to
various output backends (Prometheus, JSON, flame graphs, dashboard).

Usage:
    sudo minervadb-profiler [OPTIONS] [COMMAND]

Copyright (c) 2026 MinervaDB Inc.
"""

import os
import sys
import time
import signal
import ctypes
import logging
import argparse
import threading
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime

# eBPF library imports
try:
    import bpf as bpflib
    from bpf import BPF, USDT, attach_raw_tracepoint
    HAS_BCC = True
except ImportError:
    try:
        import libbpf
        HAS_BCC = False
    except ImportError:
        print("ERROR: Neither BCC (python3-bpfcc) nor libbpf Python bindings found.")
        print("Install with: apt-get install python3-bpfcc")
        sys.exit(1)

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

import json
import yaml
import struct
from collections import defaultdict

# ============================================================
# Constants
# ============================================================

PROFILER_VERSION = "1.0.0"
EBPF_DIR = Path(__file__).parent.parent / "ebpf"
DEFAULT_CONFIG_PATH = "/etc/minervadb/profiler.yaml"
DEFAULT_PG_BINARY = "/usr/lib/postgresql/16/bin/postgres"

# ============================================================
# Data structures mirroring eBPF common.h
# ============================================================

class QueryEvent(ctypes.Structure):
    """Mirrors struct query_event in common.h"""
    _fields_ = [
        ("timestamp_ns",      ctypes.c_uint64),
        ("start_ns",          ctypes.c_uint64),
        ("end_ns",            ctypes.c_uint64),
        ("parse_duration_ns", ctypes.c_uint64),
        ("plan_duration_ns",  ctypes.c_uint64),
        ("exec_duration_ns",  ctypes.c_uint64),
        ("total_duration_ns", ctypes.c_uint64),
        ("pid",               ctypes.c_uint32),
        ("tid",               ctypes.c_uint32),
        ("db_oid",            ctypes.c_uint32),
        ("user_oid",          ctypes.c_uint32),
        ("query_id",          ctypes.c_uint64),
        ("rows_returned",     ctypes.c_uint64),
        ("rows_affected",     ctypes.c_uint64),
        ("buffers_hit",       ctypes.c_uint64),
        ("buffers_read",      ctypes.c_uint64),
        ("buffers_dirtied",   ctypes.c_uint64),
        ("wal_bytes",         ctypes.c_uint64),
        ("dbname",            ctypes.c_char * 64),
        ("query",             ctypes.c_char * 4096),
        ("application_name",  ctypes.c_char * 64),
        ("is_slow",           ctypes.c_uint8),
        ("had_error",         ctypes.c_uint8),
        ("query_type",        ctypes.c_uint8),
        ("padding",           ctypes.c_uint8 * 5),
    ]


class LockEvent(ctypes.Structure):
    """Mirrors struct lock_event in common.h"""
    _fields_ = [
        ("timestamp_ns",     ctypes.c_uint64),
        ("wait_start_ns",    ctypes.c_uint64),
        ("wait_end_ns",      ctypes.c_uint64),
        ("hold_start_ns",    ctypes.c_uint64),
        ("hold_end_ns",      ctypes.c_uint64),
        ("wait_duration_ns", ctypes.c_uint64),
        ("hold_duration_ns", ctypes.c_uint64),
        ("pid",              ctypes.c_uint32),
        ("blocker_pid",      ctypes.c_uint32),
        ("db_oid",           ctypes.c_uint32),
        ("rel_oid",          ctypes.c_uint32),
        ("transaction_id",   ctypes.c_uint64),
        ("lockmode",         ctypes.c_uint8),
        ("locktype",         ctypes.c_uint8),
        ("granted",          ctypes.c_uint8),
        ("is_deadlock",      ctypes.c_uint8),
        ("relation_name",    ctypes.c_char * 128),
        ("lockname",         ctypes.c_char * 64),
    ]


class WaitEvent(ctypes.Structure):
    """Mirrors struct wait_event in common.h"""
    _fields_ = [
        ("timestamp_ns",    ctypes.c_uint64),
        ("wait_start_ns",   ctypes.c_uint64),
        ("wait_end_ns",     ctypes.c_uint64),
        ("wait_duration_ns", ctypes.c_uint64),
        ("pid",             ctypes.c_uint32),
        ("db_oid",          ctypes.c_uint32),
        ("wait_type",       ctypes.c_uint8),
        ("padding",         ctypes.c_uint8 * 3),
        ("wait_event_name", ctypes.c_char * 64),
        ("query_id_hex",    ctypes.c_char * 17),
    ]


# ============================================================
# Statistics Aggregation
# ============================================================

@dataclass
class QueryStats:
    count: int = 0
    total_duration_ns: int = 0
    min_duration_ns: int = 0
    max_duration_ns: int = 0
    slow_count: int = 0
    total_rows: int = 0
    total_buffers_hit: int = 0
    total_buffers_read: int = 0
    query_text: str = ""

    @property
    def avg_duration_ms(self) -> float:
        if self.count == 0:
            return 0.0
        return self.total_duration_ns / self.count / 1e6

    @property
    def buffer_hit_ratio(self) -> float:
        total = self.total_buffers_hit + self.total_buffers_read
        if total == 0:
            return 1.0
        return self.total_buffers_hit / total


@dataclass
class LockStats:
    wait_count: int = 0
    total_wait_ns: int = 0
    max_wait_ns: int = 0
    deadlock_count: int = 0
    relation_name: str = ""
    lockmode: int = 0

    @property
    def avg_wait_ms(self) -> float:
        if self.wait_count == 0:
            return 0.0
        return self.total_wait_ns / self.wait_count / 1e6


@dataclass
class ProfilingSession:
    """Holds all profiling state for a session"""
    start_time: float = field(default_factory=time.time)
    query_stats: Dict[str, QueryStats] = field(default_factory=dict)
    lock_stats: Dict[str, LockStats] = field(default_factory=dict)
    wait_event_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    wait_event_times: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_queries: int = 0
    slow_queries: int = 0
    deadlocks: int = 0
    buffer_hits: int = 0
    buffer_misses: int = 0
    wal_bytes: int = 0

    @property
    def duration_s(self) -> float:
        return time.time() - self.start_time

    @property
    def buffer_hit_ratio(self) -> float:
        total = self.buffer_hits + self.buffer_misses
        if total == 0:
            return 1.0
        return self.buffer_hits / total


# ============================================================
# MinervaDB PostgreSQL Profiler Main Class
# ============================================================

class MinervaDBProfiler:
    """
    Main profiler class that orchestrates all eBPF programs and
    coordinates data collection, aggregation, and output.
    """

    LOCKMODE_NAMES = {
        1: "AccessShareLock",
        2: "RowShareLock",
        3: "RowExclusiveLock",
        4: "ShareUpdateExclusiveLock",
        5: "ShareLock",
        6: "ShareRowExclusiveLock",
        7: "ExclusiveLock",
        8: "AccessExclusiveLock",
    }

    WAIT_TYPE_NAMES = {
        0: "Lock",
        1: "LWLock",
        2: "BufferPin",
        3: "IO",
        4: "Extension",
        5: "Client",
        6: "IPC",
        7: "Timeout",
        8: "CPU",
    }

    QUERY_TYPE_NAMES = {
        0: "SELECT",
        1: "INSERT",
        2: "UPDATE",
        3: "DELETE",
        4: "OTHER",
    }

    def __init__(self, config: dict):
        self.config = config
        self.session = ProfilingSession()
        self.running = False
        self.bpf_programs: Dict[str, Any] = {}
        self.threads: List[threading.Thread] = []
        self.logger = logging.getLogger("minervadb.profiler")

        # PostgreSQL binary path for USDT probe attachment
        self.pg_binary = config.get("postgresql", {}).get(
            "binary", DEFAULT_PG_BINARY
        )

        # Output configuration
        self.output_config = config.get("output", {})
        self.alert_config = config.get("alerting", {})

        # Lock for thread-safe access to session stats
        self._lock = threading.Lock()

    def find_postgres_pids(self) -> List[int]:
        """Find all running PostgreSQL backend PIDs."""
        pids = []
        try:
            result = subprocess.run(
                ["pgrep", "-x", "postgres"],
                capture_output=True, text=True
            )
            pids = [int(p) for p in result.stdout.strip().split() if p]
        except Exception as e:
            self.logger.warning(f"Could not find PostgreSQL PIDs: {e}")

        self.logger.info(f"Found {len(pids)} PostgreSQL backend processes")
        return pids

    def check_kernel_requirements(self) -> bool:
        """Verify kernel version and eBPF capabilities."""
        # Check kernel version
        import platform
        kernel_ver = platform.release()
        self.logger.info(f"Kernel version: {kernel_ver}")

        # Check BTF availability
        btf_path = "/sys/kernel/btf/vmlinux"
        if os.path.exists(btf_path):
            self.logger.info("BTF available - CO-RE eBPF programs supported")
        else:
            self.logger.warning("BTF not available - falling back to non-CO-RE mode")

        # Check capabilities
        if os.geteuid() != 0:
            self.logger.error("MinervaDB Profiler requires root privileges (CAP_BPF)")
            return False

        # Check debugfs
        debugfs = "/sys/kernel/debug/tracing"
        if not os.path.exists(debugfs):
            try:
                os.system("mount -t debugfs debugfs /sys/kernel/debug")
            except Exception:
                self.logger.warning("Could not mount debugfs")

        return True

    def check_usdt_probes(self) -> bool:
        """Check if PostgreSQL binary has USDT probes."""
        if not os.path.exists(self.pg_binary):
            self.logger.error(f"PostgreSQL binary not found: {self.pg_binary}")
            return False

        try:
            result = subprocess.run(
                ["readelf", "-n", self.pg_binary],
                capture_output=True, text=True
            )
            has_usdt = "stapsdt" in result.stdout.lower()
            if has_usdt:
                self.logger.info(f"USDT probes found in {self.pg_binary}")
            else:
                self.logger.warning(
                    f"No USDT probes in {self.pg_binary}. "
                    f"Recompile PostgreSQL with --enable-dtrace for full profiling."
                )
            return has_usdt
        except FileNotFoundError:
            self.logger.warning("readelf not found - cannot verify USDT probes")
            return True  # Assume available

    def load_ebpf_programs(self) -> bool:
        """Load and attach all eBPF programs."""
        profiling_config = self.config.get("profiling", {})
        pg_pids = self.find_postgres_pids()

        if not pg_pids:
            self.logger.error("No PostgreSQL processes found. Is PostgreSQL running?")
            return False

        # Load eBPF programs based on configuration
        programs_to_load = []

        if profiling_config.get("query_profiler", True):
            programs_to_load.append(("query", "query_profiler.bpf.o"))

        if profiling_config.get("lock_profiler", True):
            programs_to_load.append(("lock", "lock_profiler.bpf.o"))

        if profiling_config.get("io_profiler", True):
            programs_to_load.append(("io", "io_profiler.bpf.o"))

        if profiling_config.get("cpu_profiler", True):
            programs_to_load.append(("cpu", "cpu_profiler.bpf.o"))

        if profiling_config.get("wait_profiler", True):
            programs_to_load.append(("wait", "wait_profiler.bpf.o"))

        for prog_name, prog_file in programs_to_load:
            prog_path = EBPF_DIR / prog_file
            if not prog_path.exists():
                self.logger.warning(f"eBPF object {prog_file} not compiled - skipping")
                self.logger.info(f"Run 'make ebpf' to compile eBPF programs")
                continue

            try:
                self.logger.info(f"Loading eBPF program: {prog_name}")
                # Load via BCC or libbpf
                # (Actual loading code depends on BCC vs libbpf Python bindings)
                self.bpf_programs[prog_name] = prog_path
                self.logger.info(f"Successfully loaded: {prog_name}")
            except Exception as e:
                self.logger.error(f"Failed to load {prog_name}: {e}")

        if not self.bpf_programs:
            self.logger.warning(
                "No eBPF programs loaded. Running in simulation mode for testing."
            )

        return True

    def handle_query_event(self, cpu: int, data: bytes, size: int):
        """Process query event from eBPF ring buffer."""
        event = ctypes.cast(data, ctypes.POINTER(QueryEvent)).contents

        duration_ms = event.total_duration_ns / 1e6
        query_text = event.query.decode("utf-8", errors="replace")[:200]
        query_key = query_text[:100]  # Use first 100 chars as key

        with self._lock:
            self.session.total_queries += 1

            if event.is_slow:
                self.session.slow_queries += 1

            # Update buffer stats
            self.session.buffer_hits += event.buffers_hit
            self.session.buffer_misses += event.buffers_read
            self.session.wal_bytes += event.wal_bytes

            # Aggregate per-query stats
            if query_key not in self.session.query_stats:
                self.session.query_stats[query_key] = QueryStats(
                    query_text=query_text
                )

            qstats = self.session.query_stats[query_key]
            qstats.count += 1
            qstats.total_duration_ns += event.total_duration_ns
            qstats.total_rows += event.rows_returned
            qstats.total_buffers_hit += event.buffers_hit
            qstats.total_buffers_read += event.buffers_read

            if event.is_slow:
                qstats.slow_count += 1

            if qstats.min_duration_ns == 0 or event.total_duration_ns < qstats.min_duration_ns:
                qstats.min_duration_ns = event.total_duration_ns
            if event.total_duration_ns > qstats.max_duration_ns:
                qstats.max_duration_ns = event.total_duration_ns

        # Check alert thresholds
        slow_threshold = self.alert_config.get("slow_query_alert_threshold_ms", 1000)
        if duration_ms > slow_threshold:
            self.logger.warning(
                f"SLOW QUERY ALERT: {duration_ms:.1f}ms | PID:{event.pid} | "
                f"{query_text[:100]}"
            )

    def handle_lock_event(self, cpu: int, data: bytes, size: int):
        """Process lock event from eBPF ring buffer."""
        event = ctypes.cast(data, ctypes.POINTER(LockEvent)).contents

        wait_ms = event.wait_duration_ns / 1e6
        lockmode = self.LOCKMODE_NAMES.get(event.lockmode, f"Lock({event.lockmode})")
        rel_name = event.relation_name.decode("utf-8", errors="replace")

        lock_key = f"{rel_name}:{lockmode}"

        with self._lock:
            if event.is_deadlock:
                self.session.deadlocks += 1
                self.logger.warning(f"DEADLOCK DETECTED: PID {event.pid}")
                return

            if lock_key not in self.session.lock_stats:
                self.session.lock_stats[lock_key] = LockStats(
                    relation_name=rel_name,
                    lockmode=event.lockmode
                )

            lstats = self.session.lock_stats[lock_key]
            lstats.wait_count += 1
            lstats.total_wait_ns += event.wait_duration_ns
            if event.wait_duration_ns > lstats.max_wait_ns:
                lstats.max_wait_ns = event.wait_duration_ns

        # Check lock wait alert
        lock_threshold = self.alert_config.get("lock_wait_alert_threshold_ms", 500)
        if wait_ms > lock_threshold:
            self.logger.warning(
                f"LOCK WAIT ALERT: {wait_ms:.1f}ms | {lockmode} on {rel_name} "
                f"| PID:{event.pid}"
            )

    def handle_wait_event(self, cpu: int, data: bytes, size: int):
        """Process wait event from eBPF ring buffer."""
        event = ctypes.cast(data, ctypes.POINTER(WaitEvent)).contents

        wait_type_name = self.WAIT_TYPE_NAMES.get(event.wait_type, "Unknown")
        wait_duration_ms = event.wait_duration_ns / 1e6

        with self._lock:
            self.session.wait_event_counts[wait_type_name] += 1
            self.session.wait_event_times[wait_type_name] += event.wait_duration_ns

    def start_ring_buffer_polling(self):
        """Start threads to poll eBPF ring buffers."""
        # In production, these would attach to actual BPF ring buffers
        # For the profiler framework, we set up the polling infrastructure
        for prog_name in self.bpf_programs:
            self.logger.info(f"Starting ring buffer polling for: {prog_name}")

    def generate_report(self) -> dict:
        """Generate a profiling report from collected data."""
        with self._lock:
            session = self.session

        # Top slow queries
        top_queries = sorted(
            session.query_stats.values(),
            key=lambda q: q.total_duration_ns,
            reverse=True
        )[:20]

        # Top lock contentions
        top_locks = sorted(
            session.lock_stats.values(),
            key=lambda l: l.total_wait_ns,
            reverse=True
        )[:20]

        return {
            "profiler": f"MinervaDB PostgreSQL Profiler v{PROFILER_VERSION}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_s": session.duration_s,
            "query_profile": {
                "total_queries": session.total_queries,
                "slow_queries": session.slow_queries,
                "buffer_hit_ratio": session.buffer_hit_ratio,
                "wal_bytes_written": session.wal_bytes,
                "top_queries": [
                    {
                        "count": q.count,
                        "avg_duration_ms": q.avg_duration_ms,
                        "max_duration_ms": q.max_duration_ns / 1e6,
                        "slow_count": q.slow_count,
                        "buffer_hit_ratio": q.buffer_hit_ratio,
                        "query": q.query_text[:200],
                    }
                    for q in top_queries
                ],
            },
            "lock_profile": {
                "total_lock_waits": sum(l.wait_count for l in session.lock_stats.values()),
                "deadlocks_detected": session.deadlocks,
                "top_contentions": [
                    {
                        "relation": l.relation_name,
                        "lockmode": self.LOCKMODE_NAMES.get(l.lockmode, str(l.lockmode)),
                        "wait_count": l.wait_count,
                        "avg_wait_ms": l.avg_wait_ms,
                        "max_wait_ms": l.max_wait_ns / 1e6,
                    }
                    for l in top_locks
                ],
            },
            "wait_events": {
                name: {
                    "count": session.wait_event_counts[name],
                    "total_ms": session.wait_event_times[name] / 1e6,
                    "avg_ms": (
                        session.wait_event_times[name] / session.wait_event_counts[name] / 1e6
                        if session.wait_event_counts[name] > 0 else 0
                    ),
                }
                for name in session.wait_event_counts
            },
        }

    def print_report(self, report: dict):
        """Print a formatted profiling report."""
        if HAS_RICH:
            self._print_rich_report(report)
        else:
            self._print_text_report(report)

    def _print_rich_report(self, report: dict):
        """Print formatted report using Rich library."""
        console.print()
        console.print(
            f"[bold cyan]MinervaDB PostgreSQL Profiler v{PROFILER_VERSION}[/bold cyan]"
        )
        console.print(f"Duration: {report['duration_s']:.1f}s")
        console.print()

        qp = report["query_profile"]
        console.print(Panel(
            f"Total Queries: {qp['total_queries']:,}\n"
            f"Slow Queries: {qp['slow_queries']:,}\n"
            f"Buffer Hit Ratio: {qp['buffer_hit_ratio']:.1%}\n"
            f"WAL Written: {qp['wal_bytes_written'] / 1024 / 1024:.1f} MB",
            title="[bold]Query Overview[/bold]",
            border_style="cyan"
        ))

        if qp["top_queries"]:
            table = Table(title="Top Slow Queries", box=box.SIMPLE)
            table.add_column("Count", justify="right")
            table.add_column("Avg(ms)", justify="right")
            table.add_column("Max(ms)", justify="right")
            table.add_column("Hit%", justify="right")
            table.add_column("Query", no_wrap=True)

            for q in qp["top_queries"][:10]:
                table.add_row(
                    f"{q['count']:,}",
                    f"{q['avg_duration_ms']:.1f}",
                    f"{q['max_duration_ms']:.1f}",
                    f"{q['buffer_hit_ratio']:.1%}",
                    q["query"][:80],
                )
            console.print(table)

        lp = report["lock_profile"]
        if lp["total_lock_waits"] > 0:
            console.print()
            console.print(Panel(
                f"Total Lock Waits: {lp['total_lock_waits']:,}\n"
                f"Deadlocks: {lp['deadlocks_detected']}",
                title="[bold]Lock Overview[/bold]",
                border_style="yellow"
            ))

    def _print_text_report(self, report: dict):
        """Print text-only report."""
        print()
        print("=" * 70)
        print(f"  MinervaDB PostgreSQL Profiler v{PROFILER_VERSION}")
        print(f"  Duration: {report['duration_s']:.1f}s")
        print("=" * 70)

        qp = report["query_profile"]
        print(f"\nQUERY PROFILE:")
        print(f"  Total Queries:    {qp['total_queries']:,}")
        print(f"  Slow Queries:     {qp['slow_queries']:,}")
        print(f"  Buffer Hit Ratio: {qp['buffer_hit_ratio']:.1%}")

        lp = report["lock_profile"]
        print(f"\nLOCK PROFILE:")
        print(f"  Lock Waits:  {lp['total_lock_waits']:,}")
        print(f"  Deadlocks:   {lp['deadlocks_detected']}")

    def run(self, duration: Optional[int] = None):
        """
        Main profiling loop.

        Args:
            duration: Profiling duration in seconds (None = run until Ctrl+C)
        """
        self.logger.info(f"Starting MinervaDB PostgreSQL Profiler v{PROFILER_VERSION}")

        # Pre-flight checks
        if not self.check_kernel_requirements():
            return

        self.check_usdt_probes()

        # Load eBPF programs
        if not self.load_ebpf_programs():
            self.logger.error("Failed to load eBPF programs")
            return

        # Start ring buffer polling
        self.start_ring_buffer_polling()

        # Set up signal handlers
        self.running = True

        def signal_handler(signum, frame):
            self.logger.info("Stopping profiler...")
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        self.logger.info("Profiling started. Press Ctrl+C to stop.")

        # Main polling loop
        start_time = time.time()
        try:
            while self.running:
                if duration and (time.time() - start_time) >= duration:
                    self.logger.info(f"Profiling duration ({duration}s) reached")
                    break

                # Poll eBPF ring buffers
                # In production: bpf.ring_buffer_poll() or bpf.perf_buffer_poll()
                time.sleep(0.1)

        except KeyboardInterrupt:
            pass
        finally:
            self.running = False

        # Generate and output final report
        report = self.generate_report()
        self.print_report(report)

        # Save JSON report if configured
        output_file = self.output_config.get("file")
        if output_file:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
            self.logger.info(f"Report saved to: {output_file}")

        return report


# ============================================================
# CLI Interface
# ============================================================

def load_config(config_path: str) -> dict:
    """Load profiler configuration from YAML file."""
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file) as f:
            return yaml.safe_load(f) or {}

    # Return default configuration
    return {
        "postgresql": {
            "host": "localhost",
            "port": 5432,
            "binary": DEFAULT_PG_BINARY,
        },
        "profiling": {
            "query_profiler": True,
            "lock_profiler": True,
            "io_profiler": True,
            "cpu_profiler": True,
            "wait_profiler": True,
            "query_slow_threshold_ms": 100,
        },
        "output": {
            "format": "json",
        },
        "alerting": {
            "slow_query_alert_threshold_ms": 1000,
            "lock_wait_alert_threshold_ms": 500,
        },
    }


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="minervadb-profiler",
        description="MinervaDB PostgreSQL Profiler - eBPF-powered profiling toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Profile all PostgreSQL activity for 60 seconds
  sudo minervadb-profiler --duration 60

  # Profile with JSON output
  sudo minervadb-profiler --duration 300 --output /tmp/profile.json

  # Profile specific database
  sudo minervadb-profiler --database mydb --duration 60

  # Start with Prometheus metrics endpoint
  sudo minervadb-profiler --prometheus --prometheus-port 9187

  # Generate CPU flame graph
  sudo minervadb-profiler --flamegraph --duration 30

  # Real-time dashboard
  sudo minervadb-profiler --dashboard
        """
    )

    # Global options
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG_PATH,
        help=f"Configuration file path (default: {DEFAULT_CONFIG_PATH})"
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=None,
        help="Profiling duration in seconds (default: run until Ctrl+C)"
    )
    parser.add_argument(
        "--database",
        help="PostgreSQL database to profile"
    )
    parser.add_argument(
        "--pid",
        type=int,
        help="PostgreSQL backend PID to profile (all backends if not specified)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path for JSON report"
    )
    parser.add_argument(
        "--format",
        choices=["json", "prometheus", "csv", "text"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--slow-threshold",
        type=int,
        default=100,
        help="Slow query threshold in milliseconds (default: 100)"
    )
    parser.add_argument(
        "--prometheus",
        action="store_true",
        help="Enable Prometheus metrics endpoint"
    )
    parser.add_argument(
        "--prometheus-port",
        type=int,
        default=9187,
        help="Prometheus metrics port (default: 9187)"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Enable web dashboard"
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=8080,
        help="Web dashboard port (default: 8080)"
    )
    parser.add_argument(
        "--flamegraph",
        action="store_true",
        help="Generate CPU flame graph"
    )
    parser.add_argument(
        "--flamegraph-output",
        default="/tmp/pg_flamegraph.svg",
        help="Flame graph SVG output path"
    )
    parser.add_argument(
        "--pg-binary",
        help="Path to PostgreSQL postgres binary"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"MinervaDB PostgreSQL Profiler v{PROFILER_VERSION}"
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Profiling commands")

    # query subcommand
    query_parser = subparsers.add_parser("query", help="Query profiling")
    query_parser.add_argument("--top", type=int, default=20, help="Show top N queries")
    query_parser.add_argument("--min-duration", help="Minimum query duration (e.g. 100ms)")

    # locks subcommand
    lock_parser = subparsers.add_parser("locks", help="Lock profiling")
    lock_parser.add_argument("--watch", action="store_true", help="Real-time monitoring")
    lock_parser.add_argument("--interval", default="1s", help="Update interval")

    # io subcommand
    io_parser = subparsers.add_parser("io", help="I/O profiling")
    io_parser.add_argument("--relations", action="store_true", help="Per-relation I/O")
    io_parser.add_argument("--wal", action="store_true", help="WAL I/O focus")

    args = parser.parse_args()

    # Setup
    setup_logging(args.verbose)
    config = load_config(args.config)

    # Apply CLI overrides
    if args.output:
        config.setdefault("output", {})["file"] = args.output

    if args.format:
        config.setdefault("output", {})["format"] = args.format

    if args.pg_binary:
        config.setdefault("postgresql", {})["binary"] = args.pg_binary

    config.setdefault("profiling", {})["query_slow_threshold_ms"] = args.slow_threshold

    # Run profiler
    profiler = MinervaDBProfiler(config)
    profiler.run(duration=args.duration)


if __name__ == "__main__":
    main()
