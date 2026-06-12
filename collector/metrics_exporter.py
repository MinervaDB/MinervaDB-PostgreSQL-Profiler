#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MinervaDB PostgreSQL Profiler - Prometheus Metrics Exporter
===========================================================

Exports profiling metrics in Prometheus exposition format.
Runs an HTTP server at /metrics endpoint for Prometheus scraping.

Metrics exposed:
  - pg_profiler_query_duration_seconds (histogram)
  - pg_profiler_query_total (counter)
  - pg_profiler_slow_queries_total (counter)
  - pg_profiler_buffer_hit_ratio (gauge)
  - pg_profiler_lock_waits_total (counter)
  - pg_profiler_lock_wait_duration_seconds (histogram)
  - pg_profiler_deadlocks_total (counter)
  - pg_profiler_wait_event_total (counter by type)
  - pg_profiler_wait_event_duration_seconds (histogram by type)
  - pg_profiler_io_read_bytes_total (counter)
  - pg_profiler_io_write_bytes_total (counter)
  - pg_profiler_io_read_duration_seconds (histogram)
  - pg_profiler_io_fsync_duration_seconds (histogram)
  - pg_profiler_wal_bytes_total (counter)
  - pg_profiler_connections_total (counter)
  - pg_profiler_active_connections (gauge)

Copyright (c) 2026 MinervaDB Inc.
"""

import time
import threading
import logging
from typing import Dict, Optional, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import StringIO

try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, Info,
        CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST,
        start_http_server
    )
    HAS_PROMETHEUS_CLIENT = True
except ImportError:
    HAS_PROMETHEUS_CLIENT = False

logger = logging.getLogger("minervadb.metrics_exporter")

# ============================================================
# Metric Definitions
# ============================================================

# Query latency histogram buckets (in seconds)
QUERY_LATENCY_BUCKETS = (
    0.0001,   # 100us
    0.0005,   # 500us
    0.001,    # 1ms
    0.005,    # 5ms
    0.01,     # 10ms
    0.025,    # 25ms
    0.05,     # 50ms
    0.1,      # 100ms
    0.25,     # 250ms
    0.5,      # 500ms
    1.0,      # 1s
    2.5,      # 2.5s
    5.0,      # 5s
    10.0,     # 10s
    30.0,     # 30s
    float("inf")
)

# I/O latency histogram buckets (in seconds)
IO_LATENCY_BUCKETS = (
    0.0001,   # 100us (fast SSD)
    0.0005,   # 500us
    0.001,    # 1ms
    0.005,    # 5ms
    0.01,     # 10ms
    0.05,     # 50ms
    0.1,      # 100ms
    0.5,      # 500ms
    1.0,      # 1s (very slow)
    float("inf")
)

# Lock wait histogram buckets (in seconds)
LOCK_WAIT_BUCKETS = (
    0.000100,  # 100us
    0.000500,  # 500us
    0.001,     # 1ms
    0.005,     # 5ms
    0.010,     # 10ms
    0.050,     # 50ms
    0.100,     # 100ms
    0.500,     # 500ms
    1.000,     # 1s
    5.000,     # 5s
    float("inf")
)


class MinervaDBMetricsExporter:
    """
    Prometheus metrics exporter for MinervaDB PostgreSQL Profiler.

    Maintains Prometheus metric objects and provides methods to update
    them from eBPF profiling data. Exposes a /metrics HTTP endpoint.
    """

    def __init__(self, port: int = 9187, host: str = "0.0.0.0",
                 registry: Optional[Any] = None):
        self.port = port
        self.host = host

        if HAS_PROMETHEUS_CLIENT:
            self.registry = registry or CollectorRegistry()
            self._init_metrics()
        else:
            logger.warning(
                "prometheus_client not installed. Metrics will not be exported. "
                "Install with: pip3 install prometheus-client"
            )
            self.registry = None

        self._server_thread = None
        self._running = False

    def _init_metrics(self):
        """Initialize all Prometheus metrics."""
        labels = ["database", "host"]

        # ============================================================
        # Query Metrics
        # ============================================================
        self.query_duration = Histogram(
            "pg_profiler_query_duration_seconds",
            "PostgreSQL query execution duration",
            labelnames=labels + ["query_type"],
            buckets=QUERY_LATENCY_BUCKETS,
            registry=self.registry,
        )

        self.query_total = Counter(
            "pg_profiler_queries_total",
            "Total number of PostgreSQL queries executed",
            labelnames=labels + ["query_type"],
            registry=self.registry,
        )

        self.slow_query_total = Counter(
            "pg_profiler_slow_queries_total",
            "Total number of slow PostgreSQL queries",
            labelnames=labels + ["query_type"],
            registry=self.registry,
        )

        self.query_rows_total = Counter(
            "pg_profiler_query_rows_total",
            "Total rows returned/affected by queries",
            labelnames=labels + ["query_type", "operation"],
            registry=self.registry,
        )

        # ============================================================
        # Buffer Cache Metrics
        # ============================================================
        self.buffer_hits_total = Counter(
            "pg_profiler_buffer_hits_total",
            "Total PostgreSQL shared buffer cache hits",
            labelnames=labels,
            registry=self.registry,
        )

        self.buffer_misses_total = Counter(
            "pg_profiler_buffer_misses_total",
            "Total PostgreSQL shared buffer cache misses (disk reads)",
            labelnames=labels,
            registry=self.registry,
        )

        self.buffer_hit_ratio = Gauge(
            "pg_profiler_buffer_hit_ratio",
            "PostgreSQL shared buffer cache hit ratio (0.0-1.0)",
            labelnames=labels,
            registry=self.registry,
        )

        self.buffer_dirtied_total = Counter(
            "pg_profiler_buffer_dirtied_total",
            "Total shared buffers dirtied",
            labelnames=labels,
            registry=self.registry,
        )

        # ============================================================
        # Lock Metrics
        # ============================================================
        self.lock_waits_total = Counter(
            "pg_profiler_lock_waits_total",
            "Total number of lock wait events",
            labelnames=labels + ["lock_type", "lock_mode"],
            registry=self.registry,
        )

        self.lock_wait_duration = Histogram(
            "pg_profiler_lock_wait_duration_seconds",
            "PostgreSQL lock wait duration",
            labelnames=labels + ["lock_type", "lock_mode"],
            buckets=LOCK_WAIT_BUCKETS,
            registry=self.registry,
        )

        self.lock_hold_duration = Histogram(
            "pg_profiler_lock_hold_duration_seconds",
            "PostgreSQL lock hold duration",
            labelnames=labels + ["lock_type", "lock_mode"],
            buckets=LOCK_WAIT_BUCKETS,
            registry=self.registry,
        )

        self.deadlocks_total = Counter(
            "pg_profiler_deadlocks_total",
            "Total number of deadlocks detected",
            labelnames=labels,
            registry=self.registry,
        )

        # ============================================================
        # I/O Metrics
        # ============================================================
        self.io_reads_total = Counter(
            "pg_profiler_io_reads_total",
            "Total block I/O read operations",
            labelnames=labels + ["relation"],
            registry=self.registry,
        )

        self.io_writes_total = Counter(
            "pg_profiler_io_writes_total",
            "Total block I/O write operations",
            labelnames=labels + ["relation"],
            registry=self.registry,
        )

        self.io_read_bytes_total = Counter(
            "pg_profiler_io_read_bytes_total",
            "Total bytes read from disk",
            labelnames=labels + ["relation"],
            registry=self.registry,
        )

        self.io_write_bytes_total = Counter(
            "pg_profiler_io_write_bytes_total",
            "Total bytes written to disk",
            labelnames=labels + ["relation"],
            registry=self.registry,
        )

        self.io_read_duration = Histogram(
            "pg_profiler_io_read_duration_seconds",
            "Block I/O read latency",
            labelnames=labels + ["device"],
            buckets=IO_LATENCY_BUCKETS,
            registry=self.registry,
        )

        self.io_write_duration = Histogram(
            "pg_profiler_io_write_duration_seconds",
            "Block I/O write latency",
            labelnames=labels + ["device"],
            buckets=IO_LATENCY_BUCKETS,
            registry=self.registry,
        )

        self.io_fsync_duration = Histogram(
            "pg_profiler_io_fsync_duration_seconds",
            "fsync latency",
            labelnames=labels,
            buckets=IO_LATENCY_BUCKETS,
            registry=self.registry,
        )

        # ============================================================
        # WAL Metrics
        # ============================================================
        self.wal_bytes_total = Counter(
            "pg_profiler_wal_bytes_total",
            "Total WAL bytes generated",
            labelnames=labels,
            registry=self.registry,
        )

        self.wal_write_duration = Histogram(
            "pg_profiler_wal_write_duration_seconds",
            "WAL write duration",
            labelnames=labels,
            buckets=IO_LATENCY_BUCKETS,
            registry=self.registry,
        )

        self.wal_flush_duration = Histogram(
            "pg_profiler_wal_flush_duration_seconds",
            "WAL flush (fsync) duration",
            labelnames=labels,
            buckets=IO_LATENCY_BUCKETS,
            registry=self.registry,
        )

        # ============================================================
        # Wait Event Metrics
        # ============================================================
        self.wait_events_total = Counter(
            "pg_profiler_wait_events_total",
            "Total wait events by type",
            labelnames=labels + ["wait_type", "wait_event"],
            registry=self.registry,
        )

        self.wait_event_duration = Histogram(
            "pg_profiler_wait_event_duration_seconds",
            "Wait event duration by type",
            labelnames=labels + ["wait_type"],
            buckets=LOCK_WAIT_BUCKETS,
            registry=self.registry,
        )

        self.active_wait_events = Gauge(
            "pg_profiler_active_wait_events",
            "Current number of backends waiting by wait type",
            labelnames=labels + ["wait_type"],
            registry=self.registry,
        )

        # ============================================================
        # Connection Metrics
        # ============================================================
        self.connections_total = Counter(
            "pg_profiler_connections_total",
            "Total PostgreSQL connections established",
            labelnames=labels + ["application"],
            registry=self.registry,
        )

        self.active_connections = Gauge(
            "pg_profiler_active_connections",
            "Current active PostgreSQL connections",
            labelnames=labels,
            registry=self.registry,
        )

        self.connection_duration = Histogram(
            "pg_profiler_connection_duration_seconds",
            "PostgreSQL session duration",
            labelnames=labels + ["application"],
            buckets=(1, 5, 30, 60, 300, 900, 3600, float("inf")),
            registry=self.registry,
        )

        self.connection_auth_duration = Histogram(
            "pg_profiler_connection_auth_duration_seconds",
            "PostgreSQL authentication duration",
            labelnames=labels,
            buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, float("inf")),
            registry=self.registry,
        )

        # ============================================================
        # CPU Metrics
        # ============================================================
        self.cpu_usage_seconds_total = Counter(
            "pg_profiler_cpu_usage_seconds_total",
            "Total CPU time consumed by PostgreSQL backends",
            labelnames=labels + ["state"],
            registry=self.registry,
        )

        self.context_switches_total = Counter(
            "pg_profiler_context_switches_total",
            "Total context switches for PostgreSQL backends",
            labelnames=labels + ["type"],
            registry=self.registry,
        )

        # ============================================================
        # Profiler Info Metric
        # ============================================================
        self.profiler_info = Info(
            "pg_profiler",
            "MinervaDB PostgreSQL Profiler information",
            registry=self.registry,
        )
        self.profiler_info.info({
            "version": "1.0.0",
            "ebpf": "true",
            "vendor": "MinervaDB Inc.",
        })

        # ============================================================
        # Scrape Metrics
        # ============================================================
        self.scrape_duration = Gauge(
            "pg_profiler_last_scrape_duration_seconds",
            "Duration of last profiler data collection",
            registry=self.registry,
        )

        self.scrape_success = Gauge(
            "pg_profiler_last_scrape_success",
            "Whether the last profiler scrape was successful (1=yes, 0=no)",
            registry=self.registry,
        )

        logger.info("Prometheus metrics initialized")

    def update_from_session(self, session: Any, database: str = "unknown",
                            host: str = "localhost"):
        """
        Update all metrics from a ProfilingSession object.

        Called periodically by the profiler to push current stats
        to Prometheus metric objects.
        """
        if not HAS_PROMETHEUS_CLIENT or not self.registry:
            return

        start = time.time()
        try:
            labels = {"database": database, "host": host}

            # Buffer cache metrics
            if session.buffer_hits + session.buffer_misses > 0:
                self.buffer_hit_ratio.labels(**labels).set(
                    session.buffer_hit_ratio
                )

            # WAL metrics
            self.wal_bytes_total.labels(**labels)._value.set(
                session.wal_bytes
            )

            # Lock metrics
            if session.deadlocks > 0:
                self.deadlocks_total.labels(**labels)._value.set(
                    session.deadlocks
                )

            # Wait event metrics
            for wait_type, count in session.wait_event_counts.items():
                self.wait_events_total.labels(
                    wait_type=wait_type,
                    wait_event="all",
                    **labels
                )._value.set(count)

            self.scrape_success.set(1)

        except Exception as e:
            logger.error(f"Failed to update Prometheus metrics: {e}")
            self.scrape_success.set(0)

        finally:
            self.scrape_duration.set(time.time() - start)

    def record_query(self, duration_s: float, query_type: str,
                     database: str = "unknown", host: str = "localhost",
                     is_slow: bool = False, rows: int = 0,
                     buffers_hit: int = 0, buffers_read: int = 0):
        """Record metrics for a completed query."""
        if not HAS_PROMETHEUS_CLIENT:
            return

        labels = {"database": database, "host": host, "query_type": query_type}

        self.query_duration.labels(**labels).observe(duration_s)
        self.query_total.labels(**labels).inc()

        if is_slow:
            self.slow_query_total.labels(**labels).inc()

        if rows > 0:
            self.query_rows_total.labels(
                operation="returned", **labels
            ).inc(rows)

        if buffers_hit > 0:
            self.buffer_hits_total.labels(
                database=database, host=host
            ).inc(buffers_hit)

        if buffers_read > 0:
            self.buffer_misses_total.labels(
                database=database, host=host
            ).inc(buffers_read)

    def record_lock_wait(self, wait_s: float, lock_type: str, lock_mode: str,
                         database: str = "unknown", host: str = "localhost"):
        """Record metrics for a lock wait event."""
        if not HAS_PROMETHEUS_CLIENT:
            return

        labels = {
            "database": database, "host": host,
            "lock_type": lock_type, "lock_mode": lock_mode
        }
        self.lock_waits_total.labels(**labels).inc()
        self.lock_wait_duration.labels(**labels).observe(wait_s)

    def record_io(self, duration_s: float, bytes_count: int, is_write: bool,
                  device: str = "unknown", relation: str = "unknown",
                  database: str = "unknown", host: str = "localhost"):
        """Record metrics for an I/O operation."""
        if not HAS_PROMETHEUS_CLIENT:
            return

        base_labels = {"database": database, "host": host}

        if is_write:
            self.io_writes_total.labels(
                relation=relation, **base_labels
            ).inc()
            self.io_write_bytes_total.labels(
                relation=relation, **base_labels
            ).inc(bytes_count)
            self.io_write_duration.labels(
                device=device, **base_labels
            ).observe(duration_s)
        else:
            self.io_reads_total.labels(
                relation=relation, **base_labels
            ).inc()
            self.io_read_bytes_total.labels(
                relation=relation, **base_labels
            ).inc(bytes_count)
            self.io_read_duration.labels(
                device=device, **base_labels
            ).observe(duration_s)

    def record_wait_event(self, wait_type: str, wait_event: str,
                          duration_s: float,
                          database: str = "unknown", host: str = "localhost"):
        """Record metrics for a wait event."""
        if not HAS_PROMETHEUS_CLIENT:
            return

        self.wait_events_total.labels(
            database=database, host=host,
            wait_type=wait_type, wait_event=wait_event
        ).inc()

        self.wait_event_duration.labels(
            database=database, host=host,
            wait_type=wait_type
        ).observe(duration_s)

    def generate_text_metrics(self) -> str:
        """
        Generate Prometheus text format metrics manually
        (used when prometheus_client is not available).
        """
        output = []
        output.append("# MinervaDB PostgreSQL Profiler Metrics")
        output.append(f"# Generated at {time.time()}")
        output.append("")
        output.append("# HELP pg_profiler_info Profiler version information")
        output.append("# TYPE pg_profiler_info gauge")
        output.append('pg_profiler_info{version="1.0.0",vendor="MinervaDB"} 1')
        output.append("")
        return "\n".join(output)

    def start_server(self):
        """Start the Prometheus HTTP metrics server."""
        if not HAS_PROMETHEUS_CLIENT:
            logger.error(
                "prometheus_client not available. Cannot start metrics server. "
                "Install with: pip3 install prometheus-client"
            )
            return

        self._running = True

        def serve():
            try:
                start_http_server(self.port, addr=self.host, registry=self.registry)
                logger.info(
                    f"Prometheus metrics server started on {self.host}:{self.port}/metrics"
                )
                while self._running:
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Metrics server failed: {e}")

        self._server_thread = threading.Thread(target=serve, daemon=True)
        self._server_thread.start()
        logger.info(f"Metrics server starting on port {self.port}")

    def stop_server(self):
        """Stop the metrics server."""
        self._running = False
        if self._server_thread:
            self._server_thread.join(timeout=5)
        logger.info("Metrics server stopped")
