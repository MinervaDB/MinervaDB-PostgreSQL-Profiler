#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MinervaDB PostgreSQL Profiler - Prometheus Metrics Exporter
===========================================================

Exposes profiling data collected by the eBPF modules as a Prometheus
metrics endpoint on /metrics.  Designed to integrate with standard
Prometheus + Grafana observability stacks.

Metrics exposed:
  pg_profiler_query_duration_seconds   - query latency histogram (by db, type)
  pg_profiler_query_total              - total query counter (by db)
  pg_profiler_slow_queries_total       - slow query counter (by db)
  pg_profiler_query_errors_total       - query error counter (by db)
  pg_profiler_lock_wait_seconds        - lock wait histogram (by mode, relation)
  pg_profiler_lock_waits_total         - total lock wait counter
  pg_profiler_deadlocks_total          - deadlock counter
  pg_profiler_io_bytes_total           - bytes read/written (by device, direction)
  pg_profiler_io_ops_total             - I/O operations (by device, direction)
  pg_profiler_io_latency_seconds       - I/O latency histogram
  pg_profiler_buffer_hit_ratio         - shared buffer cache hit ratio
  pg_profiler_wal_bytes_total          - WAL bytes written
  pg_profiler_scrape_duration_seconds  - exporter internal scrape duration

Copyright (c) 2026 MinervaDB Inc.
License: MIT
"""

from __future__ import annotations

import time
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import TYPE_CHECKING, List, Optional
from io import StringIO

if TYPE_CHECKING:
    from collector.profiler_main import EventAggregator, ProfilerConfig

log = logging.getLogger('minervadb.metrics')

# ---------------------------------------------------------------------------
# Prometheus text format helpers
# ---------------------------------------------------------------------------
def _labels(**kv) -> str:
    """Format label dict as Prometheus label string."""
    if not kv:
        return ''
    parts = [f'{k}={repr(str(v))}' for k, v in sorted(kv.items())]
    return '{' + ','.join(parts) + '}'

class PrometheusRegistry:
    """Minimal Prometheus text-format metric registry."""

    def __init__(self) -> None:
        self._lines: List[str] = []

    def _emit(self, name: str, labels: dict, value: float,
              kind: str, help_text: str, unit: str = '') -> None:
        full = name + (f'_{unit}' if unit else '')
        self._lines.append(f'# HELP {full} {help_text}')
        self._lines.append(f'# TYPE {full} {kind}')
        self._lines.append(f'{full}{_labels(**labels)} {value}')

    def counter(self, name: str, value: float, help_text: str, **labels) -> None:
        self._emit(name, labels, value, 'counter', help_text)

    def gauge(self, name: str, value: float, help_text: str, **labels) -> None:
        self._emit(name, labels, value, 'gauge', help_text)

    def histogram(self, name: str, samples: list, buckets: list,
                  help_text: str, **labels) -> None:
        self._lines.append(f'# HELP {name} {help_text}')
        self._lines.append(f'# TYPE {name} histogram')
        label_str = _labels(**labels)
        sorted_s = sorted(samples)
        total = len(sorted_s)
        idx = 0
        for b in buckets:
            while idx < total and sorted_s[idx] <= b:
                idx += 1
            self._lines.append(f'{name}_bucket{_labels(le=b, **labels)} {idx}')
        self._lines.append(f'{name}_bucket{_labels(le="+Inf", **labels)} {total}')
        self._lines.append(f'{name}_count{label_str} {total}')
        s = sum(sorted_s) if sorted_s else 0
        self._lines.append(f'{name}_sum{label_str} {s:.6f}')

    def render(self) -> str:
        return '\n'.join(self._lines) + '\n'

    def reset(self) -> None:
        self._lines = []

# Query latency histogram buckets (in seconds)
QUERY_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
LOCK_BUCKETS  = [0.0001, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
IO_BUCKETS    = [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]

# ---------------------------------------------------------------------------
# Metrics exporter
# ---------------------------------------------------------------------------
class MetricsExporter:
    """
    Serves Prometheus metrics over HTTP.
    Runs in its own daemon thread.
    """

    def __init__(self, aggregator: 'EventAggregator', config: 'ProfilerConfig') -> None:
        self.agg    = aggregator
        self.config = config
        self._registry = PrometheusRegistry()
        self._lock = threading.Lock()
        self._last_rendered: str = ''

    def collect(self) -> str:
        """Build a fresh Prometheus text payload from current aggregator state."""
        t0 = time.perf_counter()
        reg = PrometheusRegistry()

        with self.agg._lock:
            # ---- Query metrics ----
            total_q = self.agg.total_queries
            total_s = self.agg.total_slow
            total_lw= self.agg.total_lock_waits
            total_dl= self.agg.total_deadlocks
            q_stats = list(self.agg.query_stats.values())
            l_stats = list(self.agg.lock_stats.values())
            io_stats= list(self.agg.io_stats.values())

        # Global counters
        reg.counter('pg_profiler_query_total', total_q,
                    'Total number of PostgreSQL queries observed')
        reg.counter('pg_profiler_slow_queries_total', total_s,
                    f'Queries exceeding {self.config.slow_query_ms}ms threshold')
        reg.counter('pg_profiler_lock_waits_total', total_lw,
                    'Total number of lock wait events')
        reg.counter('pg_profiler_deadlocks_total', total_dl,
                    'Total number of deadlock events detected')

        # Per-query histograms and counters
        for qs in q_stats:
            db = qs.dbname or 'unknown'
            samples_s = [x / 1e6 for x in qs.samples]  # us -> seconds
            reg.histogram(
                'pg_profiler_query_duration_seconds',
                samples_s, QUERY_BUCKETS,
                'PostgreSQL query duration in seconds',
                database=db
            )
            reg.counter(f'pg_profiler_query_calls_total', qs.call_count,
                        'Total calls per normalized query', database=db)
            reg.counter('pg_profiler_query_errors_total', qs.error_count,
                        'Total query error count', database=db)
            total_buf = qs.buf_hit_total + qs.buf_read_total
            if total_buf > 0:
                reg.gauge('pg_profiler_buffer_hit_ratio',
                          qs.buf_hit_total / total_buf,
                          'PostgreSQL shared buffer hit ratio (0-1)',
                          database=db)
            reg.counter('pg_profiler_wal_bytes_total', qs.wal_bytes_total,
                        'Total WAL bytes generated by profiled queries', database=db)

        # Lock metrics
        for ls in l_stats:
            reg.counter('pg_profiler_lock_waits_by_mode_total', ls.wait_count,
                        'Lock wait count by mode and relation',
                        lock_mode=ls.lock_mode, relation=ls.relation_name or 'unknown',
                        database=ls.dbname or 'unknown')
            reg.gauge('pg_profiler_lock_max_wait_seconds', ls.max_wait_us / 1e6,
                      'Maximum observed lock wait duration in seconds',
                      lock_mode=ls.lock_mode, relation=ls.relation_name or 'unknown')

        # I/O metrics
        for io in io_stats:
            reg.counter('pg_profiler_io_read_bytes_total', io.read_bytes,
                        'Total bytes read from block device', device=io.device)
            reg.counter('pg_profiler_io_write_bytes_total', io.write_bytes,
                        'Total bytes written to block device', device=io.device)
            reg.counter('pg_profiler_io_read_ops_total', io.read_ops,
                        'Total read I/O operations', device=io.device)
            reg.counter('pg_profiler_io_write_ops_total', io.write_ops,
                        'Total write I/O operations', device=io.device)
            if io.read_lat_us:
                reg.histogram('pg_profiler_io_read_latency_seconds',
                              [x / 1e6 for x in io.read_lat_us], IO_BUCKETS,
                              'Block I/O read latency in seconds', device=io.device)
            if io.write_lat_us:
                reg.histogram('pg_profiler_io_write_latency_seconds',
                              [x / 1e6 for x in io.write_lat_us], IO_BUCKETS,
                              'Block I/O write latency in seconds', device=io.device)

        # Exporter self-metrics
        scrape_dur = time.perf_counter() - t0
        reg.gauge('pg_profiler_scrape_duration_seconds', scrape_dur,
                  'Time taken to render metrics payload')
        reg.gauge('pg_profiler_info', 1,
                  'MinervaDB PostgreSQL Profiler metadata',
                  version='1.0.0', backend='ebpf')

        return reg.render()

    # ------------------------------------------------------------------
    # HTTP handler
    # ------------------------------------------------------------------
    def _make_handler(self):
        exporter = self

        class MetricsHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path not in ('/', '/metrics'):
                    self.send_response(404)
                    self.end_headers()
                    return
                try:
                    payload = exporter.collect()
                    body = payload.encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type',
                                     'text/plain; version=0.0.4; charset=utf-8')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except Exception as exc:
                    log.error('Metrics handler error: %s', exc)
                    self.send_response(500)
                    self.end_headers()

            def log_message(self, fmt, *args):
                pass  # Suppress default HTTP access log to stderr

        return MetricsHandler

    def run(self) -> None:
        port = self.config.prometheus_port
        server = HTTPServer(('', port), self._make_handler())
        log.info('Prometheus metrics server listening on :%d/metrics', port)
        try:
            server.serve_forever()
        except Exception as exc:
            log.error('Metrics server error: %s', exc)
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# Standalone usage
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    print('Use minervadb-profiler to start the full profiler with metrics export.')
    print('Direct invocation of metrics_exporter.py is not supported.')
    sys.exit(1)
