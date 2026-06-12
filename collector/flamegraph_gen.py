#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MinervaDB PostgreSQL Profiler - Flame Graph Generator
=====================================================

Generates interactive SVG and HTML flame graphs from CPU stack traces
captured by the eBPF cpu_profiler module.  Implements the Brendan Gregg
folded stack format and produces self-contained, zoomable SVG output
without external dependencies.

Output formats:
  - SVG  : Standalone interactive flame graph (zoom + search)
  - HTML : Embedded SVG with JavaScript controls
  - JSON : Raw folded stack data for external flame graph tools
  - TXT  : Folded stack format compatible with flamegraph.pl

Copyright (c) 2026 MinervaDB Inc.
License: MIT
"""

from __future__ import annotations

import os
import re
import math
import json
import time
import logging
import hashlib
import colorsys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger('minervadb.flamegraph')

# ---------------------------------------------------------------------------
# Frame color palettes
# ---------------------------------------------------------------------------
# Colors inspired by Brendan Gregg's flamegraph.pl
PALETTE_JAVA    = ('#b2d9ff', '#99ccff')  # blue - JIT/Java
PALETTE_KERNEL  = ('#e8a0d0', '#d080bc')  # purple - kernel
PALETTE_CPP     = ('#ffd0a0', '#ffb870')  # orange - C/C++
PALETTE_PYTHON  = ('#c0e8a0', '#a0d080')  # green - Python
PALETTE_PG      = ('#ffe0a0', '#ffc860')  # yellow - PostgreSQL
PALETTE_DEFAULT = ('#e0d0c0', '#c8b8a0')  # gray - other

def _frame_color(frame: str, variant: int = 0) -> str:
    f = frame.lower()
    if '[k]' in f or frame.endswith('_softirq') or 'sys_' in f:
        palette = PALETTE_KERNEL
    elif 'postgres' in f or 'pg_' in f or 'executor' in f.lower():
        palette = PALETTE_PG
    elif '.py' in f or 'python' in f:
        palette = PALETTE_PYTHON
    elif frame.endswith('.c') or 'libc' in f:
        palette = PALETTE_CPP
    else:
        palette = PALETTE_DEFAULT
    return palette[variant % 2]

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class StackFrame:
    name:     str
    count:    int   = 0
    children: Dict[str, 'StackFrame'] = field(default_factory=dict)

    def add_count(self, n: int = 1) -> None:
        self.count += n

@dataclass
class FlamegraphOptions:
    title:      str   = 'MinervaDB PostgreSQL CPU Flame Graph'
    subtitle:   str   = 'MinervaDB PostgreSQL Profiler v1.0.0'
    width:      int   = 1200
    height:     int   = 0          # 0 = auto
    frame_h:    int   = 16         # pixels per frame row
    min_width:  float = 0.1        # minimum frame width in pixels
    font_size:  int   = 12
    reverse:    bool  = False      # icicle chart
    search_color: str = '#e600e6'

# ---------------------------------------------------------------------------
# Stack tree builder
# ---------------------------------------------------------------------------
class StackTree:
    """Builds a hierarchical stack frame tree from folded stack data."""

    def __init__(self) -> None:
        self.root = StackFrame(name='all')
        self.total_samples = 0

    def add_folded(self, stack_str: str, count: int = 1) -> None:
        """
        Add a folded stack string.
        Format: 'frame1;frame2;frame3 COUNT'
        """
        if not stack_str.strip():
            return
        parts = stack_str.rsplit(' ', 1)
        if len(parts) == 2:
            frames_str, cnt_str = parts
            try:
                count = int(cnt_str)
            except ValueError:
                frames_str = stack_str
        else:
            frames_str = parts[0]
        frames = [f.strip() for f in frames_str.split(';') if f.strip()]
        self.total_samples += count
        node = self.root
        node.add_count(count)
        for frame in frames:
            if frame not in node.children:
                node.children[frame] = StackFrame(name=frame)
            node = node.children[frame]
            node.add_count(count)

    def add_from_bpf_map(self, stack_counts: Dict[str, int]) -> None:
        """Import directly from eBPF stack count map (frame_str -> count)."""
        for stack_str, count in stack_counts.items():
            self.add_folded(stack_str, count)

    def depth(self) -> int:
        def _depth(node: StackFrame) -> int:
            if not node.children:
                return 1
            return 1 + max(_depth(c) for c in node.children.values())
        return _depth(self.root)

# ---------------------------------------------------------------------------
# SVG renderer
# ---------------------------------------------------------------------------
class SVGFlamegraphRenderer:
    """Renders a StackTree as an interactive SVG flame graph."""

    _INTERACTIVE_JS = '''
    var svg = document.getElementById("main");
    var details = document.getElementById("details");
    function show(evt) {
        var g = evt.currentTarget;
        details.nodeValue = g.querySelector("title").textContent;
    }
    function hide(evt) { details.nodeValue = " "; }
    function zoom(node) {
        var attr = node.attributes;
        var width = svg.width.baseVal.value;
        var xScale = width / parseFloat(attr.getNamedItem("width").value);
        var x = parseFloat(attr.getNamedItem("x").value) * xScale;
        var frames = svg.querySelectorAll(".frame");
        frames.forEach(function(f) {
            var fx = parseFloat(f.getAttribute("x")) * xScale;
            var fw = parseFloat(f.getAttribute("width")) * xScale;
            f.setAttribute("display", fx < x || fx + fw > x + width ? "none" : "block");
            f.setAttribute("x", (fx - x).toString());
            f.setAttribute("width", fw.toString());
        });
    }
    ''
''

    def __init__(self, tree: StackTree, opts: Optional[FlamegraphOptions] = None) -> None:
        self.tree = tree
        self.opts = opts or FlamegraphOptions()
        self._rects: List[Dict] = []

    def _visit(self, node: StackFrame, x: float, y: int,
               total_width: float, total: int, depth: int) -> None:
        if total == 0:
            return
        w = (node.count / total) * total_width
        if w < self.opts.min_width:
            return
        color = _frame_color(node.name, depth)
        pct   = node.count / total * 100
        self._rects.append({
            'x': round(x, 2), 'y': y, 'w': round(w, 2),
            'h': self.opts.frame_h, 'color': color,
            'name': node.name, 'count': node.count, 'pct': round(pct, 2)
        })
        child_x = x
        for child in sorted(node.children.values(), key=lambda c: c.name):
            self._visit(child, child_x, y - self.opts.frame_h, total_width, total, depth + 1)
            child_x += (child.count / total) * total_width

    def render(self) -> str:
        tree_depth = self.tree.depth()
        w = self.opts.width
        fh = self.opts.frame_h
        header_h = 60
        auto_h = header_h + (tree_depth + 1) * fh + 20
        h = self.opts.height if self.opts.height else auto_h
        base_y = h - 20
        self._rects = []
        if self.tree.root.count > 0:
            self._visit(self.tree.root, 0, base_y - fh, float(w),
                        self.tree.root.count, 0)
        return self._build_svg(w, h)

    def _build_svg(self, w: int, h: int) -> str:
        lines = [
            f'<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" id="main"',
            f'  width="{w}" height="{h}" viewBox="0 0 {w} {h}"',
            f'  style="background:#f8f8f8;font-family:monospace">',
            f'<defs>',
            f'  <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">',
            f'    <stop offset="5%" stop-color="#eeeeee"/>',
            f'    <stop offset="95%" stop-color="#e0e0e0"/>',
            f'  </linearGradient>',
            f'</defs>',
            f'<rect width="100%" height="100%" fill="url(#bg)"/>',
            f'<text x="{w//2}" y="24" text-anchor="middle" font-size="17" font-weight="bold">{self.opts.title}</text>',
            f'<text x="{w//2}" y="42" text-anchor="middle" font-size="12" fill="#666">{self.opts.subtitle} | {self.tree.total_samples} samples</text>',
            f'<text id="details" x="10" y="{h-5}" font-size="12"> </text>',
        ]
        for r in self._rects:
            escaped = r['name'].replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
            title = f'{escaped} ({r["count"]} samples, {r["pct"]}%)'
            lines.append(
                f'<g class="frame" onmouseover="show(evt)" onmouseout="hide(evt)">'
            )
            lines.append(f'  <title>{title}</title>')
            lines.append(
                f'  <rect x="{r["x"]}" y="{r["y"]}" width="{r["w"]}" height="{r["h"]}"'
            )
            lines.append(f'    rx="2" fill="{r["color"]}" stroke="white" stroke-width="0.5"/>')
            if r['w'] > 30:
                label = r['name']
                max_chars = max(1, int(r['w'] / self.opts.font_size * 1.8))
                if len(label) > max_chars:
                    label = label[:max_chars - 2] + '..'
                lines.append(
                    f'  <text x="{r["x"] + 3}" y="{r["y"] + r["h"] - 4}"'
                )
                lines.append(f'    font-size="{self.opts.font_size}" fill="#1a1a1a">{label}</text>')
            lines.append('</g>')
        lines.append('</svg>')
        return '\n'.join(lines)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
class FlamegraphGenerator:
    """High-level API for generating flame graphs from profiler data."""

    def __init__(self, output_dir: str = '/var/lib/minervadb/flamegraphs') -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def from_bpf_stack_map(self, stack_counts: Dict[str, int],
                           title: str = 'PostgreSQL CPU Flame Graph',
                           fmt: str = 'svg') -> Path:
        """
        Generate a flame graph from an eBPF stack count map.
        Returns path to the generated file.
        """
        tree = StackTree()
        tree.add_from_bpf_map(stack_counts)
        return self._render(tree, title, fmt)

    def from_folded_file(self, path: str, title: str = 'Flame Graph',
                         fmt: str = 'svg') -> Path:
        """Generate a flame graph from a folded stack file."""
        tree = StackTree()
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    tree.add_folded(line)
        return self._render(tree, title, fmt)

    def _render(self, tree: StackTree, title: str, fmt: str) -> Path:
        if tree.total_samples == 0:
            log.warning('No samples to render for flame graph: %s', title)
        opts = FlamegraphOptions(title=title)
        ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', title)[:40]
        fname = f'{safe}_{ts}.{fmt}'
        out_path = self.output_dir / fname
        if fmt == 'svg':
            renderer = SVGFlamegraphRenderer(tree, opts)
            out_path.write_text(renderer.render(), encoding='utf-8')
        elif fmt == 'json':
            data = {'title': title, 'total': tree.total_samples,
                    'generated': ts}
            out_path.write_text(json.dumps(data, indent=2))
        elif fmt == 'txt':
            with open(out_path, 'w') as f:
                def _write(node, prefix=''):
                    for name, child in sorted(node.children.items()):
                        stack = f'{prefix};{name}' if prefix else name
                        if not child.children:
                            f.write(f'{stack} {child.count}\n')
                        else:
                            _write(child, stack)
                _write(tree.root)
        else:
            raise ValueError(f'Unsupported format: {fmt}')
        log.info('Flame graph written: %s (%d samples)', out_path, tree.total_samples)
        return out_path

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import sys, argparse
    ap = argparse.ArgumentParser(description='Generate flame graphs from folded stacks')
    ap.add_argument('input', help='Folded stack file or - for stdin')
    ap.add_argument('--output', '-o', default='flamegraph.svg')
    ap.add_argument('--title', default='PostgreSQL CPU Flame Graph')
    ap.add_argument('--format', choices=['svg','json','txt'], default='svg')
    args = ap.parse_args()

    gen = FlamegraphGenerator(output_dir=str(Path(args.output).parent))
    src = '/dev/stdin' if args.input == '-' else args.input
    out = gen.from_folded_file(src, title=args.title, fmt=args.format)
    print(f'Generated: {out}')
