#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MinervaDB PostgreSQL Profiler - Flame Graph Generator
======================================================

Generates SVG flame graphs from eBPF stack trace data collected by
the CPU profiler. Supports on-CPU, off-CPU, and memory allocation
flame graphs.

Flame graph format: Brendan Gregg's folded stacks format,
then rendered to SVG using built-in SVG generation.

Compatible with: flamegraph.pl (Brendan Gregg) or built-in SVG renderer.

Copyright (c) 2026 MinervaDB Inc.
"""

import os
import re
import subprocess
import tempfile
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("minervadb.flamegraph")

# ============================================================
# Data Structures
# ============================================================

@dataclass
class StackFrame:
    """A single stack frame."""
    address: int = 0
    symbol: str = ""
    offset: int = 0
    module: str = ""
    is_kernel: bool = False

    def __str__(self) -> str:
        if self.symbol:
            return self.symbol
        return f"0x{self.address:016x}"


@dataclass
class StackTrace:
    """A complete kernel + userspace stack trace."""
    kernel_frames: List[StackFrame] = field(default_factory=list)
    user_frames: List[StackFrame] = field(default_factory=list)
    count: int = 0
    pid: int = 0
    comm: str = ""

    def to_folded(self) -> str:
        """Convert to Brendan Gregg's folded stack format."""
        frames = []

        # User frames (bottom to top)
        for frame in reversed(self.user_frames):
            frames.append(str(frame))

        # Kernel frames (bottom to top)
        for frame in reversed(self.kernel_frames):
            frames.append(f"{frame.symbol}_[k]" if frame.symbol else f"0x{frame.address:016x}_[k]")

        if not frames:
            frames = ["[unknown]"]

        label = f"{self.comm or 'postgres'};{';'.join(frames)}"
        return f"{label} {self.count}"


# ============================================================
# Symbol Resolution
# ============================================================

class SymbolResolver:
    """
    Resolves kernel and userspace addresses to symbol names.
    Uses /proc/kallsyms for kernel symbols and addr2line/nm for userspace.
    """

    def __init__(self, pg_binary: str = "/usr/lib/postgresql/16/bin/postgres"):
        self.pg_binary = pg_binary
        self._kernel_symbols: Dict[int, str] = {}
        self._user_symbols: Dict[int, str] = {}
        self._kernel_loaded = False

    def load_kernel_symbols(self):
        """Load kernel symbols from /proc/kallsyms."""
        if self._kernel_loaded:
            return

        try:
            with open("/proc/kallsyms", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        addr = int(parts[0], 16)
                        sym_type = parts[1]
                        name = parts[2]
                        # Only track text symbols (T/t = text, W/w = weak)
                        if sym_type.lower() in ("t", "w"):
                            self._kernel_symbols[addr] = name
            self._kernel_loaded = True
            logger.debug(f"Loaded {len(self._kernel_symbols)} kernel symbols")
        except PermissionError:
            logger.warning("Cannot read /proc/kallsyms - kernel symbols unavailable")
        except Exception as e:
            logger.warning(f"Failed to load kernel symbols: {e}")

    def resolve_kernel(self, address: int) -> str:
        """Resolve a kernel address to a symbol name."""
        if not self._kernel_loaded:
            self.load_kernel_symbols()

        # Find the closest symbol below the address
        best_addr = 0
        best_sym = ""
        for sym_addr, sym_name in self._kernel_symbols.items():
            if sym_addr <= address and sym_addr > best_addr:
                best_addr = sym_addr
                best_sym = sym_name

        if best_sym:
            offset = address - best_addr
            return f"{best_sym}+0x{offset:x}" if offset else best_sym

        return f"0x{address:016x}"

    def resolve_user(self, address: int, pid: Optional[int] = None) -> str:
        """Resolve a userspace address to a symbol name."""
        if address in self._user_symbols:
            return self._user_symbols[address]

        # Try addr2line for PostgreSQL binary
        if self.pg_binary and os.path.exists(self.pg_binary):
            try:
                result = subprocess.run(
                    ["addr2line", "-e", self.pg_binary, "-f", "-s",
                     f"0x{address:x}"],
                    capture_output=True, text=True, timeout=1
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    if lines and lines[0] != "??" :
                        symbol = lines[0]
                        self._user_symbols[address] = symbol
                        return symbol
            except Exception:
                pass

        return f"0x{address:016x}"

    def resolve_stack(self, stack_trace: StackTrace) -> StackTrace:
        """Resolve all addresses in a stack trace."""
        for frame in stack_trace.kernel_frames:
            if not frame.symbol and frame.address:
                frame.symbol = self.resolve_kernel(frame.address)

        for frame in stack_trace.user_frames:
            if not frame.symbol and frame.address:
                frame.symbol = self.resolve_user(frame.address, stack_trace.pid)

        return stack_trace


# ============================================================
# Flame Graph Renderer
# ============================================================

class FlameGraphRenderer:
    """
    Renders flame graphs as SVG.
    Implements a subset of Brendan Gregg's flamegraph.pl functionality
    in pure Python.
    """

    # Color palettes
    PALETTE_HOT = {
        "default":   (230, 100, 10),
        "kernel":    (240, 100, 100),
        "jit":       (230, 200, 50),
        "interp":    (150, 150, 200),
        "background": (238, 238, 238),
    }

    PALETTE_COLD = {
        "default":   (60, 80, 200),
        "kernel":    (50, 150, 200),
        "background": (238, 238, 238),
    }

    PALETTE_MEM = {
        "default":   (0, 180, 0),
        "kernel":    (0, 200, 100),
        "background": (238, 238, 238),
    }

    def __init__(self,
                 width: int = 1200,
                 height_per_frame: int = 16,
                 font_size: int = 12,
                 color_scheme: str = "hot",
                 title: str = "Flame Graph"):
        self.width = width
        self.frame_height = height_per_frame
        self.font_size = font_size
        self.color_scheme = color_scheme
        self.title = title

        palette_map = {
            "hot": self.PALETTE_HOT,
            "cold": self.PALETTE_COLD,
            "mem": self.PALETTE_MEM,
        }
        self.palette = palette_map.get(color_scheme, self.PALETTE_HOT)

    def _color_for_name(self, name: str) -> str:
        """Generate a deterministic color for a frame name."""
        palette = self.palette
        base_r, base_g, base_b = palette["default"]

        if name.endswith("_[k]") or "[kernel]" in name:
            base_r, base_g, base_b = palette.get("kernel", palette["default"])

        # Add deterministic variation based on name hash
        v = hash(name) % 255
        r = min(255, base_r + v % 30)
        g = min(255, base_g + (v // 3) % 30)
        b = min(255, base_b + (v // 5) % 30)

        return f"rgb({r},{g},{b})"

    def render(self, folded_stacks: List[str], output_path: str) -> str:
        """
        Render folded stacks to SVG flame graph.

        Args:
            folded_stacks: List of folded stack strings (frame;frame;frame count)
            output_path: Output SVG file path

        Returns:
            Path to generated SVG file
        """
        # Parse folded stacks into frame tree
        root = self._build_frame_tree(folded_stacks)

        # Calculate dimensions
        total_samples = root.get("count", 1)
        max_depth = self._max_depth(root)
        height = (max_depth + 4) * self.frame_height + 100  # Extra for title/info

        # Generate SVG
        svg_parts = [self._svg_header(height)]
        svg_parts.append(self._svg_title())
        svg_parts.append(self._svg_info(total_samples))

        # Render frames
        frames_svg = []
        self._render_node(root, 0, total_samples, 0, max_depth + 2,
                          frames_svg, total_samples)
        svg_parts.extend(frames_svg)
        svg_parts.append(self._svg_footer())

        svg_content = "\n".join(svg_parts)

        with open(output_path, "w") as f:
            f.write(svg_content)

        logger.info(f"Flame graph saved to: {output_path}")
        return output_path

    def _build_frame_tree(self, folded_stacks: List[str]) -> dict:
        """Build a frame tree from folded stack strings."""
        root = {"name": "root", "count": 0, "children": {}}

        for line in folded_stacks:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.rsplit(" ", 1)
            if len(parts) != 2:
                continue

            try:
                count = int(parts[1])
            except ValueError:
                continue

            frames = parts[0].split(";")
            root["count"] += count

            node = root
            for frame in frames:
                if frame not in node["children"]:
                    node["children"][frame] = {
                        "name": frame,
                        "count": 0,
                        "children": {}
                    }
                node = node["children"][frame]
                node["count"] += count

        return root

    def _max_depth(self, node: dict, depth: int = 0) -> int:
        """Calculate maximum frame depth."""
        if not node["children"]:
            return depth
        return max(self._max_depth(child, depth + 1)
                   for child in node["children"].values())

    def _svg_header(self, height: int) -> str:
        return f"""<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" width="{self.width}" height="{height}"
     onload="init(evt)"
     viewBox="0 0 {self.width} {height}"
     xmlns="http://www.w3.org/2000/svg">
<defs>
  <style type="text/css">
    text {{ font-family: Verdana, Helvetica, sans-serif; font-size: {self.font_size}px; fill: rgb(0,0,0); }}
    rect {{ stroke-width: 1; }}
    .unzoom {{ cursor: pointer; }}
    .frame {{ cursor: pointer; }}
    .frame:hover rect {{ stroke: black; fill: yellow; }}
  </style>
</defs>
<rect width="{self.width}" height="{height}" fill="{self.palette.get('background', '#eee')}" />"""

    def _svg_title(self) -> str:
        y = 24
        return (f'<text x="{self.width // 2}" y="{y}" text-anchor="middle" '
                f'font-size="17" font-weight="bold">{self.title}</text>')

    def _svg_info(self, total_samples: int) -> str:
        return (f'<text id="details" x="10" y="40" text-anchor="left">'
                f'MinervaDB PostgreSQL Profiler | Samples: {total_samples:,}'
                f' | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
                f'</text>')

    def _render_node(self, node: dict, x_start: float, total: int,
                     depth: int, max_depth: int,
                     output: list, root_total: int):
        """Recursively render a frame node."""
        if node["name"] == "root":
            # Render children of root
            x = 0.0
            for child in node["children"].values():
                w = (child["count"] / total) * self.width
                if w > 0.5:  # Skip very thin frames
                    self._render_node(child, x, total, depth, max_depth,
                                      output, root_total)
                x += w
            return

        # Calculate frame position
        w = (node["count"] / total) * self.width
        if w < 0.5:
            return

        y = (max_depth - depth) * self.frame_height + 60  # 60px top margin

        # Truncate name for display
        chars = max(2, int(w / (self.font_size * 0.6)))
        display_name = node["name"][:chars] if len(node["name"]) > chars else node["name"]

        # Frame percentage
        pct = 100.0 * node["count"] / root_total

        color = self._color_for_name(node["name"])

        # Render frame rectangle with tooltip
        tooltip = (f"{node['name']} ({node['count']:,} samples, {pct:.1f}%)")

        output.append(
            f'<g class="frame" onclick="zoom(this)">'
            f'<title>{tooltip}</title>'
            f'<rect x="{x_start:.1f}" y="{y}" width="{w:.1f}" '
            f'height="{self.frame_height - 1}" fill="{color}" stroke="white"/>'
            f'<text x="{x_start + 3:.1f}" y="{y + self.frame_height - 4}" '
            f'clip-path="url(#clip_{int(x_start)}_{y})">{display_name}</text>'
            f'</g>'
        )

        # Render children
        x = x_start
        for child in node["children"].values():
            child_w = (child["count"] / total) * self.width
            if child_w >= 0.5:
                self._render_node(child, x, total, depth + 1, max_depth,
                                  output, root_total)
            x += child_w

    def _svg_footer(self) -> str:
        return """<script type="text/ecmascript">
<![CDATA[
var currentRoot = null;
function init(evt) {
    // Basic zoom interaction
}
function zoom(node) {
    // Placeholder for zoom functionality
}
]]>
</script>
</svg>"""


# ============================================================
# Main Flame Graph Generator
# ============================================================

class FlameGraphGenerator:
    """
    Generates flame graphs from eBPF profiling data.

    Reads stack trace data from eBPF maps, resolves symbols,
    and renders SVG flame graphs.
    """

    def __init__(self,
                 output_dir: str = "/var/lib/minervadb/flamegraphs",
                 pg_binary: str = "/usr/lib/postgresql/16/bin/postgres",
                 color_scheme: str = "hot",
                 width: int = 1200):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.resolver = SymbolResolver(pg_binary)
        self.renderer = FlameGraphRenderer(
            width=width,
            color_scheme=color_scheme,
        )

        # Check for flamegraph.pl (Brendan Gregg's tool)
        self.has_flamegraph_pl = bool(
            subprocess.run(["which", "flamegraph.pl"],
                          capture_output=True).returncode == 0
        )
        if self.has_flamegraph_pl:
            logger.info("flamegraph.pl found - using for rendering")
        else:
            logger.info("Using built-in SVG renderer")

    def generate_cpu_flamegraph(self,
                                 stack_counts: Dict,
                                 output_name: str = "",
                                 title: str = "PostgreSQL CPU Flame Graph") -> Optional[str]:
        """
        Generate a CPU flame graph from stack count data.

        Args:
            stack_counts: Dict mapping stack_count_key -> count
                         (from the eBPF stack_counts map)
            output_name: Output filename (auto-generated if empty)
            title: Flame graph title

        Returns:
            Path to generated SVG file, or None on failure
        """
        if not output_name:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"cpu_flamegraph_{ts}.svg"

        output_path = self.output_dir / output_name

        # Convert stack_counts to folded stack format
        folded_stacks = self._stacks_to_folded(stack_counts, "on-cpu")

        if not folded_stacks:
            logger.warning("No stack data available for CPU flame graph")
            return None

        return self._render_flamegraph(folded_stacks, str(output_path), title)

    def generate_offcpu_flamegraph(self,
                                    off_cpu_times: Dict,
                                    output_name: str = "",
                                    title: str = "PostgreSQL Off-CPU Flame Graph") -> Optional[str]:
        """
        Generate an off-CPU flame graph showing time spent waiting.

        Off-CPU flame graphs show where PostgreSQL spends time sleeping
        (waiting for I/O, locks, network, etc.) rather than using CPU.
        """
        if not output_name:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"offcpu_flamegraph_{ts}.svg"

        output_path = self.output_dir / output_name
        folded_stacks = self._stacks_to_folded(off_cpu_times, "off-cpu")

        if not folded_stacks:
            logger.warning("No off-CPU data available")
            return None

        renderer = FlameGraphRenderer(
            width=1200,
            color_scheme="cold",
            title=title
        )

        if folded_stacks:
            return self._render_flamegraph(folded_stacks, str(output_path), title,
                                          color_scheme="cold")
        return None

    def _stacks_to_folded(self, stack_data: Dict,
                           mode: str = "on-cpu") -> List[str]:
        """Convert eBPF stack data to folded format."""
        folded = []

        for key, value in stack_data.items():
            try:
                # key is struct stack_count_key
                pid = getattr(key, "pid", 0)
                comm = getattr(key, "comm", b"postgres").decode("utf-8", errors="replace").rstrip("\x00")
                kstack_id = getattr(key, "kernel_stack_id", -1)
                ustack_id = getattr(key, "user_stack_id", -1)

                count = int(value)
                if count <= 0:
                    continue

                # Build stack frames
                frames = [comm]

                # Add user frames
                if ustack_id >= 0:
                    # In production, read from user_stacks BPF_MAP_TYPE_STACK_TRACE
                    frames.append("[user_stack]")

                # Add kernel frames
                if kstack_id >= 0:
                    # In production, read from kernel_stacks BPF_MAP_TYPE_STACK_TRACE
                    frames.append("[kernel_stack]_[k]")

                stack_str = ";".join(frames)
                folded.append(f"{stack_str} {count}")

            except Exception as e:
                logger.debug(f"Error processing stack: {e}")
                continue

        return folded

    def _render_flamegraph(self, folded_stacks: List[str],
                            output_path: str, title: str,
                            color_scheme: str = "hot") -> Optional[str]:
        """Render folded stacks to SVG using flamegraph.pl or built-in renderer."""

        # Write folded stacks to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".folded",
                                         delete=False) as f:
            f.write("\n".join(folded_stacks))
            temp_path = f.name

        try:
            if self.has_flamegraph_pl:
                # Use Brendan Gregg's flamegraph.pl
                result = subprocess.run(
                    ["flamegraph.pl",
                     "--title", title,
                     "--width", "1200",
                     "--colors", color_scheme,
                     temp_path],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    with open(output_path, "w") as f:
                        f.write(result.stdout)
                    logger.info(f"Flame graph (flamegraph.pl): {output_path}")
                    return output_path
                else:
                    logger.warning(f"flamegraph.pl failed: {result.stderr}")

            # Fallback: built-in renderer
            renderer = FlameGraphRenderer(
                color_scheme=color_scheme,
                title=title
            )
            return renderer.render(folded_stacks, output_path)

        except Exception as e:
            logger.error(f"Flame graph generation failed: {e}")
            return None
        finally:
            os.unlink(temp_path)

    def generate_html_report(self, svg_path: str, output_name: str = "") -> str:
        """Wrap SVG flame graph in an interactive HTML report."""
        if not output_name:
            output_name = Path(svg_path).stem + ".html"

        output_path = self.output_dir / output_name

        with open(svg_path) as f:
            svg_content = f.read()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MinervaDB PostgreSQL Profiler - Flame Graph</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
  h1 {{ color: #4fc3f7; }}
  .flame-container {{ background: white; border-radius: 8px; padding: 10px; overflow-x: auto; }}
  .info {{ color: #90caf9; margin-bottom: 20px; }}
</style>
</head>
<body>
<h1>MinervaDB PostgreSQL Profiler</h1>
<div class="info">
  <strong>CPU Flame Graph</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  | <a href="{Path(svg_path).name}" style="color: #4fc3f7;">Download SVG</a>
</div>
<div class="flame-container">
{svg_content}
</div>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)

        logger.info(f"HTML report saved to: {output_path}")
        return str(output_path)
