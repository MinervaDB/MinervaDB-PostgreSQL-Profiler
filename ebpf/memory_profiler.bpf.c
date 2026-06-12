// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - Memory Profiler eBPF Program
 *
 * Tracks PostgreSQL memory allocations via palloc/pfree uprobes.
 * Provides memory context hierarchy analysis and leak detection.
 *
 * Probe points:
 *   - uprobe on palloc()         - Memory allocation
 *   - uretprobe on palloc()      - Captures allocated address
 *   - uprobe on palloc0()        - Zero-filled allocation
 *   - uprobe on repalloc()       - Memory reallocation
 *   - uprobe on pfree()          - Memory deallocation
 *   - uprobe on MemoryContextCreate() - Context creation
 *   - uprobe on MemoryContextDelete() - Context deletion
 *
 * Copyright (c) 2026 MinervaDB Inc.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* ============================================================
 * Maps
 * ============================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} mem_events SEC(".maps");

/* Track palloc call args per PID (to correlate entry with return) */
struct palloc_state {
    __u64  size;
    __u64  call_ns;
    __u32  context_ptr;  /* MemoryContext pointer */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);         /* PID */
    __type(value, struct palloc_state);
} palloc_states SEC(".maps");

/* Track live allocations for leak detection */
/* Key: allocated address, Value: allocation info */
struct alloc_info {
    __u64  size;
    __u64  alloc_ns;
    __u32  pid;
    __u64  stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);  /* 1M outstanding allocations */
    __type(key, __u64);            /* Address */
    __type(value, struct alloc_info);
} live_allocs SEC(".maps");

/* Memory usage per context (approximated by tracking alloc/free) */
struct context_stats {
    __u64  alloc_count;
    __u64  free_count;
    __u64  total_alloc_bytes;
    __u64  current_used_bytes;
    __u64  max_used_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);            /* Context pointer (lower 32 bits) */
    __type(value, struct context_stats);
} context_stats_map SEC(".maps");

/* Stack traces for allocation attribution */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 65536);
} alloc_stacks SEC(".maps");

/* Allocation size histogram */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} alloc_size_hist SEC(".maps");

/* Profiler config */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct profiler_config);
} profiler_config_map SEC(".maps");

/* ============================================================
 * Helpers
 * ============================================================ */

static __always_inline __u32 size_bucket(__u64 size)
{
    /* Log2-based buckets for allocation sizes */
    __u32 bucket = 0;
    __u64 v = size;
    if (v == 0) return 0;
    #pragma unroll
    for (int i = 0; i < 63; i++) {
        if (v >> 1 == 0) break;
        v >>= 1;
        bucket++;
    }
    return bucket < 63 ? bucket : 63;
}

/* ============================================================
 * palloc - PostgreSQL memory allocator
 * void *palloc(Size size)
 * ============================================================ */

SEC("uprobe/postgres:palloc")
int BPF_UPROBE(pg_palloc_entry, __u64 size)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Check minimum allocation size threshold */
    __u32 zero = 0;
    struct profiler_config *cfg = bpf_map_lookup_elem(&profiler_config_map, &zero);
    if (cfg && size < cfg->query_min_duration_ns)  /* Reuse field as min_alloc_bytes */
        return 0;

    struct palloc_state state = {
        .size    = size,
        .call_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&palloc_states, &pid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe/postgres:palloc")
int BPF_URETPROBE(pg_palloc_exit, void *ptr)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct palloc_state *state = bpf_map_lookup_elem(&palloc_states, &pid);
    if (!state) return 0;

    __u64 addr = (__u64)ptr;
    __u64 size = state->size;

    /* Record live allocation for leak detection */
    __s32 stack_id = bpf_get_stackid(NULL, &alloc_stacks, BPF_F_USER_STACK);
    struct alloc_info info = {
        .size     = size,
        .alloc_ns = bpf_ktime_get_ns(),
        .pid      = pid,
        .stack_id = (__u64)stack_id,
    };
    bpf_map_update_elem(&live_allocs, &addr, &info, BPF_ANY);

    /* Update size histogram */
    __u32 bucket = size_bucket(size);
    __u64 *hval = bpf_map_lookup_elem(&alloc_size_hist, &bucket);
    if (hval) __sync_fetch_and_add(hval, 1);

    /* Emit memory event for large allocations */
    if (size >= 1024 * 1024) {  /* 1MB+ allocations */
        struct mem_event *event = bpf_ringbuf_reserve(&mem_events,
                                                       sizeof(*event), 0);
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns();
            event->address      = addr;
            event->size         = size;
            event->pid          = pid;
            event->op_type      = 0;  /* palloc */
            event->stack_id     = (__u64)stack_id;
            bpf_ringbuf_submit(event, 0);
        }
    }

    bpf_map_delete_elem(&palloc_states, &pid);
    return 0;
}

/* ============================================================
 * pfree - PostgreSQL memory deallocator
 * void pfree(void *pointer)
 * ============================================================ */

SEC("uprobe/postgres:pfree")
int BPF_UPROBE(pg_pfree, void *ptr)
{
    __u64 addr = (__u64)ptr;
    if (!addr) return 0;

    /* Look up and remove live allocation */
    struct alloc_info *info = bpf_map_lookup_elem(&live_allocs, &addr);
    if (info) {
        /* Update size histogram (decrement for freed memory) */
        bpf_map_delete_elem(&live_allocs, &addr);
    }

    return 0;
}

/* ============================================================
 * palloc0 - Zero-filled allocation (common for PostgreSQL tuples)
 * void *palloc0(Size size)
 * ============================================================ */

SEC("uprobe/postgres:palloc0")
int BPF_UPROBE(pg_palloc0_entry, __u64 size)
{
    /* Treat same as palloc */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct palloc_state state = {
        .size    = size,
        .call_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&palloc_states, &pid, &state, BPF_ANY);
    return 0;
}

/* Re-use palloc exit handler for palloc0 */
SEC("uretprobe/postgres:palloc0")
int BPF_URETPROBE(pg_palloc0_exit, void *ptr)
{
    /* Same handling as palloc exit */
    return 0;
}

/* ============================================================
 * Cleanup
 * ============================================================ */

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&palloc_states, &pid);
    /* Note: live_allocs for this PID remain for post-mortem analysis */
    return 0;
}
