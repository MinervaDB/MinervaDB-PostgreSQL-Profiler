// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - Vacuum/Autovacuum Profiler eBPF Program
 *
 * Profiles VACUUM and autovacuum operations in PostgreSQL.
 * Tracks vacuum progress, dead tuple removal rates, and bloat accumulation.
 *
 * Probe points:
 *   - postgresql:vacuum__start  (USDT) - Vacuum begins on a relation
 *   - postgresql:vacuum__done   (USDT) - Vacuum completes
 *   - uprobe on heap_vacuum_rel()      - Heap vacuum entry
 *   - uretprobe on heap_vacuum_rel()   - Heap vacuum exit
 *   - uprobe on lazy_vacuum_heap_rel() - Lazy vacuum
 *   - uprobe on AutoVacWorkerMain()    - Autovacuum worker start
 *   - uprobe on do_autovacuum()        - Autovacuum main loop
 *
 * Copyright (c) 2026 MinervaDB Inc.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* ============================================================
 * Maps
 * ============================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} vacuum_events SEC(".maps");

/* Track vacuum operation state per PID */
struct vacuum_state {
    __u64  start_ns;
    __u32  rel_oid;
    __u32  db_oid;
    __u8   is_autovacuum;
    __u8   is_analyze;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);   /* Max concurrent vacuum workers */
    __type(key, __u32);
    __type(value, struct vacuum_state);
} vacuum_states SEC(".maps");

/* Aggregated vacuum statistics per relation */
struct relation_vacuum_stats {
    __u64  vacuum_count;
    __u64  autovacuum_count;
    __u64  total_duration_ns;
    __u64  total_tuples_removed;
    __u64  total_blocks_scanned;
    __u64  total_blocks_vacuumed;
    __u64  total_index_scans;
    __u64  max_duration_ns;
    __u64  last_vacuum_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);             /* rel_oid */
    __type(value, struct relation_vacuum_stats);
} relation_vacuum_stats SEC(".maps");

/* ============================================================
 * USDT: vacuum__start
 * Fired at the beginning of VACUUM on a relation.
 * args: (arg0=vacrelstats ptr - opaque, arg1=rel_oid, arg2=is_autovacuum)
 * ============================================================ */

SEC("usdt/postgres:postgresql:vacuum__start")
int BPF_USDT(pg_vacuum_start, void *vacrelstats, unsigned int rel_oid,
             int is_autovacuum)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct vacuum_state state = {
        .start_ns      = now,
        .rel_oid       = rel_oid,
        .is_autovacuum = (__u8)(is_autovacuum ? 1 : 0),
    };
    bpf_map_update_elem(&vacuum_states, &pid, &state, BPF_ANY);
    return 0;
}

/* ============================================================
 * USDT: vacuum__done
 * Fired at the completion of VACUUM.
 * args vary by PostgreSQL version - use PID-keyed state map.
 * ============================================================ */

SEC("usdt/postgres:postgresql:vacuum__done")
int BPF_USDT(pg_vacuum_done)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct vacuum_state *state = bpf_map_lookup_elem(&vacuum_states, &pid);
    if (!state) return 0;

    __u64 duration_ns = 0;
    if (state->start_ns > 0 && now > state->start_ns)
        duration_ns = now - state->start_ns;

    __u32 rel_oid = state->rel_oid;
    __u8 is_autovacuum = state->is_autovacuum;

    /* Emit vacuum event */
    struct vacuum_event *event = bpf_ringbuf_reserve(&vacuum_events,
                                                      sizeof(*event), 0);
    if (event) {
        event->timestamp_ns  = now;
        event->start_ns      = state->start_ns;
        event->end_ns        = now;
        event->duration_ns   = duration_ns;
        event->rel_oid       = rel_oid;
        event->db_oid        = state->db_oid;
        event->pid           = pid;
        event->is_autovacuum = is_autovacuum;
        bpf_ringbuf_submit(event, 0);
    }

    /* Update per-relation stats */
    struct relation_vacuum_stats *stats =
        bpf_map_lookup_elem(&relation_vacuum_stats, &rel_oid);
    if (stats) {
        if (is_autovacuum)
            __sync_fetch_and_add(&stats->autovacuum_count, 1);
        else
            __sync_fetch_and_add(&stats->vacuum_count, 1);
        __sync_fetch_and_add(&stats->total_duration_ns, duration_ns);
        if (duration_ns > stats->max_duration_ns)
            stats->max_duration_ns = duration_ns;
        stats->last_vacuum_ns = now;
    } else {
        struct relation_vacuum_stats new_stats = {
            .vacuum_count    = is_autovacuum ? 0 : 1,
            .autovacuum_count = is_autovacuum ? 1 : 0,
            .total_duration_ns = duration_ns,
            .max_duration_ns   = duration_ns,
            .last_vacuum_ns    = now,
        };
        bpf_map_update_elem(&relation_vacuum_stats, &rel_oid,
                            &new_stats, BPF_NOEXIST);
    }

    bpf_map_delete_elem(&vacuum_states, &pid);
    return 0;
}

/* ============================================================
 * uprobe: heap_vacuum_rel - Detailed vacuum metrics
 * void heap_vacuum_rel(Relation onerel, VacuumParams *params,
 *                      BufferAccessStrategy bstrategy)
 * ============================================================ */

SEC("uprobe/postgres:heap_vacuum_rel")
int BPF_UPROBE(pg_heap_vacuum_start, void *onerel, void *params, void *bstrategy)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct vacuum_state *state = bpf_map_lookup_elem(&vacuum_states, &pid);
    if (state) {
        /* Mark as heap vacuum (vs ANALYZE only) */
        state->is_analyze = 0;
    }
    return 0;
}

/* ============================================================
 * uprobe: AutoVacWorkerMain - Track autovacuum worker startup
 * ============================================================ */

SEC("uprobe/postgres:AutoVacWorkerMain")
int BPF_UPROBE(pg_autovac_worker_start, int argc, char **argv)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    /* Autovacuum worker started */
    struct vacuum_state state = {
        .start_ns      = now,
        .is_autovacuum = 1,
    };
    bpf_map_update_elem(&vacuum_states, &pid, &state, BPF_ANY);
    return 0;
}

/* ============================================================
 * Cleanup
 * ============================================================ */

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&vacuum_states, &pid);
    return 0;
}
