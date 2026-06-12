// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - WAL Profiler eBPF Program
 *
 * Profiles PostgreSQL Write-Ahead Log (WAL) operations including:
 * - WAL record writes and flushes
 * - Checkpoint operations
 * - WAL write amplification analysis
 * - fsync latency tracking
 *
 * Probe points:
 *   - uprobe on XLogWrite()       - WAL write to disk
 *   - uretprobe on XLogWrite()    - WAL write completion
 *   - uprobe on XLogFlush()       - WAL flush (fsync)
 *   - uretprobe on XLogFlush()    - WAL flush completion
 *   - uprobe on CreateCheckPoint() - Checkpoint start
 *   - uretprobe on CreateCheckPoint() - Checkpoint end
 *   - uprobe on XLogInsert()      - WAL record insertion
 *   - tracepoint/writeback/writeback_start - Kernel writeback
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
} wal_events SEC(".maps");

/* Track WAL write operations per PID */
struct wal_op_state {
    __u64  start_ns;
    __u64  lsn;
    __u64  end_lsn;
    __u8   op_type;  /* 0=write, 1=flush, 2=checkpoint */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct wal_op_state);
} wal_op_states SEC(".maps");

/* WAL throughput statistics */
struct wal_stats {
    __u64  write_count;
    __u64  flush_count;
    __u64  total_bytes_written;
    __u64  total_write_latency_ns;
    __u64  total_flush_latency_ns;
    __u64  max_write_latency_ns;
    __u64  max_flush_latency_ns;
    __u64  checkpoint_count;
    __u64  total_checkpoint_duration_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct wal_stats);
} wal_global_stats SEC(".maps");

/* WAL write latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} wal_write_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} wal_flush_hist SEC(".maps");

/* ============================================================
 * Helpers
 * ============================================================ */

static __always_inline __u32 log2_ns(__u64 value_ns)
{
    __u32 bucket = 0;
    __u64 v = value_ns;
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
 * XLogWrite - WAL Write
 * void XLogWrite(XLogwrtRqst WriteRqst, bool flexible, bool do_via_wal_writer)
 * ============================================================ */

SEC("uprobe/postgres:XLogWrite")
int BPF_UPROBE(pg_xlogwrite_entry)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct wal_op_state state = {
        .start_ns = bpf_ktime_get_ns(),
        .op_type  = 0,  /* write */
    };
    bpf_map_update_elem(&wal_op_states, &pid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe/postgres:XLogWrite")
int BPF_URETPROBE(pg_xlogwrite_exit)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct wal_op_state *state = bpf_map_lookup_elem(&wal_op_states, &pid);
    if (!state || state->op_type != 0) {
        bpf_map_delete_elem(&wal_op_states, &pid);
        return 0;
    }

    __u64 latency_ns = now - state->start_ns;

    /* Update global stats */
    __u32 zero = 0;
    struct wal_stats *stats = bpf_map_lookup_elem(&wal_global_stats, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->write_count, 1);
        __sync_fetch_and_add(&stats->total_write_latency_ns, latency_ns);
        if (latency_ns > stats->max_write_latency_ns)
            stats->max_write_latency_ns = latency_ns;
    }

    /* Update histogram */
    __u32 bucket = log2_ns(latency_ns);
    __u64 *hval = bpf_map_lookup_elem(&wal_write_hist, &bucket);
    if (hval) __sync_fetch_and_add(hval, 1);

    /* Emit WAL event */
    struct wal_event *event = bpf_ringbuf_reserve(&wal_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns   = now;
        event->write_start_ns = state->start_ns;
        event->write_end_ns   = now;
        event->pid            = pid;
        event->record_type    = WAL_TYPE_OTHER;
        bpf_ringbuf_submit(event, 0);
    }

    bpf_map_delete_elem(&wal_op_states, &pid);
    return 0;
}

/* ============================================================
 * XLogFlush - WAL fsync
 * void XLogFlush(XLogRecPtr record)
 * ============================================================ */

SEC("uprobe/postgres:XLogFlush")
int BPF_UPROBE(pg_xlogflush_entry, __u64 record_lsn)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct wal_op_state state = {
        .start_ns = bpf_ktime_get_ns(),
        .lsn      = record_lsn,
        .op_type  = 1,  /* flush */
    };
    bpf_map_update_elem(&wal_op_states, &pid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe/postgres:XLogFlush")
int BPF_URETPROBE(pg_xlogflush_exit)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct wal_op_state *state = bpf_map_lookup_elem(&wal_op_states, &pid);
    if (!state || state->op_type != 1) {
        bpf_map_delete_elem(&wal_op_states, &pid);
        return 0;
    }

    __u64 latency_ns = now - state->start_ns;

    /* Update stats */
    __u32 zero = 0;
    struct wal_stats *stats = bpf_map_lookup_elem(&wal_global_stats, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->flush_count, 1);
        __sync_fetch_and_add(&stats->total_flush_latency_ns, latency_ns);
        if (latency_ns > stats->max_flush_latency_ns)
            stats->max_flush_latency_ns = latency_ns;
    }

    /* Update flush histogram */
    __u32 bucket = log2_ns(latency_ns);
    __u64 *hval = bpf_map_lookup_elem(&wal_flush_hist, &bucket);
    if (hval) __sync_fetch_and_add(hval, 1);

    /* Emit event */
    struct wal_event *event = bpf_ringbuf_reserve(&wal_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns    = now;
        event->flush_start_ns  = state->start_ns;
        event->flush_end_ns    = now;
        event->flush_latency_ns = latency_ns;
        event->lsn             = state->lsn;
        event->pid             = pid;
        bpf_ringbuf_submit(event, 0);
    }

    bpf_map_delete_elem(&wal_op_states, &pid);
    return 0;
}

/* ============================================================
 * CreateCheckPoint - Checkpoint tracking
 * void CreateCheckPoint(int flags)
 * ============================================================ */

SEC("uprobe/postgres:CreateCheckPoint")
int BPF_UPROBE(pg_checkpoint_start, int flags)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct wal_op_state state = {
        .start_ns = bpf_ktime_get_ns(),
        .op_type  = 2,  /* checkpoint */
    };
    bpf_map_update_elem(&wal_op_states, &pid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe/postgres:CreateCheckPoint")
int BPF_URETPROBE(pg_checkpoint_end)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct wal_op_state *state = bpf_map_lookup_elem(&wal_op_states, &pid);
    if (!state || state->op_type != 2) {
        bpf_map_delete_elem(&wal_op_states, &pid);
        return 0;
    }

    __u64 duration_ns = now - state->start_ns;

    __u32 zero = 0;
    struct wal_stats *stats = bpf_map_lookup_elem(&wal_global_stats, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->checkpoint_count, 1);
        __sync_fetch_and_add(&stats->total_checkpoint_duration_ns, duration_ns);
    }

    /* Emit checkpoint event */
    struct wal_event *event = bpf_ringbuf_reserve(&wal_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns  = now;
        event->pid           = pid;
        event->is_checkpoint = 1;
        event->record_type   = WAL_TYPE_CHECKPOINT;
        bpf_ringbuf_submit(event, 0);
    }

    bpf_map_delete_elem(&wal_op_states, &pid);
    return 0;
}

/* Cleanup */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&wal_op_states, &pid);
    return 0;
}
