// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - Wait Event Profiler eBPF Program
 *
 * Tracks PostgreSQL wait events with nanosecond precision using USDT probes.
 * Provides real-time visibility into what PostgreSQL backends are waiting for,
 * matching PostgreSQL 14+ wait event taxonomy.
 *
 * Wait event categories:
 *   - Lock: Heavyweight lock waits
 *   - LWLock: Lightweight lock waits
 *   - BufferPin: Buffer pin waits
 *   - IO: Disk I/O waits
 *   - Extension: Extension-defined waits
 *   - Client: Network/client I/O waits
 *   - IPC: Inter-process communication
 *   - Timeout: Timer-based waits
 *   - CPU: Currently executing (not waiting)
 *
 * USDT probes:
 *   - postgresql:wait__start   (arg0=wait_event_class, arg1=wait_event_id)
 *   - postgresql:wait__done    (arg0=wait_event_class, arg1=wait_event_id)
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
 * eBPF Maps
 * ============================================================ */

/* Ring buffer for wait events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} wait_events SEC(".maps");

/* Track wait state per PID */
struct wait_state {
    __u64  wait_start_ns;
    __u32  wait_type;           /* wait_event_type enum */
    __u32  wait_id;             /* Specific wait event ID */
    __u32  db_oid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);         /* PID */
    __type(value, struct wait_state);
} wait_states SEC(".maps");

/*
 * Wait event statistics aggregation
 * Key: (wait_type, wait_id)
 * Value: statistics
 */
struct wait_event_key {
    __u32  wait_type;
    __u32  wait_id;
};

struct wait_event_stats {
    __u64  count;
    __u64  total_wait_ns;
    __u64  min_wait_ns;
    __u64  max_wait_ns;
    __u64  p50_bucket;          /* Histogram bucket for ~p50 */
    __u64  p99_bucket;          /* Histogram bucket for ~p99 */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);   /* ~100 wait event types in PostgreSQL */
    __type(key, struct wait_event_key);
    __type(value, struct wait_event_stats);
} wait_event_stats_map SEC(".maps");

/*
 * Current wait snapshot per PID (for real-time "what are backends waiting for")
 * This is polled by userspace at regular intervals.
 */
struct current_wait {
    __u64  wait_start_ns;
    __u32  wait_type;
    __u32  wait_id;
    __u32  db_oid;
    __u32  padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);         /* PID */
    __type(value, struct current_wait);
} current_waits SEC(".maps");

/* Wait duration histogram - one per wait event type */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} wait_duration_hist SEC(".maps");

/* Active PID count per wait type (for real-time monitoring) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);    /* Number of wait event types */
    __type(key, __u32);         /* wait_event_type */
    __type(value, __u64);       /* active count */
} active_wait_counts SEC(".maps");

/* Profiler configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct profiler_config);
} profiler_config_map SEC(".maps");

/* ============================================================
 * Wait event type name lookup (for logging) 
 * ============================================================ */

/* PostgreSQL wait event class IDs (from pgstat.h) */
#define PG_WAIT_LWLOCK          0x01000000U
#define PG_WAIT_LOCK            0x03000000U
#define PG_WAIT_BUFFER_PIN      0x04000000U
#define PG_WAIT_ACTIVITY        0x05000000U
#define PG_WAIT_CLIENT          0x06000000U
#define PG_WAIT_EXTENSION       0x07000000U
#define PG_WAIT_IPC             0x08000000U
#define PG_WAIT_TIMEOUT         0x09000000U
#define PG_WAIT_IO              0x0A000000U

static __always_inline __u8 classify_wait_event(__u32 wait_event_info)
{
    __u32 class = wait_event_info & 0xFF000000U;
    if (class == PG_WAIT_LOCK)       return WAIT_EVENT_LOCK;
    if (class == PG_WAIT_LWLOCK)     return WAIT_EVENT_LWLOCK;
    if (class == PG_WAIT_BUFFER_PIN) return WAIT_EVENT_BUFFER_PIN;
    if (class == PG_WAIT_IO)         return WAIT_EVENT_IO;
    if (class == PG_WAIT_CLIENT)     return WAIT_EVENT_CLIENT;
    if (class == PG_WAIT_IPC)        return WAIT_EVENT_IPC;
    if (class == PG_WAIT_TIMEOUT)    return WAIT_EVENT_TIMEOUT;
    if (class == PG_WAIT_EXTENSION)  return WAIT_EVENT_EXTENSION;
    return WAIT_EVENT_CPU;           /* Default: running */
}

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
 * USDT Probe Handlers
 * ============================================================ */

/*
 * postgresql:wait__start
 * Fired when a PostgreSQL backend begins waiting.
 * arg0 = wait_event_info (encoded class + event ID as uint32)
 *
 * In PostgreSQL, wait event info is stored in MyProc->wait_event_info:
 *   bits 31-24: wait event class
 *   bits 23-0:  specific wait event within class
 */
SEC("usdt/postgres:postgresql:wait__start")
int BPF_USDT(pg_wait_start, unsigned int wait_event_info)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    __u8 wait_type = classify_wait_event(wait_event_info);
    __u32 wait_id  = wait_event_info & 0x00FFFFFFU;

    /* Store wait state */
    struct wait_state state = {
        .wait_start_ns = now,
        .wait_type     = wait_type,
        .wait_id       = wait_id,
    };
    bpf_map_update_elem(&wait_states, &pid, &state, BPF_ANY);

    /* Update current wait snapshot */
    struct current_wait cw = {
        .wait_start_ns = now,
        .wait_type     = wait_type,
        .wait_id       = wait_id,
    };
    bpf_map_update_elem(&current_waits, &pid, &cw, BPF_ANY);

    /* Increment active wait count for this type */
    __u32 type_key = wait_type;
    __u64 *active = bpf_map_lookup_elem(&active_wait_counts, &type_key);
    if (active)
        __sync_fetch_and_add(active, 1);

    return 0;
}

/*
 * postgresql:wait__done
 * Fired when a PostgreSQL backend finishes waiting.
 * arg0 = wait_event_info (same encoding as wait__start)
 */
SEC("usdt/postgres:postgresql:wait__done")
int BPF_USDT(pg_wait_done, unsigned int wait_event_info)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct wait_state *state = bpf_map_lookup_elem(&wait_states, &pid);
    if (!state) return 0;

    __u64 wait_duration_ns = 0;
    if (state->wait_start_ns > 0 && now > state->wait_start_ns)
        wait_duration_ns = now - state->wait_start_ns;

    __u8  wait_type = (__u8)state->wait_type;
    __u32 wait_id   = state->wait_id;

    /* Decrement active wait count */
    __u32 type_key = wait_type;
    __u64 *active = bpf_map_lookup_elem(&active_wait_counts, &type_key);
    if (active && *active > 0)
        __sync_fetch_and_add(active, (__u64)(-1));

    /* Remove current wait snapshot */
    bpf_map_delete_elem(&current_waits, &pid);

    /* Update wait event statistics */
    struct wait_event_key wkey = {
        .wait_type = wait_type,
        .wait_id   = wait_id,
    };

    struct wait_event_stats *stats = bpf_map_lookup_elem(&wait_event_stats_map, &wkey);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        __sync_fetch_and_add(&stats->total_wait_ns, wait_duration_ns);
        if (wait_duration_ns < stats->min_wait_ns || stats->min_wait_ns == 0)
            stats->min_wait_ns = wait_duration_ns;
        if (wait_duration_ns > stats->max_wait_ns)
            stats->max_wait_ns = wait_duration_ns;
    } else {
        struct wait_event_stats new_stats = {
            .count         = 1,
            .total_wait_ns = wait_duration_ns,
            .min_wait_ns   = wait_duration_ns,
            .max_wait_ns   = wait_duration_ns,
        };
        bpf_map_update_elem(&wait_event_stats_map, &wkey, &new_stats, BPF_NOEXIST);
    }

    /* Update histogram */
    __u32 bucket = log2_ns(wait_duration_ns);
    __u64 *hist  = bpf_map_lookup_elem(&wait_duration_hist, &bucket);
    if (hist)
        __sync_fetch_and_add(hist, 1);

    /* Emit detailed event to ring buffer for significant waits */
    __u32 zero = 0;
    struct profiler_config *cfg = bpf_map_lookup_elem(&profiler_config_map, &zero);
    __u64 min_wait = cfg ? cfg->lock_min_wait_ns : 100000;  /* 100us default */

    if (wait_duration_ns >= min_wait) {
        struct wait_event *event = bpf_ringbuf_reserve(&wait_events,
                                                        sizeof(*event), 0);
        if (event) {
            event->timestamp_ns    = now;
            event->wait_start_ns   = state->wait_start_ns;
            event->wait_end_ns     = now;
            event->wait_duration_ns = wait_duration_ns;
            event->pid             = pid;
            event->db_oid          = state->db_oid;
            event->wait_type       = wait_type;
            bpf_ringbuf_submit(event, 0);
        }
    }

    bpf_map_delete_elem(&wait_states, &pid);
    return 0;
}

/* ============================================================
 * Periodic wait snapshot via uprobe on pgstat_report_wait_start
 *
 * PostgreSQL calls pgstat_report_wait_start() to update the shared
 * memory wait event info for pg_stat_activity. We can hook this
 * to get a consistent view of what each backend is waiting for.
 * ============================================================ */
SEC("uprobe/postgres:pgstat_report_wait_start")
int BPF_UPROBE(pg_pgstat_wait_start, __u32 wait_event_info)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    __u8  wait_type = classify_wait_event(wait_event_info);
    __u32 wait_id   = wait_event_info & 0x00FFFFFFU;

    struct current_wait cw = {
        .wait_start_ns = now,
        .wait_type     = wait_type,
        .wait_id       = wait_id,
    };
    bpf_map_update_elem(&current_waits, &pid, &cw, BPF_ANY);
    return 0;
}

SEC("uprobe/postgres:pgstat_report_wait_end")
int BPF_UPROBE(pg_pgstat_wait_end)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&current_waits, &pid);
    return 0;
}

/* ============================================================
 * Cleanup
 * ============================================================ */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&wait_states, &pid);
    bpf_map_delete_elem(&current_waits, &pid);
    return 0;
}
