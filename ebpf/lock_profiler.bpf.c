// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - Lock Profiler eBPF Program
 *
 * Instruments PostgreSQL lock acquisition and release using USDT probes
 * and uprobes. Tracks lock wait times, contention patterns, and deadlocks.
 *
 * Supported probe points:
 *   - postgresql:lock__wait__start    (USDT) - Heavyweight lock wait start
 *   - postgresql:lock__wait__done     (USDT) - Heavyweight lock wait end
 *   - uprobe on LockAcquire()         - Lock acquisition entry
 *   - uretprobe on LockAcquire()      - Lock acquisition exit
 *   - uprobe on LockRelease()         - Lock release
 *   - uprobe on LWLockAcquire()       - LWLock acquisition
 *   - uretprobe on LWLockAcquire()    - LWLock acquisition exit
 *   - uprobe on LWLockRelease()       - LWLock release
 *   - uprobe on DeadLockCheck()       - Deadlock detection
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

/* Ring buffer for lock events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} lock_events SEC(".maps");

/* Track lock wait state per PID */
struct lock_wait_state {
    __u64  wait_start_ns;
    __u32  lockmode;
    __u32  rel_oid;
    __u32  db_oid;
    __u8   locktype;
    __u8   is_lwlock;
    char   lockname[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct lock_wait_state);
} lock_wait_states SEC(".maps");

/* Track lock hold state per PID (acquired -> released) */
struct lock_hold_state {
    __u64  acquire_ns;
    __u32  lockmode;
    __u32  rel_oid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct lock_hold_state);
} lock_hold_states SEC(".maps");

/* Per-relation lock contention statistics */
struct lock_relation_stats {
    __u64  wait_count;
    __u64  total_wait_ns;
    __u64  max_wait_ns;
    __u64  hold_count;
    __u64  total_hold_ns;
    __u64  deadlock_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);             /* rel_oid */
    __type(value, struct lock_relation_stats);
} lock_relation_stats_map SEC(".maps");

/* Lock wait duration histogram */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} lock_wait_hist SEC(".maps");

/* LWLock contention by lock ID */
struct lwlock_stats {
    __u64  acquire_count;
    __u64  total_wait_ns;
    __u64  max_wait_ns;
    char   name[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);             /* LWLock tranche ID */
    __type(value, struct lwlock_stats);
} lwlock_stats_map SEC(".maps");

/* Profiler configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct profiler_config);
} profiler_config_map SEC(".maps");

/* Deadlock counter */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} deadlock_counter SEC(".maps");

/* ============================================================
 * Helper Functions
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
 * USDT Probe Handlers - Heavyweight Lock Waits
 * ============================================================ */

/*
 * postgresql:lock__wait__start
 * Fired when a heavyweight lock acquisition must wait.
 * args: locktagtype, oid, oid2, objsubid, mode
 */
SEC("usdt/postgres:postgresql:lock__wait__start")
int BPF_USDT(pg_lock_wait_start, int locktagtype, unsigned int oid,
             unsigned int oid2, int objsubid, int mode)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct lock_wait_state state = {
        .wait_start_ns = now,
        .lockmode      = (__u32)mode,
        .rel_oid       = oid,
        .locktype      = (__u8)locktagtype,
        .is_lwlock     = 0,
    };

    bpf_map_update_elem(&lock_wait_states, &pid, &state, BPF_ANY);
    return 0;
}

/*
 * postgresql:lock__wait__done
 * Fired when a heavyweight lock wait completes (lock acquired or timeout).
 * args: locktagtype, oid, oid2, objsubid, mode
 */
SEC("usdt/postgres:postgresql:lock__wait__done")
int BPF_USDT(pg_lock_wait_done, int locktagtype, unsigned int oid,
             unsigned int oid2, int objsubid, int mode)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct lock_wait_state *state = bpf_map_lookup_elem(&lock_wait_states, &pid);
    if (!state)
        return 0;

    __u64 wait_duration_ns = 0;
    if (state->wait_start_ns > 0 && now > state->wait_start_ns)
        wait_duration_ns = now - state->wait_start_ns;

    /* Get config - check minimum wait threshold */
    __u32 zero = 0;
    struct profiler_config *cfg = bpf_map_lookup_elem(&profiler_config_map, &zero);
    if (cfg && wait_duration_ns < cfg->lock_min_wait_ns) {
        bpf_map_delete_elem(&lock_wait_states, &pid);
        return 0;
    }

    /* Emit lock event to ring buffer */
    struct lock_event *event = bpf_ringbuf_reserve(&lock_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&lock_wait_states, &pid);
        return 0;
    }

    event->timestamp_ns     = now;
    event->wait_start_ns    = state->wait_start_ns;
    event->wait_end_ns      = now;
    event->wait_duration_ns = wait_duration_ns;
    event->pid              = pid;
    event->rel_oid          = oid;
    event->db_oid           = state->db_oid;
    event->lockmode         = (__u8)mode;
    event->locktype         = (__u8)locktagtype;
    event->granted          = 1;  /* USDT fires on success */

    bpf_ringbuf_submit(event, 0);

    /* Update histogram */
    __u32 bucket = log2_ns(wait_duration_ns);
    __u64 *hist_val = bpf_map_lookup_elem(&lock_wait_hist, &bucket);
    if (hist_val)
        __sync_fetch_and_add(hist_val, 1);

    /* Update per-relation statistics */
    struct lock_relation_stats *rel_stats =
        bpf_map_lookup_elem(&lock_relation_stats_map, &oid);
    if (rel_stats) {
        __sync_fetch_and_add(&rel_stats->wait_count, 1);
        __sync_fetch_and_add(&rel_stats->total_wait_ns, wait_duration_ns);
        if (wait_duration_ns > rel_stats->max_wait_ns)
            rel_stats->max_wait_ns = wait_duration_ns;
    } else {
        struct lock_relation_stats new_stats = {
            .wait_count    = 1,
            .total_wait_ns = wait_duration_ns,
            .max_wait_ns   = wait_duration_ns,
        };
        bpf_map_update_elem(&lock_relation_stats_map, &oid, &new_stats, BPF_NOEXIST);
    }

    /* Track hold state */
    struct lock_hold_state hold = {
        .acquire_ns = now,
        .lockmode   = (__u32)mode,
        .rel_oid    = oid,
    };
    bpf_map_update_elem(&lock_hold_states, &pid, &hold, BPF_ANY);

    bpf_map_delete_elem(&lock_wait_states, &pid);
    return 0;
}

/* ============================================================
 * uprobe Handlers - LWLock (Lightweight Lock)
 *
 * LWLocks are PostgreSQL's internal lightweight locks used to
 * protect shared memory data structures. They have lower overhead
 * than heavyweight locks but can still be contention points.
 * ============================================================ */

/*
 * Uprobe on LWLockAcquire(LWLock *lock, LWLockMode mode)
 * Track LWLock acquisition start.
 */
SEC("uprobe/postgres:LWLockAcquire")
int BPF_UPROBE(pg_lwlock_acquire_entry, void *lock, int mode)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct lock_wait_state state = {
        .wait_start_ns = now,
        .lockmode      = (__u32)mode,
        .is_lwlock     = 1,
    };

    /* Read tranche ID from LWLock struct (offset 0 = tranche field) */
    __u16 tranche_id = 0;
    bpf_probe_read_user(&tranche_id, sizeof(tranche_id), lock);
    state.rel_oid = tranche_id;

    bpf_map_update_elem(&lock_wait_states, &pid, &state, BPF_ANY);
    return 0;
}

/*
 * Uretprobe on LWLockAcquire return.
 * Return value: true if lock was acquired without sleeping.
 */
SEC("uretprobe/postgres:LWLockAcquire")
int BPF_URETPROBE(pg_lwlock_acquire_exit, bool acquired_without_waiting)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct lock_wait_state *state = bpf_map_lookup_elem(&lock_wait_states, &pid);
    if (!state || !state->is_lwlock) {
        bpf_map_delete_elem(&lock_wait_states, &pid);
        return 0;
    }

    __u64 wait_duration_ns = 0;
    if (!acquired_without_waiting && state->wait_start_ns > 0)
        wait_duration_ns = now - state->wait_start_ns;

    /* Only record contentions (wait > 0) */
    if (wait_duration_ns > 0) {
        /* Update LWLock statistics */
        __u32 tranche_id = state->rel_oid;
        struct lwlock_stats *stats = bpf_map_lookup_elem(&lwlock_stats_map, &tranche_id);
        if (stats) {
            __sync_fetch_and_add(&stats->acquire_count, 1);
            __sync_fetch_and_add(&stats->total_wait_ns, wait_duration_ns);
            if (wait_duration_ns > stats->max_wait_ns)
                stats->max_wait_ns = wait_duration_ns;
        } else {
            struct lwlock_stats new_stats = {
                .acquire_count = 1,
                .total_wait_ns = wait_duration_ns,
                .max_wait_ns   = wait_duration_ns,
            };
            bpf_map_update_elem(&lwlock_stats_map, &tranche_id, &new_stats, BPF_NOEXIST);
        }

        /* Emit lock event for significant LWLock waits */
        __u32 zero = 0;
        struct profiler_config *cfg = bpf_map_lookup_elem(&profiler_config_map, &zero);
        if (!cfg || wait_duration_ns >= cfg->lock_min_wait_ns) {
            struct lock_event *event = bpf_ringbuf_reserve(&lock_events,
                                                            sizeof(*event), 0);
            if (event) {
                event->timestamp_ns     = now;
                event->wait_start_ns    = state->wait_start_ns;
                event->wait_end_ns      = now;
                event->wait_duration_ns = wait_duration_ns;
                event->pid              = pid;
                event->lockmode         = (__u8)state->lockmode;
                event->locktype         = PG_LOCKTYPE_LWLOCK;
                event->granted          = 1;
                bpf_ringbuf_submit(event, 0);
            }
        }
    }

    bpf_map_delete_elem(&lock_wait_states, &pid);
    return 0;
}

/* ============================================================
 * uprobe on DeadLockCheck()
 * Fires when PostgreSQL's deadlock detection algorithm runs.
 * ============================================================ */
SEC("uprobe/postgres:DeadLockCheck")
int BPF_UPROBE(pg_deadlock_check)
{
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&deadlock_counter, &zero);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    /* Emit a lock event with deadlock flag */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lock_event *event = bpf_ringbuf_reserve(&lock_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns = bpf_ktime_get_ns();
        event->pid          = pid;
        event->is_deadlock  = 1;
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

/* ============================================================
 * Cleanup on process exit
 * ============================================================ */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&lock_wait_states, &pid);
    bpf_map_delete_elem(&lock_hold_states, &pid);
    return 0;
}
