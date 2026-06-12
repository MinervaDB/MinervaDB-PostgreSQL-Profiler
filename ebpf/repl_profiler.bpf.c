// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - Replication Profiler eBPF Program
 *
 * Profiles PostgreSQL streaming replication - tracking WAL sender
 * and receiver operations, lag measurements, and apply latency.
 *
 * Probe points (Primary - WAL Sender):
 *   - uprobe on WalSndMain()          - WAL sender main loop
 *   - uprobe on WalSndWriteData()     - WAL data sent
 *   - uprobe on WalSndKeepalive()     - Keepalive sent
 *   - uprobe on ProcessStandbyMessage() - Standby message received
 *
 * Probe points (Replica - WAL Receiver):
 *   - uprobe on WalReceiverMain()     - WAL receiver main loop
 *   - uprobe on XLogWalRcvWrite()     - WAL received and written
 *   - uprobe on XLogWalRcvFlush()     - WAL flushed on replica
 *   - uprobe on ApplyLoop()           - Logical replication apply
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
    __uint(max_entries, 4 * 1024 * 1024);
} repl_events SEC(".maps");

/* WAL sender state */
struct walsnd_state {
    __u64  send_start_ns;
    __u64  lsn_sent;
    __u64  lsn_flushed;
    __u64  lsn_applied;
    __u32  standby_addr;
    __u8   is_active;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);    /* Max WAL senders (max_wal_senders) */
    __type(key, __u32);         /* PID */
    __type(value, struct walsnd_state);
} walsnd_states SEC(".maps");

/* WAL receiver state */
struct walrcv_state {
    __u64  recv_start_ns;
    __u64  bytes_received;
    __u64  lsn_received;
    __u64  lsn_flushed;
    __u32  primary_addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);     /* Max WAL receivers */
    __type(key, __u32);         /* PID */
    __type(value, struct walrcv_state);
} walrcv_states SEC(".maps");

/* Replication lag statistics */
struct repl_lag_stats {
    __u64  total_lag_samples;
    __u64  total_send_lag_ns;
    __u64  total_write_lag_ns;
    __u64  total_flush_lag_ns;
    __u64  total_replay_lag_ns;
    __u64  max_send_lag_ns;
    __u64  max_replay_lag_ns;
    __u64  bytes_sent;
    __u64  bytes_received;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct repl_lag_stats);
} repl_lag_stats_map SEC(".maps");

/* ============================================================
 * WAL Sender Probes (Primary)
 * ============================================================ */

/*
 * uprobe on WalSndWriteData()
 * Called when WAL sender writes data to the standby.
 */
SEC("uprobe/postgres:WalSndWriteData")
int BPF_UPROBE(pg_walsnd_write_start)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct walsnd_state *state = bpf_map_lookup_elem(&walsnd_states, &pid);
    if (state) {
        state->send_start_ns = now;
    } else {
        struct walsnd_state new_state = {
            .send_start_ns = now,
            .is_active     = 1,
        };
        bpf_map_update_elem(&walsnd_states, &pid, &new_state, BPF_ANY);
    }
    return 0;
}

SEC("uretprobe/postgres:WalSndWriteData")
int BPF_URETPROBE(pg_walsnd_write_done)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct walsnd_state *state = bpf_map_lookup_elem(&walsnd_states, &pid);
    if (!state || state->send_start_ns == 0) return 0;

    __u64 send_latency = now - state->send_start_ns;

    /* Update lag stats */
    __u32 zero = 0;
    struct repl_lag_stats *stats = bpf_map_lookup_elem(&repl_lag_stats_map, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->total_lag_samples, 1);
        __sync_fetch_and_add(&stats->total_send_lag_ns, send_latency);
        if (send_latency > stats->max_send_lag_ns)
            stats->max_send_lag_ns = send_latency;
    }

    state->send_start_ns = 0;
    return 0;
}

/*
 * uprobe on ProcessStandbyMessage()
 * Captures standby lag info from the feedback messages.
 * This allows calculating write/flush/replay lag.
 */
SEC("uprobe/postgres:ProcessStandbyMessage")
int BPF_UPROBE(pg_standby_message)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    /* Update sample count */
    __u32 zero = 0;
    struct repl_lag_stats *stats = bpf_map_lookup_elem(&repl_lag_stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->total_lag_samples, 1);

    return 0;
}

/* ============================================================
 * WAL Receiver Probes (Replica)
 * ============================================================ */

/*
 * uprobe on XLogWalRcvWrite()
 * Called on replica when WAL data is written to disk.
 */
SEC("uprobe/postgres:XLogWalRcvWrite")
int BPF_UPROBE(pg_walrcv_write_start, char *buf, __u64 nbytes, __u64 recptr)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct walrcv_state *state = bpf_map_lookup_elem(&walrcv_states, &pid);
    if (state) {
        state->recv_start_ns = now;
        __sync_fetch_and_add(&state->bytes_received, nbytes);
    } else {
        struct walrcv_state new_state = {
            .recv_start_ns  = now,
            .bytes_received = nbytes,
            .lsn_received   = recptr,
        };
        bpf_map_update_elem(&walrcv_states, &pid, &new_state, BPF_ANY);
    }

    /* Update global stats */
    __u32 zero = 0;
    struct repl_lag_stats *stats = bpf_map_lookup_elem(&repl_lag_stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->bytes_received, nbytes);

    return 0;
}

SEC("uretprobe/postgres:XLogWalRcvWrite")
int BPF_URETPROBE(pg_walrcv_write_done)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct walrcv_state *state = bpf_map_lookup_elem(&walrcv_states, &pid);
    if (!state || state->recv_start_ns == 0) return 0;

    __u64 write_latency = now - state->recv_start_ns;

    __u32 zero = 0;
    struct repl_lag_stats *stats = bpf_map_lookup_elem(&repl_lag_stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->total_write_lag_ns, write_latency);

    state->recv_start_ns = 0;
    return 0;
}

/*
 * uprobe on XLogWalRcvFlush()
 * Called on replica when WAL is flushed (fsync'd).
 */
SEC("uprobe/postgres:XLogWalRcvFlush")
int BPF_UPROBE(pg_walrcv_flush_start, bool dying)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct walrcv_state *state = bpf_map_lookup_elem(&walrcv_states, &pid);
    if (state)
        state->recv_start_ns = bpf_ktime_get_ns();
    return 0;
}

SEC("uretprobe/postgres:XLogWalRcvFlush")
int BPF_URETPROBE(pg_walrcv_flush_done)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct walrcv_state *state = bpf_map_lookup_elem(&walrcv_states, &pid);
    if (!state || state->recv_start_ns == 0) return 0;

    __u64 flush_latency = now - state->recv_start_ns;

    __u32 zero = 0;
    struct repl_lag_stats *stats = bpf_map_lookup_elem(&repl_lag_stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->total_flush_lag_ns, flush_latency);

    state->recv_start_ns = 0;
    return 0;
}

/* ============================================================
 * Cleanup
 * ============================================================ */

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&walsnd_states, &pid);
    bpf_map_delete_elem(&walrcv_states, &pid);
    return 0;
}
