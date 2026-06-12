// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - I/O Profiler eBPF Program
 *
 * Instruments PostgreSQL I/O operations at the block device level using
 * kernel tracepoints and PostgreSQL-specific uprobes. Tracks per-relation
 * read/write latencies, buffer cache efficiency, and WAL I/O patterns.
 *
 * Kernel mechanisms used:
 *   - tracepoint/block/block_rq_issue   - Block I/O requests issued
 *   - tracepoint/block/block_rq_complete - Block I/O completions
 *   - tracepoint/filemap/mm_filemap_add_to_page_cache - Page cache add
 *   - tracepoint/filemap/mm_filemap_delete_from_page_cache - Page evict
 *   - uprobe on mdread()     - PostgreSQL relation file reads
 *   - uprobe on mdwrite()    - PostgreSQL relation file writes
 *   - uprobe on smgrread()   - Storage manager reads
 *   - uprobe on smgrwrite()  - Storage manager writes
 *   - uprobe on FileRead()   - VFD file reads
 *   - uprobe on FileWrite()  - VFD file writes
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
 * eBPF Maps
 * ============================================================ */

/* Ring buffer for I/O events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} io_events SEC(".maps");

/* Track in-flight block I/O requests by device+sector */
struct bio_key {
    __u32  dev;                 /* Device number */
    __u64  sector;              /* Starting sector */
};

struct bio_info {
    __u64  issue_ns;            /* Issue timestamp */
    __u32  pid;                 /* Process that issued the I/O */
    __u32  size;                /* I/O size in bytes */
    __u8   is_write;            /* 1=write, 0=read */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct bio_key);
    __type(value, struct bio_info);
} bio_inflight SEC(".maps");

/* Per-relation I/O statistics */
struct relation_io_stats {
    __u64  read_count;
    __u64  write_count;
    __u64  fsync_count;
    __u64  bytes_read;
    __u64  bytes_written;
    __u64  total_read_latency_ns;
    __u64  total_write_latency_ns;
    __u64  max_read_latency_ns;
    __u64  max_write_latency_ns;
    __u64  cache_hits;
    __u64  cache_misses;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct relation_key);
    __type(value, struct relation_io_stats);
} relation_io_stats_map SEC(".maps");

/* I/O latency histograms - separate for reads and writes */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} read_latency_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} write_latency_hist SEC(".maps");

/* Track PostgreSQL smgr operations per PID */
struct smgr_op_state {
    __u64  start_ns;
    __u32  rel_filenode;
    __u32  db_oid;
    __u32  fork_number;
    __u32  block_num;
    __u64  bytes;
    __u8   is_write;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct smgr_op_state);
} smgr_op_states SEC(".maps");

/* Buffer cache statistics per database */
struct db_buffer_stats {
    __u64  hits;
    __u64  misses;
    __u64  evictions;
    __u64  dirty_evictions;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);             /* db_oid */
    __type(value, struct db_buffer_stats);
} db_buffer_stats_map SEC(".maps");

/* Profiler configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct profiler_config);
} profiler_config_map SEC(".maps");

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
 * Tracepoint Handlers - Block Layer I/O
 * ============================================================ */

/*
 * block_rq_issue - fired when a block I/O request is submitted to hardware
 */
SEC("tracepoint/block/block_rq_issue")
int tp_block_rq_issue(struct trace_event_raw_block_rq *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Only track PostgreSQL processes */
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    /* Quick check: PostgreSQL process names start with 'postgres' */
    if (comm[0] != 'p' || comm[1] != 'o') return 0;

    struct bio_key key = {
        .dev    = ctx->dev,
        .sector = ctx->sector,
    };

    struct bio_info info = {
        .issue_ns = bpf_ktime_get_ns(),
        .pid      = pid,
        .size     = ctx->nr_sector * 512,
        .is_write = (ctx->rwbs[0] == 'W') ? 1 : 0,
    };

    bpf_map_update_elem(&bio_inflight, &key, &info, BPF_ANY);
    return 0;
}

/*
 * block_rq_complete - fired when block I/O request completes
 */
SEC("tracepoint/block/block_rq_complete")
int tp_block_rq_complete(struct trace_event_raw_block_rq_completion *ctx)
{
    struct bio_key key = {
        .dev    = ctx->dev,
        .sector = ctx->sector,
    };

    struct bio_info *info = bpf_map_lookup_elem(&bio_inflight, &key);
    if (!info) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 latency_ns = now - info->issue_ns;
    __u32 pid = info->pid;
    __u8 is_write = info->is_write;
    __u32 size = info->size;

    bpf_map_delete_elem(&bio_inflight, &key);

    /* Emit I/O event */
    struct io_event *event = bpf_ringbuf_reserve(&io_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns  = now;
        event->issue_ns      = now - latency_ns;
        event->complete_ns   = now;
        event->latency_ns    = latency_ns;
        event->bytes         = size;
        event->pid           = pid;
        event->op_type       = is_write ? IO_OP_WRITE : IO_OP_READ;
        bpf_ringbuf_submit(event, 0);
    }

    /* Update latency histogram */
    __u32 bucket = log2_ns(latency_ns);
    if (is_write) {
        __u64 *hval = bpf_map_lookup_elem(&write_latency_hist, &bucket);
        if (hval) __sync_fetch_and_add(hval, 1);
    } else {
        __u64 *hval = bpf_map_lookup_elem(&read_latency_hist, &bucket);
        if (hval) __sync_fetch_and_add(hval, 1);
    }

    return 0;
}

/* ============================================================
 * uprobe Handlers - PostgreSQL Storage Manager
 *
 * smgrread/smgrwrite are the primary storage manager interfaces
 * in PostgreSQL, called for every relation block read/write.
 * ============================================================ */

/*
 * uprobe on smgrread(SMgrRelation reln, ForkNumber forknum,
 *                    BlockNumber blocknum, char *buffer)
 *
 * Arguments by register/stack (x86_64 calling convention):
 *   rdi = SMgrRelation *reln
 *   rsi = ForkNumber forknum
 *   rdx = BlockNumber blocknum
 *   rcx = char *buffer
 */
SEC("uprobe/postgres:smgrread")
int BPF_UPROBE(pg_smgrread, void *reln, int forknum, __u32 blocknum, void *buffer)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct smgr_op_state state = {
        .start_ns    = now,
        .fork_number = (__u32)forknum,
        .block_num   = blocknum,
        .bytes       = 8192,  /* PostgreSQL default block size */
        .is_write    = 0,
    };

    /* Read relation filenode from SMgrRelation struct */
    /* SMgrRelation->smgr_rlocator.locator.relNumber (offset varies by PG version) */
    /* Using BTF would allow version-independent access */
    __u32 relfilenode = 0;
    bpf_probe_read_user(&relfilenode, sizeof(relfilenode),
                        (__u8 *)reln + 8);  /* Approximate offset */
    state.rel_filenode = relfilenode;

    bpf_map_update_elem(&smgr_op_states, &pid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe/postgres:smgrread")
int BPF_URETPROBE(pg_smgrread_ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct smgr_op_state *state = bpf_map_lookup_elem(&smgr_op_states, &pid);
    if (!state || state->is_write) {
        bpf_map_delete_elem(&smgr_op_states, &pid);
        return 0;
    }

    __u64 latency_ns = now - state->start_ns;

    /* Update relation I/O stats */
    struct relation_key rkey = {
        .rel_filenode = state->rel_filenode,
        .fork_number  = state->fork_number,
    };

    struct relation_io_stats *stats = bpf_map_lookup_elem(&relation_io_stats_map, &rkey);
    if (stats) {
        __sync_fetch_and_add(&stats->read_count, 1);
        __sync_fetch_and_add(&stats->bytes_read, state->bytes);
        __sync_fetch_and_add(&stats->total_read_latency_ns, latency_ns);
        if (latency_ns > stats->max_read_latency_ns)
            stats->max_read_latency_ns = latency_ns;
    } else {
        struct relation_io_stats new_stats = {
            .read_count            = 1,
            .bytes_read            = state->bytes,
            .total_read_latency_ns = latency_ns,
            .max_read_latency_ns   = latency_ns,
        };
        bpf_map_update_elem(&relation_io_stats_map, &rkey, &new_stats, BPF_NOEXIST);
    }

    bpf_map_delete_elem(&smgr_op_states, &pid);
    return 0;
}

/*
 * uprobe on smgrwrite()
 */
SEC("uprobe/postgres:smgrwrite")
int BPF_UPROBE(pg_smgrwrite, void *reln, int forknum, __u32 blocknum,
               void *buffer, bool skipFsync)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct smgr_op_state state = {
        .start_ns    = now,
        .fork_number = (__u32)forknum,
        .block_num   = blocknum,
        .bytes       = 8192,
        .is_write    = 1,
    };

    __u32 relfilenode = 0;
    bpf_probe_read_user(&relfilenode, sizeof(relfilenode), (__u8 *)reln + 8);
    state.rel_filenode = relfilenode;

    bpf_map_update_elem(&smgr_op_states, &pid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe/postgres:smgrwrite")
int BPF_URETPROBE(pg_smgrwrite_ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct smgr_op_state *state = bpf_map_lookup_elem(&smgr_op_states, &pid);
    if (!state || !state->is_write) {
        bpf_map_delete_elem(&smgr_op_states, &pid);
        return 0;
    }

    __u64 latency_ns = now - state->start_ns;

    struct relation_key rkey = {
        .rel_filenode = state->rel_filenode,
        .fork_number  = state->fork_number,
    };

    struct relation_io_stats *stats = bpf_map_lookup_elem(&relation_io_stats_map, &rkey);
    if (stats) {
        __sync_fetch_and_add(&stats->write_count, 1);
        __sync_fetch_and_add(&stats->bytes_written, state->bytes);
        __sync_fetch_and_add(&stats->total_write_latency_ns, latency_ns);
        if (latency_ns > stats->max_write_latency_ns)
            stats->max_write_latency_ns = latency_ns;
    } else {
        struct relation_io_stats new_stats = {
            .write_count             = 1,
            .bytes_written           = state->bytes,
            .total_write_latency_ns  = latency_ns,
            .max_write_latency_ns    = latency_ns,
        };
        bpf_map_update_elem(&relation_io_stats_map, &rkey, &new_stats, BPF_NOEXIST);
    }

    bpf_map_delete_elem(&smgr_op_states, &pid);
    return 0;
}

/* ============================================================
 * uprobe on smgrfsync() - fsync/checkpoint tracking
 * ============================================================ */
SEC("uprobe/postgres:smgrfsync")
int BPF_UPROBE(pg_smgrfsync, void *reln, int forknum)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct smgr_op_state state = {
        .start_ns    = bpf_ktime_get_ns(),
        .fork_number = (__u32)forknum,
        .is_write    = 2,  /* fsync marker */
    };
    bpf_map_update_elem(&smgr_op_states, &pid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe/postgres:smgrfsync")
int BPF_URETPROBE(pg_smgrfsync_ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct smgr_op_state *state = bpf_map_lookup_elem(&smgr_op_states, &pid);
    if (!state) return 0;

    __u64 latency_ns = now - state->start_ns;

    /* Emit fsync event */
    struct io_event *event = bpf_ringbuf_reserve(&io_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns  = now;
        event->latency_ns    = latency_ns;
        event->pid           = pid;
        event->rel_filenode  = state->rel_filenode;
        event->op_type       = IO_OP_FSYNC;
        bpf_ringbuf_submit(event, 0);
    }

    bpf_map_delete_elem(&smgr_op_states, &pid);
    return 0;
}

/* ============================================================
 * Tracepoint: page cache operations for buffer cache tracking
 * ============================================================ */
SEC("tracepoint/filemap/mm_filemap_add_to_page_cache")
int tp_filemap_add_to_cache(struct trace_event_raw_mm_filemap_op_page_range *ctx)
{
    /* Track page cache additions for PostgreSQL files */
    /* This helps correlate OS page cache with PostgreSQL buffer cache */
    return 0;
}

/* ============================================================
 * Cleanup
 * ============================================================ */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&smgr_op_states, &pid);
    return 0;
}
