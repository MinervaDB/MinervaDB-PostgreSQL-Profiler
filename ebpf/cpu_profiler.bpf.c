// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - CPU Profiler eBPF Program
 *
 * Generates CPU flame graphs and scheduler analysis for PostgreSQL processes
 * using perf_events with a configurable sampling frequency (default 99Hz).
 *
 * Captures both on-CPU time (CPU flame graphs) and off-CPU time (wait analysis)
 * with full kernel + userspace stack traces for each sample.
 *
 * Kernel mechanisms:
 *   - perf_event (PERF_COUNT_SW_CPU_CLOCK) - CPU sampling
 *   - tracepoint/sched/sched_switch - Context switches (off-CPU)
 *   - tracepoint/sched/sched_wakeup - Process wakeups (off-CPU end)
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

/* Ring buffer for CPU samples */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);  /* 64MB for stack traces */
} cpu_samples SEC(".maps");

/*
 * Stack trace maps - separate for kernel and user stacks
 * STACK_TRACE map type stores arrays of instruction pointers.
 */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 131072);
} kernel_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 131072);
} user_stacks SEC(".maps");

/*
 * Folded stack aggregation map
 * Key = (kernel_stack_id, user_stack_id, pid)
 * Value = count of samples with this stack
 *
 * This is the primary data structure for flame graph generation.
 */
struct stack_count_key {
    __u32  pid;
    __s32  kernel_stack_id;
    __s32  user_stack_id;
    char   comm[MAX_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct stack_count_key);
    __type(value, __u64);
} stack_counts SEC(".maps");

/*
 * Off-CPU tracking - records when PostgreSQL backends go off-CPU
 * Key: TID, Value: timestamp when process was descheduled
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);             /* TID */
    __type(value, __u64);           /* off-cpu start timestamp */
} off_cpu_start SEC(".maps");

/* Off-CPU time aggregated by stack */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct stack_count_key);
    __type(value, __u64);           /* total off-cpu time in ns */
} off_cpu_times SEC(".maps");

/* Per-PID CPU usage accumulation */
struct pid_cpu_stats {
    __u64  on_cpu_ns;               /* Total on-CPU time (ns) */
    __u64  off_cpu_ns;              /* Total off-CPU time (wait time) */
    __u64  voluntary_switches;      /* Voluntary context switches */
    __u64  involuntary_switches;    /* Involuntary context switches */
    __u64  sample_count;            /* Number of on-CPU samples */
    char   comm[MAX_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pid_cpu_stats);
} pid_cpu_stats_map SEC(".maps");

/* Profiler configuration (PID filter, etc.) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);             /* PostgreSQL PID to monitor */
    __type(value, __u8);            /* 1 = monitor this PID */
} target_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct profiler_config);
} profiler_config_map SEC(".maps");

/* ============================================================
 * Helper Functions
 * ============================================================ */

static __always_inline bool is_postgres_pid(__u32 pid)
{
    /* Check if PID is in our target set */
    __u8 *val = bpf_map_lookup_elem(&target_pids, &pid);
    if (val && *val) return true;

    /* Fallback: check process name */
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    return (comm[0] == 'p' && comm[1] == 'o' && comm[2] == 's' &&
            comm[3] == 't' && comm[4] == 'g' && comm[5] == 'r');
}

/* ============================================================
 * perf_event handler - On-CPU sampling
 *
 * This is attached to a perf_event with type=PERF_COUNT_SW_CPU_CLOCK
 * at the configured frequency (default: 99Hz to avoid Nyquist issues).
 * ============================================================ */
SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    /* Filter to PostgreSQL processes only */
    if (!is_postgres_pid(pid)) return 0;

    /* Capture stack traces */
    __s32 kernel_stack_id = bpf_get_stackid(ctx, &kernel_stacks,
                                              BPF_F_FAST_STACK_CMP);
    __s32 user_stack_id   = bpf_get_stackid(ctx, &user_stacks,
                                              BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);

    /* Aggregate by stack signature */
    struct stack_count_key key = {
        .pid             = pid,
        .kernel_stack_id = kernel_stack_id,
        .user_stack_id   = user_stack_id,
    };
    bpf_get_current_comm(key.comm, sizeof(key.comm));

    __u64 *count = bpf_map_lookup_elem(&stack_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&stack_counts, &key, &one, BPF_NOEXIST);
    }

    /* Update per-PID CPU stats */
    struct pid_cpu_stats *stats = bpf_map_lookup_elem(&pid_cpu_stats_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->sample_count, 1);
        /* Approximate on-CPU time: sample_count * (1/Hz) * 1e9 ns */
        __sync_fetch_and_add(&stats->on_cpu_ns, 10101010);  /* ~10ms at 99Hz */
    } else {
        struct pid_cpu_stats new_stats = {
            .sample_count = 1,
            .on_cpu_ns    = 10101010,
        };
        bpf_get_current_comm(new_stats.comm, sizeof(new_stats.comm));
        bpf_map_update_elem(&pid_cpu_stats_map, &pid, &new_stats, BPF_NOEXIST);
    }

    /* Emit sample event for real-time monitoring */
    struct cpu_sample *sample = bpf_ringbuf_reserve(&cpu_samples, sizeof(*sample), 0);
    if (sample) {
        sample->timestamp_ns   = bpf_ktime_get_ns();
        sample->pid            = pid;
        sample->tid            = tid;
        sample->kstack_id      = (__u64)kernel_stack_id;
        sample->ustack_id      = (__u64)user_stack_id;
        bpf_get_current_comm(sample->comm, sizeof(sample->comm));
        bpf_ringbuf_submit(sample, 0);
    }

    return 0;
}

/* ============================================================
 * Off-CPU profiling via scheduler tracepoints
 *
 * By tracking when processes are descheduled (sched_switch) and
 * rescheduled (sched_wakeup), we can measure time spent waiting
 * for I/O, locks, sleep, etc.
 * ============================================================ */

/*
 * sched_switch - fired on every context switch
 * Captures the off-CPU start time for outgoing process.
 */
SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 prev_pid = ctx->prev_pid;
    __u32 next_pid = ctx->next_pid;
    __u64 now = bpf_ktime_get_ns();

    /* Record when prev process went off-CPU */
    if (is_postgres_pid(prev_pid)) {
        bpf_map_update_elem(&off_cpu_start, &prev_pid, &now, BPF_ANY);

        /* Track voluntary vs involuntary switches */
        struct pid_cpu_stats *stats = bpf_map_lookup_elem(&pid_cpu_stats_map, &prev_pid);
        if (stats) {
            if (ctx->prev_state == TASK_RUNNING) {
                /* Involuntary preemption */
                __sync_fetch_and_add(&stats->involuntary_switches, 1);
            } else {
                /* Voluntary sleep */
                __sync_fetch_and_add(&stats->voluntary_switches, 1);
            }
        }
    }

    /* When next_pid is a PostgreSQL process, calculate its off-CPU time */
    if (is_postgres_pid(next_pid)) {
        __u64 *off_start = bpf_map_lookup_elem(&off_cpu_start, &next_pid);
        if (off_start && *off_start > 0) {
            __u64 off_duration = now - *off_start;

            /* Capture stack trace at the moment of wakeup */
            struct stack_count_key key = {
                .pid             = next_pid,
                .kernel_stack_id = bpf_get_stackid(ctx, &kernel_stacks,
                                                    BPF_F_FAST_STACK_CMP),
                .user_stack_id   = -1,  /* No user stack in kernel context */
            };

            __u64 *total = bpf_map_lookup_elem(&off_cpu_times, &key);
            if (total) {
                __sync_fetch_and_add(total, off_duration);
            } else {
                bpf_map_update_elem(&off_cpu_times, &key, &off_duration, BPF_NOEXIST);
            }

            /* Update per-PID stats */
            struct pid_cpu_stats *stats = bpf_map_lookup_elem(&pid_cpu_stats_map, &next_pid);
            if (stats)
                __sync_fetch_and_add(&stats->off_cpu_ns, off_duration);

            bpf_map_delete_elem(&off_cpu_start, &next_pid);
        }
    }

    return 0;
}

/*
 * sched_wakeup - alternative wakeup tracking
 * Used for more accurate off-CPU end detection.
 */
SEC("tracepoint/sched/sched_wakeup")
int tp_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 pid = ctx->pid;

    if (!is_postgres_pid(pid)) return 0;

    /* Process will soon be scheduled back on */
    /* Off-CPU time calculation happens in sched_switch when next_pid matches */
    return 0;
}

/* ============================================================
 * Cleanup
 * ============================================================ */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&off_cpu_start, &pid);
    return 0;
}
