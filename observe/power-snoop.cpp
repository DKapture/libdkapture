// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 DKapture Project
//
// Based on dkapture framework power management observation tool.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <thread>

#include "power-snoop.skel.h"
#include "dkapture.h"
#include "power-snoop.h"

static struct ring_buffer *rb = NULL;
static struct power_snoop_bpf *obj = NULL;
static volatile bool exiting = false;

#ifdef BUILTIN
static std::thread *rb_thread = nullptr;
#endif

/* Environment structure for command line arguments */
struct env {
    __u32 pid;
    __u32 cpu;
    char comm[16];
    __u32 event_mask;
    __u32 min_freq;
    __u32 max_freq;
    __u64 min_idle_duration;
    __u64 max_idle_duration;
    bool verbose;
    bool timestamp;
    bool stats;
    bool summary;
    time_t interval;
    int times;
} env = {
    .pid = 0,
    .cpu = (__u32)-1,
    .comm = "",
    .event_mask = POWER_EVENT_MASK_ALL,
    .min_freq = 0,
    .max_freq = 0,
    .min_idle_duration = 0,
    .max_idle_duration = 0,
    .verbose = false,
    .timestamp = false,
    .stats = false,
    .summary = false,
    .interval = 99999999,
    .times = 99999999,
};

static struct power_stats global_stats = {};

const char argp_program_doc[] =
"power-snoop - Power management subsystem observation tool\n"
"\n"
"USAGE: power-snoop [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    power-snoop                           # Trace all power events\n"
"    power-snoop -p 1234                   # Trace specific process\n"
"    power-snoop -c 0                      # Trace specific CPU\n"
"    power-snoop -e 0x03                   # Trace CPU freq and idle events\n"
"    power-snoop --min-freq 1000000        # Trace frequencies >= 1GHz\n"
"    power-snoop --min-idle 1000000        # Trace idle durations >= 1ms\n"
"    power-snoop -v -t                     # Verbose output with timestamps\n"
"    power-snoop -s                        # Show statistics\n"
"\n"
"Event types (for -e bitmask):\n"
"    1   CPU_FREQ        CPU frequency changes\n"
"    2   CPU_IDLE        CPU idle state changes\n"
"    4   DEVICE_PM       Device power management\n"
"    8   PM_QOS          PM QoS requests\n"
"    16  CLOCK           Clock enable/disable\n"
"    32  RPM             Runtime PM\n";

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "Process ID to trace", 0 },
    { "cpu", 'c', "CPU", 0, "CPU ID to trace", 0 },
    { "comm", 'C', "COMM", 0, "Process name to trace", 0 },
    { "events", 'e', "MASK", 0, "Event types to trace (bitmask)", 0 },
    { "min-freq", ARG_MIN_FREQ, "FREQ", 0, "Minimum CPU frequency to trace", 0 },
    { "max-freq", ARG_MAX_FREQ, "FREQ", 0, "Maximum CPU frequency to trace", 0 },
    { "min-idle", ARG_MIN_IDLE, "NS", 0, "Minimum idle duration to trace", 0 },
    { "max-idle", ARG_MAX_IDLE, "NS", 0, "Maximum idle duration to trace", 0 },
    { "verbose", 'v', NULL, 0, "Verbose output", 0 },
    { "timestamp", 't', NULL, 0, "Show timestamps", 0 },
    { "stats", 's', NULL, 0, "Show statistics", 0 },
    { "summary", 'S', NULL, 0, "Show summary at exit", 0 },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;

    switch (key) {
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case 'p':
        errno = 0;
        env.pid = strtol(arg, NULL, 10);
        if (errno) {
            fprintf(stderr, "invalid PID: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'c':
        errno = 0;
        env.cpu = strtol(arg, NULL, 10);
        if (errno) {
            fprintf(stderr, "invalid CPU: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'C':
        strncpy(env.comm, arg, sizeof(env.comm) - 1);
        env.comm[sizeof(env.comm) - 1] = '\0';
        break;
    case 'e':
        errno = 0;
        env.event_mask = strtol(arg, NULL, 0);
        if (errno) {
            fprintf(stderr, "invalid event mask: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARG_MIN_FREQ:
        errno = 0;
        env.min_freq = strtol(arg, NULL, 10);
        if (errno) {
            fprintf(stderr, "invalid min frequency: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARG_MAX_FREQ:
        errno = 0;
        env.max_freq = strtol(arg, NULL, 10);
        if (errno) {
            fprintf(stderr, "invalid max frequency: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARG_MIN_IDLE:
        errno = 0;
        env.min_idle_duration = strtoll(arg, NULL, 10);
        if (errno) {
            fprintf(stderr, "invalid min idle duration: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARG_MAX_IDLE:
        errno = 0;
        env.max_idle_duration = strtoll(arg, NULL, 10);
        if (errno) {
            fprintf(stderr, "invalid max idle duration: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'v':
        env.verbose = true;
        break;
    case 't':
        env.timestamp = true;
        break;
    case 's':
        env.stats = true;
        break;
    case 'S':
        env.summary = true;
        break;
    case ARGP_KEY_ARG:
        errno = 0;
        if (pos_args == 0) {
            env.interval = strtol(arg, NULL, 10);
            if (errno) {
                fprintf(stderr, "invalid interval\n");
                argp_usage(state);
            }
        } else if (pos_args == 1) {
            env.times = strtol(arg, NULL, 10);
            if (errno) {
                fprintf(stderr, "invalid times\n");
                argp_usage(state);
            }
        } else {
            fprintf(stderr, "unrecognized positional argument: %s\n", arg);
            argp_usage(state);
        }
        pos_args++;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    exiting = true;
}

static const char *power_event_type_str(enum power_event_type type)
{
    switch (type) {
    case POWER_CPU_FREQ: return "CPU_FREQ";
    case POWER_CPU_IDLE: return "CPU_IDLE";
    case POWER_DEVICE_PM_START: return "DEVICE_PM_START";
    case POWER_DEVICE_PM_END: return "DEVICE_PM_END";
    case POWER_PM_QOS_ADD: return "PM_QOS_ADD";
    case POWER_PM_QOS_UPDATE: return "PM_QOS_UPDATE";
    case POWER_CLOCK_ENABLE: return "CLOCK_ENABLE";
    case POWER_CLOCK_DISABLE: return "CLOCK_DISABLE";
    case POWER_RPM_SUSPEND: return "RPM_SUSPEND";
    case POWER_RPM_RESUME: return "RPM_RESUME";
    default: return "UNKNOWN";
    }
}

#ifndef BUILTIN
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct power_event *e = (struct power_event *)data;
    char timestamp_str[64] = "";
    
    if (env.timestamp) {
        struct tm *tm;
        time_t t = time(NULL);
        tm = localtime(&t);
        strftime(timestamp_str, sizeof(timestamp_str), "%H:%M:%S ", tm);
    }
    
    /* Update global statistics */
    global_stats.total_events++;
    
    switch (e->header.event_type) {
    case POWER_CPU_FREQ:
        global_stats.cpu_freq_events++;
        if (env.verbose) {
            printf("%s[%s] CPU%d: %d -> %dHz (pid=%d comm=%s)\n",
                   timestamp_str, power_event_type_str((enum power_event_type)e->header.event_type),
                   e->data.cpu_freq.cpu_id,
                   e->data.cpu_freq.old_freq, e->data.cpu_freq.new_freq,
                   e->header.pid, e->header.comm);
        } else {
            printf("CPU%d frequency: %d -> %dHz\n",
                   e->data.cpu_freq.cpu_id,
                   e->data.cpu_freq.old_freq, e->data.cpu_freq.new_freq);
        }
        break;
        
    case POWER_CPU_IDLE:
        global_stats.cpu_idle_events++;
        if (env.verbose) {
            printf("%s[%s] CPU%d: state=%d (pid=%d comm=%s)\n",
                   timestamp_str, power_event_type_str((enum power_event_type)e->header.event_type),
                   e->data.cpu_idle.cpu_id, e->data.cpu_idle.state,
                   e->header.pid, e->header.comm);
        } else {
            printf("CPU%d idle state: %d\n",
                   e->data.cpu_idle.cpu_id, e->data.cpu_idle.state);
        }
        break;
        
    case POWER_DEVICE_PM_START:
    case POWER_DEVICE_PM_END:
        global_stats.device_pm_events++;
        if (env.verbose) {
            printf("%s[%s] Device: %s event=%d duration=%lluns ret=%d (pid=%d comm=%s)\n",
                   timestamp_str, power_event_type_str((enum power_event_type)e->header.event_type),
                   e->data.device_pm.device_name, e->data.device_pm.pm_event,
                   e->data.device_pm.duration_ns, e->data.device_pm.ret,
                   e->header.pid, e->header.comm);
        } else {
            printf("Device PM: %s event=%d\n",
                   e->data.device_pm.device_name, e->data.device_pm.pm_event);
        }
        break;
        
    case POWER_PM_QOS_ADD:
    case POWER_PM_QOS_UPDATE:
        global_stats.pm_qos_events++;
        if (env.verbose) {
            printf("%s[%s] PM QoS: type=%d value=%d requestor=%s (pid=%d comm=%s)\n",
                   timestamp_str, power_event_type_str((enum power_event_type)e->header.event_type),
                   e->data.pm_qos.qos_type, e->data.pm_qos.qos_value,
                   e->data.pm_qos.requestor, e->header.pid, e->header.comm);
        } else {
            printf("PM QoS: type=%d value=%d\n",
                   e->data.pm_qos.qos_type, e->data.pm_qos.qos_value);
        }
        break;
        
    case POWER_CLOCK_ENABLE:
    case POWER_CLOCK_DISABLE:
        global_stats.clock_events++;
        if (env.verbose) {
            printf("%s[%s] Clock: %s rate=%lluHz prepare=%d enable=%d (pid=%d comm=%s)\n",
                   timestamp_str, power_event_type_str((enum power_event_type)e->header.event_type),
                   e->data.clock.clock_name, e->data.clock.rate,
                   e->data.clock.prepare_count, e->data.clock.enable_count,
                   e->header.pid, e->header.comm);
        } else {
            printf("Clock %s: %s rate=%lluHz\n",
                   (e->header.event_type == POWER_CLOCK_ENABLE) ? "enable" : "disable",
                   e->data.clock.clock_name, e->data.clock.rate);
        }
        break;
        
    case POWER_RPM_SUSPEND:
    case POWER_RPM_RESUME:
        global_stats.rpm_events++;
        if (env.verbose) {
            printf("%s[%s] RPM: %s usage=%d depth=%d error=%d active=%lluns suspended=%lluns (pid=%d comm=%s)\n",
                   timestamp_str, power_event_type_str((enum power_event_type)e->header.event_type),
                   e->data.rpm.device_name, e->data.rpm.usage_count,
                   e->data.rpm.disable_depth, e->data.rpm.runtime_error,
                   e->data.rpm.active_time, e->data.rpm.suspended_time,
                   e->header.pid, e->header.comm);
        } else {
            printf("RPM %s: %s usage=%d\n",
                   (e->header.event_type == POWER_RPM_SUSPEND) ? "suspend" : "resume",
                   e->data.rpm.device_name, e->data.rpm.usage_count);
        }
        break;
        
    default:
        if (env.verbose) {
            printf("%s[%s] Unknown event type: %d (pid=%d comm=%s)\n",
                   timestamp_str, power_event_type_str((enum power_event_type)e->header.event_type),
                   e->header.event_type, e->header.pid, e->header.comm);
        }
        break;
    }
    
    return 0;
}
#endif

static void print_stats(void)
{
    printf("\nPower Management Statistics:\n");
    printf("============================\n");
    printf("Total events:     %llu\n", global_stats.total_events);
    printf("CPU freq events:  %llu\n", global_stats.cpu_freq_events);
    printf("CPU idle events:  %llu\n", global_stats.cpu_idle_events);
    printf("Device PM events: %llu\n", global_stats.device_pm_events);
    printf("PM QoS events:    %llu\n", global_stats.pm_qos_events);
    printf("Clock events:     %llu\n", global_stats.clock_events);
    printf("RPM events:       %llu\n", global_stats.rpm_events);
}

void ringbuffer_worker(void)
{
    int err;
    while (!exiting && --env.times != 0) {
        err = ring_buffer__poll(rb, 500);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        
        if (env.stats && env.interval != 99999999) {
            static time_t last_stats = 0;
            time_t now = time(NULL);
            if (now - last_stats >= env.interval) {
                print_stats();
                last_stats = now;
            }
        }
    }
}

#ifdef BUILTIN
int power_snoop_deinit(void)
{
    exiting = true;
    if (rb_thread) {
        rb_thread->join();
        delete rb_thread;
        rb_thread = nullptr;
    }
    if (rb) {
        ring_buffer__free(rb);
        rb = nullptr;
    }
    if (obj) {
        power_snoop_bpf__destroy(obj);
        obj = nullptr;
    }
    return 0;
}

int power_snoop_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx)
#else
int main(int argc, char **argv)
#endif
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    int err;

    exiting = false;
    signal(SIGINT, sig_handler);
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    obj = power_snoop_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    /* Initialize global data (filtering options) */
    obj->rodata->targ_verbose = env.verbose;
    obj->rodata->targ_timestamp = env.timestamp;

    err = power_snoop_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /* Note: bss check removed as it may not be available in all BPF objects */

    /* Set up filter */
    {
        struct power_filter filter = {
            .target_pid = env.pid,
            .target_cpu = env.cpu,
            .event_mask = env.event_mask,
            .min_freq = env.min_freq,
            .max_freq = env.max_freq,
            .min_idle_duration = env.min_idle_duration,
            .max_idle_duration = env.max_idle_duration,
        };
        strncpy(filter.target_comm, env.comm, sizeof(filter.target_comm) - 1);
        
        __u32 filter_key = 0;
        err = bpf_map_update_elem(bpf_map__fd(obj->maps.filter_map), &filter_key, &filter, BPF_ANY);
        if (err) {
            fprintf(stderr, "failed to set filter: %d\n", err);
            goto cleanup;
        }
    }

    err = power_snoop_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

#ifdef BUILTIN
    rb = ring_buffer__new(bpf_map__fd(obj->maps.power_events), (ring_buffer_sample_fn)cb, ctx, NULL);
#else
    rb = ring_buffer__new(bpf_map__fd(obj->maps.power_events), handle_event, NULL, NULL);
#endif
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

#ifdef BUILTIN
    rb_thread = new std::thread(ringbuffer_worker);
    return 0;
#endif

    printf("Tracing power management events... Hit Ctrl-C to end.\n");
    ringbuffer_worker();

    if (env.summary) {
        print_stats();
    }

cleanup:
    if (rb)
        ring_buffer__free(rb);
    power_snoop_bpf__destroy(obj);

    return err != 0;
} 