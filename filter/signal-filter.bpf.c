#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "signal-filter.h"

char _license[] SEC("license") = "GPL";

#define EPERM 1

// Event structure for ring buffer
struct event_t {
    u32 sender_pid;
    char sender_comm[16];
    u32 target_pid;
    char target_comm[16];
    u32 sig;
    int  result;
    u64 generate_time;
    u64 deliver_time;
    u32 action;  
    u64 timestamp;  
    char filter_flag;
};

#define MAP_MAX_ENTRY 10240

// Maps for signal tracking and filtering
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct event_t);
    __uint(max_entries, MAP_MAX_ENTRY);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} interception_mode SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct Rule);
    __uint(max_entries, 1);
} filter_rules SEC(".maps");

// Helper functions
static inline void create_trace_event(u32 sender_pid, u32 target_pid, u32 sig, 
                                     u64 generate_time, u64 deliver_time, int result) {
    struct event_t *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
    if (!evt) {
        return;
    }
    
    evt->sender_pid = sender_pid;
    evt->target_pid = target_pid;
    evt->sig = sig;
    evt->generate_time = generate_time;
    evt->deliver_time = deliver_time;
    evt->result = result;
    evt->filter_flag = TRACESIGNAL;
    evt->action = 0;
    evt->timestamp = 0;
    
    bpf_ringbuf_submit(evt, 0);
}

static inline void create_intercept_event(u32 target_pid, u32 sig, u32 action) {
    struct event_t *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
    if (!evt) {
        return;
    }
    
    evt->sender_pid = 0;
    evt->sender_comm[0] = '\0';
    evt->target_pid = target_pid;
    bpf_get_current_comm(&evt->target_comm, sizeof(evt->target_comm));
    evt->sig = sig;
    evt->result = 0;
    evt->generate_time = 0;
    evt->deliver_time = 0;
    evt->timestamp = bpf_ktime_get_ns();
    evt->filter_flag = FILTERFLAG;
    evt->action = action;
    
    bpf_ringbuf_submit(evt, 0);
}

static inline u32 get_interception_mode() {
    u32 key = 0;
    u32 *mode = bpf_map_lookup_elem(&interception_mode, &key);
    return mode ? *mode : MODE_MONITOR_ONLY;
}

static inline struct Rule *get_rule(void) {
    struct Rule *rule;
    u32 key = 0;
    rule = bpf_map_lookup_elem(&filter_rules, &key);
    return rule;
}

// Rule checking logic
static inline bool check_all_rules(u32 sender_pid, u32 target_pid, u32 sig, u32 sender_uid) {
    struct Rule *rule = get_rule();
    if (!rule) {
        return false; // No rules, don't intercept
    }
    
    // Check if any rule is set (non-zero values)
    bool has_rules = false;
    if (rule->sender_pid > 0 || rule->recv_pid > 0 || rule->sig > 0 || 
        rule->sender_uid > 0) {
        has_rules = true;
    }
    
    // If no rules are set, allow all signals
    if (!has_rules) {
        return false;
    }
    
    // Check each rule - if any doesn't match, allow the signal
    if (rule->sender_pid > 0 && rule->sender_pid != sender_pid) {
        return false;
    }
    
    if (rule->recv_pid > 0 && rule->recv_pid != target_pid) {
        return false;
    }
    
    if (rule->sig > 0 && rule->sig != sig) {
        return false;
    }
    
    if (rule->sender_uid > 0 && rule->sender_uid != sender_uid) {
        return false;
    }
    
    // All rules satisfied, return true to intercept
    return true;
}

static inline bool should_intercept_signal_by_rule(u32 sender_pid, u32 target_pid, u32 sig, u32 sender_uid) {
    u32 current_mode = get_interception_mode();
    if (current_mode == MODE_RULE_FILTER) {
        return check_all_rules(sender_pid, target_pid, sig, sender_uid);
    }
    return false;
}

// BPF programs
SEC("tracepoint/signal/signal_generate")
int on_signal_generate(struct trace_event_raw_signal_generate *ctx) {
    u64 key = (u64)ctx->pid;
    struct event_t info = {};
    
    info.target_pid = key;
    info.sender_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.sender_comm, sizeof(info.sender_comm));
    info.sig = ctx->sig;
    info.filter_flag = 0;
    info.generate_time = bpf_ktime_get_ns();

    bpf_map_update_elem(&start, &key, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/signal/signal_deliver")
int on_signal_deliver(struct trace_event_raw_signal_deliver *ctx) {
    u64 key = (u64)bpf_get_current_pid_tgid() >> 32;  
    struct event_t *s = bpf_map_lookup_elem(&start, &key);
    if (!s) {
        return 0;
    }

    create_trace_event(s->sender_pid, key, s->sig, s->generate_time, bpf_ktime_get_ns(), ctx->errno);
    bpf_map_delete_elem(&start, &key);
    return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill,
             struct task_struct *p,
             struct kernel_siginfo *info,
             int sig,
             const struct cred *cred,
             int ret)
{
    if (ret) {
        return ret;
    }

    u32 target_pid = p->pid;
    u32 sender_pid = bpf_get_current_pid_tgid() >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 sender_uid = uid_gid >> 32; // Get UID from the high 32 bits
    
    // Check rule filter mode
    if (should_intercept_signal_by_rule(sender_pid, target_pid, sig, sender_uid)) {
        create_intercept_event(target_pid, sig, 1);
        return -EPERM;
    }
    
    create_intercept_event(target_pid, sig, 0);
    return 0;
}