/**
 * @file signal-filter.bpf.c
 * @brief 信号过滤器 eBPF 程序
 * 
 * 该文件实现了基于 eBPF 的系统信号监控和过滤功能，包括：
 * - 信号发送和接收的跟踪
 * - 基于规则的信号拦截
 * - 信号事件的实时记录和统计
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "signal-filter.h"

char _license[] SEC("license") = "GPL";

#define EPERM 1

/**
 * @brief 信号事件结构体
 * 用于在环形缓冲区中传递信号事件数据
 */
struct event_t
{
	u32 sender_pid;      ///< 发送者进程ID
	char sender_comm[16]; ///< 发送者进程名称
	u32 target_pid;      ///< 目标进程ID
	char target_comm[16]; ///< 目标进程名称
	u32 sig;             ///< 信号编号
	int result;          ///< 操作结果
	u64 generate_time;   ///< 信号生成时间
	u64 deliver_time;    ///< 信号传递时间
	u32 action;          ///< 执行的动作
	u64 timestamp;       ///< 时间戳
	char filter_flag;    ///< 过滤标志
};

#define MAP_MAX_ENTRY 10240

/**
 * @brief 信号开始跟踪映射
 * 用于跟踪信号的开始时间和状态
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct event_t);
	__uint(max_entries, MAP_MAX_ENTRY);
} start SEC(".maps");

/**
 * @brief 环形缓冲区
 * 用于向用户空间传递信号事件数据
 */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} ringbuf SEC(".maps");

/**
 * @brief 拦截模式映射
 * 存储信号拦截的模式配置
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} interception_mode SEC(".maps");

/**
 * @brief 过滤规则映射
 * 存储信号过滤的规则配置
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, 1);
} filter_rules SEC(".maps");

/**
 * @brief 创建跟踪事件
 * 创建信号跟踪事件并发送到环形缓冲区
 * @param sender_pid 发送者进程ID
 * @param target_pid 目标进程ID
 * @param sig 信号编号
 * @param generate_time 生成时间
 * @param deliver_time 传递时间
 * @param result 操作结果
 */
static inline void create_trace_event(
	u32 sender_pid,
	u32 target_pid,
	u32 sig,
	u64 generate_time,
	u64 deliver_time,
	int result
)
{
	struct event_t *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
	if (!evt)
	{
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

/**
 * @brief 创建信号拦截事件
 * 创建拦截事件并发送到环形缓冲区
 * @param target_pid 目标进程ID
 * @param sig 信号编号
 * @param action 拦截动作
 */
static inline void create_intercept_event(u32 target_pid, u32 sig, u32 action)
{
	struct event_t *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
	if (!evt)
	{
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

/**
 * @brief 获取拦截模式
 * @return 拦截模式值，默认为监控模式
 */
static inline u32 get_interception_mode()
{
	u32 key = 0;
	u32 *mode = bpf_map_lookup_elem(&interception_mode, &key);
	return mode ? *mode : MODE_MONITOR_ONLY;
}

/**
 * @brief 获取过滤规则
 * @return 过滤规则指针，可能为NULL
 */
static inline struct Rule *get_rule(void)
{
	struct Rule *rule;
	u32 key = 0;
	rule = bpf_map_lookup_elem(&filter_rules, &key);
	return rule;
}

/**
 * @brief 检查所有过滤规则
 * 根据配置的规则检查是否应该拦截信号
 * @param sender_pid 发送者进程ID
 * @param target_pid 目标进程ID
 * @param sig 信号编号
 * @param sender_uid 发送者用户ID
 * @return true表示应该拦截，false表示允许通过
 */
static inline bool
check_all_rules(u32 sender_pid, u32 target_pid, u32 sig, u32 sender_uid)
{
	struct Rule *rule = get_rule();
	if (!rule)
	{
		return false; // No rules, don't intercept
	}

	/// 检查是否设置了任何规则（非零值）
	bool has_rules = false;
	if (rule->sender_pid > 0 || rule->recv_pid > 0 || rule->sig > 0 ||
		rule->sender_uid > 0)
	{
		has_rules = true;
	}

	/// 如果没有设置规则，允许所有信号
	if (!has_rules)
	{
		return false;
	}

	/// 检查每个规则 - 如果任何一个不匹配，允许信号通过
	if (rule->sender_pid > 0 && rule->sender_pid != sender_pid)
	{
		return false;
	}

	if (rule->recv_pid > 0 && rule->recv_pid != target_pid)
	{
		return false;
	}

	if (rule->sig > 0 && rule->sig != sig)
	{
		return false;
	}

	if (rule->sender_uid > 0 && rule->sender_uid != sender_uid)
	{
		return false;
	}

	/// 所有规则都满足，返回true进行拦截
	return true;
}

/**
 * @brief 根据规则判断是否应该拦截信号
 * 检查信号是否符合拦截条件
 * @param sender_pid 发送者进程ID
 * @param target_pid 目标进程ID
 * @param sig 信号编号
 * @param sender_uid 发送者用户ID
 * @return true表示应该拦截，false表示不拦截
 */
static inline bool should_intercept_signal_by_rule(
	u32 sender_pid,
	u32 target_pid,
	u32 sig,
	u32 sender_uid
)
{
	u32 current_mode = get_interception_mode();
	if (current_mode == MODE_RULE_FILTER)
	{
		return check_all_rules(sender_pid, target_pid, sig, sender_uid);
	}
	return false;
}

// BPF programs
SEC("tracepoint/signal/signal_generate")
int on_signal_generate(struct trace_event_raw_signal_generate *ctx)
{
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
int on_signal_deliver(struct trace_event_raw_signal_deliver *ctx)
{
	u64 key = (u64)bpf_get_current_pid_tgid() >> 32;
	struct event_t *s = bpf_map_lookup_elem(&start, &key);
	if (!s)
	{
		return 0;
	}

	create_trace_event(
		s->sender_pid,
		key,
		s->sig,
		s->generate_time,
		bpf_ktime_get_ns(),
		ctx->errno
	);
	bpf_map_delete_elem(&start, &key);
	return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(
	task_kill,
	struct task_struct *p,
	struct kernel_siginfo *info,
	int sig,
	const struct cred *cred,
	int ret
)
{
	if (ret)
	{
		return ret;
	}

	u32 target_pid = p->pid;
	u32 sender_pid = bpf_get_current_pid_tgid() >> 32;
	u64 uid_gid = bpf_get_current_uid_gid();
	u32 sender_uid = uid_gid >> 32; // Get UID from the high 32 bits

	// Check rule filter mode
	if (should_intercept_signal_by_rule(
			sender_pid,
			target_pid,
			sig,
			sender_uid
		))
	{
		create_intercept_event(target_pid, sig, 1);
		return -EPERM;
	}

	create_intercept_event(target_pid, sig, 0);
	return 0;
}