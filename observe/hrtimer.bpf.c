/**
 * 通过使用
 * kprobe（内核探针）在hrtimer_nanosleep函数的入口和退出处放置钩子，实现对该系统调用的跟踪
 */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 定义许可证，以允许程序在内核中运行
char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile bool filter_cg = false;
const volatile bool targ_relative_time = false;
const volatile bool targ_unit_ms = false;
const volatile pid_t targ_tgid = 0;
const volatile int targ_time = 0;

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct nanosleep_args_t
{
	struct __kernel_timespec rqt;
	struct __kernel_timespec rmt;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct nanosleep_args_t);
} active_nanosleep_args_map SEC(".maps");

struct clock_nanosleep_args_t
{
	clockid_t which_clock;
	int flags;
	struct __kernel_timespec rqt;
	struct __kernel_timespec rmt;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct clock_nanosleep_args_t);
} active_clock_nanosleep_args_map SEC(".maps");

// 定义一个名为hrtimer_nanosleep的
// kprobe，当进入hrtimer_nanosleep函数时，它会被触发

SEC("kprobe/hrtimer_nanosleep")
int BPF_KPROBE(
	hrtimer_nanosleep,
	ktime_t rqtp,
	enum hrtimer_mode mode,
	clockid_t clockid
) // 捕获函数的参数
{
	// 获取当前进程的 PID 和 TGID
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(pid_tgid >> 32); // 获取 PID
	__u32 tgid = (__u32)(pid_tgid);		 // 获取 TGID

	// if (targ_tgid && targ_tgid != tgid)
	// 	return 0;

	// 打印参数到内核日志
	bpf_printk(
		"hrtimer_nanosleep called with: rqtp=%ld ns, mode=%d, clockid=%d, "
		"PID=%d, TGID=%d\n",
		rqtp,
		mode,
		clockid,
		pid,
		tgid
	);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int tracepoint__syscalls__sys_enter_nanosleep(
	struct trace_event_raw_sys_enter *ctx
)
{
	// 获取当前进程的 PID 和 TGID
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid); // 获取 TGID

	struct nanosleep_args_t nanosleep_args;

	// bpf_printk("sys_enter_clock_nanosleep pid=%d, targ_tgid:PID=%d,
	// targ_times_sec = %d, targ_times_msec = %d\n",pid ,targ_tgid,
	// targ_times_sec , targ_times_msec);

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
	{
		return 0;
	}

	if (targ_tgid && targ_tgid != tgid)
	{
		return 0;
	}

	bpf_probe_read_user(
		&nanosleep_args.rqt,
		sizeof(nanosleep_args.rqt),
		(struct __kernel_timespec *)ctx->args[0]
	);

	// bpf_printk("sys_enter_nanosleep called with:PID=%d tv_sec = %lld tv_nsec
	// = %lld\n", pid ,nanosleep_args.rqtp->tv_sec,
	// nanosleep_args.rqtp->tv_nsec);
	if (targ_relative_time)
	{
		if (targ_unit_ms)
		{
			// nanosleep_args.rqt.tv_sec = 0;
			nanosleep_args.rqt.tv_nsec += targ_time * 1000000;
		}
		else
		{
			nanosleep_args.rqt.tv_sec += targ_time;
		}
	}
	else
	{
		if (targ_unit_ms)
		{
			nanosleep_args.rqt.tv_sec = 0;
			nanosleep_args.rqt.tv_nsec = targ_time * 1000000;
		}
		else
		{
			nanosleep_args.rqt.tv_sec = targ_time;
			nanosleep_args.rqt.tv_nsec = 0;
		}
	}

	bpf_map_update_elem(
		&active_nanosleep_args_map,
		&tgid,
		&nanosleep_args,
		BPF_ANY
	);

	// bpf_printk("sys_enter_nanosleep called with:PID=%d tv_sec =%d tv_sec =
	// %d\n",
	//   tgid, nanosleep_args.rqt.tv_sec, nanosleep_args.rqt.tv_nsec);

	bpf_probe_write_user(
		(struct __kernel_timespec *)ctx->args[0],
		&nanosleep_args.rqt,
		sizeof(nanosleep_args.rqt)
	);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_nanosleep")
int tracepoint__syscalls__sys_enter_clock_nanosleep(
	struct trace_event_raw_sys_enter *ctx
)
{
	// 获取当前进程的 PID 和 TGID
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid); // 获取 TGID
	struct clock_nanosleep_args_t clock_nanosleep_args;

	// bpf_printk("sys_enter_clock_nanosleep pid=%d, targ_tgid:PID=%d,
	// targ_times_sec = %d, targ_times_msec = %d\n",pid ,targ_tgid,
	// targ_times_sec , targ_times_msec);

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
	{
		return 0;
	}
	if (targ_tgid && targ_tgid != tgid)
	{
		return 0;
	}

	bpf_probe_read_user(
		&clock_nanosleep_args.rqt,
		sizeof(clock_nanosleep_args.rqt),
		(struct __kernel_timespec *)ctx->args[2]
	);

	if (targ_relative_time)
	{
		if (targ_unit_ms)
		{
			// clock_nanosleep_args.rqt.tv_sec = 0;
			clock_nanosleep_args.rqt.tv_nsec += targ_time * 1000000;
		}
		else
		{
			clock_nanosleep_args.rqt.tv_sec += targ_time;
		}
	}
	else
	{
		if (targ_unit_ms)
		{
			clock_nanosleep_args.rqt.tv_sec = 0;
			clock_nanosleep_args.rqt.tv_nsec = targ_time * 1000000;
		}
		else
		{
			clock_nanosleep_args.rqt.tv_sec = targ_time;
			clock_nanosleep_args.rqt.tv_nsec = 0;
		}
	}

	bpf_map_update_elem(
		&active_nanosleep_args_map,
		&tgid,
		&clock_nanosleep_args,
		BPF_ANY
	);

	// bpf_printk("sys_enter_clock_nanosleep called with:PID=%d tv_sec = %ld
	// tv_nsec = %ld\n", tgid ,clock_nanosleep_args.rqt.tv_sec,
	// clock_nanosleep_args.rqt.tv_nsec);

	bpf_probe_write_user(
		(struct __kernel_timespec *)ctx->args[2],
		&clock_nanosleep_args.rqt,
		sizeof(clock_nanosleep_args.rqt)
	);

	return 0;
}