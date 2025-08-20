#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ps.h"
#include "Kcom.h"

#define __AC(X, Y) (X##Y)
#define _AC(X, Y) __AC(X, Y)
#define PAGE_MASK (~(PAGE_SIZE - 1))

#define __ALIGN_KERNEL_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a) __ALIGN_KERNEL_MASK(x, (__typeof__(x))(a)-1)
#define ALIGN(x, a) __ALIGN_KERNEL((x), (a))
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

char _license[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); // 2M
} output SEC(".maps");

#define _NSIG 64
#define _NSIG_BPW 64
#define _NSIG_WORDS (_NSIG / _NSIG_BPW)
#define SIG_IGN ((__sighandler_t)1)
#define SIG_DFL 0
#define TASK_RUNNING 0x00000000

static void collect_sigign_sigcatch(
	struct task_struct *p,
	sigset_t *sigign,
	sigset_t *sigcatch
)
{
	struct k_sigaction *k;
	int i;

	k = p->sighand->action;
	for (i = 1; i <= _NSIG; ++i, ++k)
	{
		if (k->sa.sa_handler == SIG_IGN)
		{
			sigign->sig[0] |= 1UL << (i - 1);
		}
		else if (k->sa.sa_handler != SIG_DFL)
		{
			sigign->sig[0] |= 1UL << (i - 1);
		}
	}
}

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	// fill output buffer with struct dcapture_task which is defined in ps.h
	struct task_struct *task = ctx->task;
	if (!task)
	{
		return 0;
	}

	// Create a new dcapture_task with reserve_with_flags
	struct dcapture_task *dtask;
	dtask = bpf_ringbuf_reserve(&output, sizeof(struct dcapture_task), 0);
	if (!dtask)
	{
		return 0;
	}

	// Fill in all available fields from task_struct
	dtask->pid = task->pid;
	bpf_probe_read_kernel_str(&dtask->comm, TASK_COMM_LEN, task->comm);
	dtask->state = task->__state;

	// Parent PID
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	dtask->ppid = BPF_CORE_READ(parent, pid);

	// Process group and session info
	dtask->pgid = BPF_CORE_READ(task, group_leader, pid);

	dtask->sid = BPF_CORE_READ(task, signal, pids[PIDTYPE_SID], numbers[0].nr);

	// TTY information
	struct tty_struct *tty = BPF_CORE_READ(task, signal, tty);
	dtask->tty_nr = 0;
	if (tty)
	{
		dtask->tty_nr = tty ? BPF_CORE_READ(tty, index) : 0;

		struct pid *pgrp = BPF_CORE_READ(tty, ctrl.pgrp);
		dtask->tty_pgrp = 0;
		if (pgrp)
		{
			dtask->tty_pgrp = BPF_CORE_READ(pgrp, numbers[0].nr);
		}
	}

	// Process flags
	dtask->flags = BPF_CORE_READ(task, flags);

	// Fault counters
	dtask->min_flt = BPF_CORE_READ(task, min_flt);
	dtask->maj_flt = BPF_CORE_READ(task, maj_flt);
	dtask->cmin_flt = BPF_CORE_READ(task, signal, cmin_flt);
	dtask->cmaj_flt = BPF_CORE_READ(task, signal, cmaj_flt);

	// CPU times
	dtask->utime = BPF_CORE_READ(task, utime);
	dtask->stime = BPF_CORE_READ(task, stime);
	dtask->cutime = BPF_CORE_READ(task, signal, cutime);
	dtask->cstime = BPF_CORE_READ(task, signal, cstime);

	// Priority and nice value
	dtask->priority = BPF_CORE_READ(task, prio);
	dtask->nice = BPF_CORE_READ(task, static_prio) - 120; // Convert to nice
	dtask->num_threads = BPF_CORE_READ(task, signal, nr_threads);

	// Start time
	dtask->start_time = BPF_CORE_READ(task, start_time);

	// Memory usage
	struct mm_struct *mm = BPF_CORE_READ(task, mm);

	dtask->vsize = 0;
	if (mm)
	{
		dtask->vsize = BPF_CORE_READ(mm, total_vm) * (PAGE_SIZE >> 10);
	}

	dtask->rss = 0;
	if (mm)
	{
		dtask->rss += BPF_CORE_READ(task, mm, rss_stat[MM_FILEPAGES].count) *
					  (PAGE_SIZE >> 10);
		dtask->rss += BPF_CORE_READ(task, mm, rss_stat[MM_ANONPAGES].count) *
					  (PAGE_SIZE >> 10);
		dtask->rss += BPF_CORE_READ(task, mm, rss_stat[MM_SHMEMPAGES].count) *
					  (PAGE_SIZE >> 10);
	}

	dtask->rsslim =
		BPF_CORE_READ(task, signal, rlim[5 /*RLIMIT_RSS*/].rlim_cur);

	// Memory locations
	dtask->start_code = 0;
	dtask->end_code = 0;
	dtask->start_stack = 0;
	if (mm)
	{
		dtask->start_code = BPF_CORE_READ(mm, start_code);
		dtask->end_code = BPF_CORE_READ(mm, end_code);
		dtask->start_stack = BPF_CORE_READ(mm, start_stack);
	}
	dtask->kstkesp = REG_SP(task);
	dtask->kstkeip = KSTK_EIP(task);

	// Signal handling
	sigset_t sigset = BPF_CORE_READ(task, pending.signal);
	dtask->signal = sigset.sig[0];
	sigset = BPF_CORE_READ(task, blocked);
	dtask->blocked = sigset.sig[0];
	sigset_t ignored = {0};
	sigset_t caught = {0};
	collect_sigign_sigcatch(task, &ignored, &caught);
	dtask->sigignore = ignored.sig[0];
	dtask->sigcatch = caught.sig[0];

	// Other info

	dtask->wchan = BPF_CORE_READ(task, __state) != TASK_RUNNING;
	dtask->exit_signal = BPF_CORE_READ(task, exit_signal);
	dtask->processor = CURRENT_CPU(task);
	dtask->rt_priority = BPF_CORE_READ(task, rt_priority);
	dtask->policy = BPF_CORE_READ(task, policy);

	// Block I/O
	dtask->delayacct_blkio_ticks = BPF_CORE_READ(task, delays, blkio_delay);

	// Guest time
	dtask->guest_time = BPF_CORE_READ(task, gtime);
	dtask->cguest_time = BPF_CORE_READ(task, signal, cgtime);

	// Memory regions
	dtask->start_data = BPF_CORE_READ(task, mm, start_data);
	dtask->end_data = BPF_CORE_READ(task, mm, end_data);
	dtask->start_brk = BPF_CORE_READ(task, mm, brk);
	dtask->arg_start = BPF_CORE_READ(task, mm, arg_start);
	dtask->arg_end = BPF_CORE_READ(task, mm, arg_end);
	dtask->env_start = BPF_CORE_READ(task, mm, env_start);
	dtask->env_end = BPF_CORE_READ(task, mm, env_end);
	dtask->exit_code = BPF_CORE_READ(task, exit_code);

	dtask->size = BPF_CORE_READ(task, mm, total_vm);

	dtask->resident =
		dtask->shared + BPF_CORE_READ(task, mm, rss_stat)[MM_ANONPAGES].count;

	dtask->shared = BPF_CORE_READ(task, mm, rss_stat)[MM_FILEPAGES].count +
					BPF_CORE_READ(task, mm, rss_stat)[MM_SHMEMPAGES].count;

	dtask->text = (PAGE_ALIGN(BPF_CORE_READ(task, mm, end_data)) -
				   (BPF_CORE_READ(task, mm, start_data) & PAGE_MASK)) >>
				  PAGE_SHIFT;

	dtask->data =
		BPF_CORE_READ(task, mm, data_vm) + BPF_CORE_READ(task, mm, stack_vm);

	bpf_ringbuf_submit(dtask, 0);
	return 0;
}
