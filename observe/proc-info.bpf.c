#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/sched/prio.h>

#include "Kcom.h"
#include "Kstr-utils.h"
#include "dkapture.h"

#define BUF_SZ (32 * 1024 * 1024) // 32 MB
#define MAJOR(dev) ((dev) >> 8)
#define MINOR(dev) ((dev) & 0xff)
#define MKDEV(ma, mi) ((ma) << 8 | (mi))
#define RLIMIT_AS 6		 /* address space limit */
#define RLIMIT_RSS 7	 /* max resident set size */
#define RLIMIT_NPROC 8	 /* max number of processes */
#define RLIMIT_MEMLOCK 9 /* max locked-in-memory address space */

/* Used in tsk->__state: */
#define TASK_RUNNING 0x00000000
#define TASK_INTERRUPTIBLE 0x00000001
#define TASK_UNINTERRUPTIBLE 0x00000002
#define __TASK_STOPPED 0x00000004
#define __TASK_TRACED 0x00000008
/* Used in tsk->exit_state: */
#define EXIT_DEAD 0x00000010
#define EXIT_ZOMBIE 0x00000020
#define EXIT_TRACE (EXIT_ZOMBIE | EXIT_DEAD)
/* Used in tsk->__state again: */
#define TASK_PARKED 0x00000040
#define TASK_DEAD 0x00000080
#define TASK_WAKEKILL 0x00000100
#define TASK_WAKING 0x00000200
#define TASK_NOLOAD 0x00000400
#define TASK_NEW 0x00000800
#define TASK_RTLOCK_WAIT 0x00001000
#define TASK_FREEZABLE 0x00002000
#define __TASK_FREEZABLE_UNSAFE (0x00004000 * IS_ENABLED(CONFIG_LOCKDEP))
#define TASK_FROZEN 0x00008000
#define TASK_STATE_MAX 0x00010000
#define TASK_IDLE (TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

#define TASK_ANY (TASK_STATE_MAX - 1)

#define TASK_REPORT                                                            \
	(TASK_RUNNING | TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE |                \
	 __TASK_STOPPED | __TASK_TRACED | EXIT_DEAD | EXIT_ZOMBIE | TASK_PARKED)
#define TASK_REPORT_IDLE (TASK_REPORT + 1)

#define PF_INET 2
#define TRAFFIC_IN -1
#define TRAFFIC_OUT 1

#define thread_leader_only(task)                                               \
	do                                                                         \
	{                                                                          \
		if (task->pid != task->tgid)                                           \
			return 0;                                                          \
	} while (0)

#define PF_KTHREAD 0x00200000
#define skip_kthread(task)                                                     \
	do                                                                         \
	{                                                                          \
		if (task->flags & PF_KTHREAD)                                          \
			return 0;                                                          \
	} while (0)

typedef struct
{
	pid_t pid;
	pid_t tgid;
	u64 start_time;
} net_key_t;

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, net_key_t);
	__type(value, struct ProcPidTraffic);
	__uint(max_entries, 50000); // 最多记录 50000 个线程
} traffic_stat_map SEC(".maps");

static char LICENSE[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BUF_SZ); // 1 MB
} dk_shared_mem SEC(".maps");

extern bool CONFIG_VIRT_CPU_ACCOUNTING_NATIVE __kconfig __weak;

static inline unsigned int task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->__state | tsk->exit_state) & TASK_REPORT;

	if ((tsk->__state & TASK_IDLE) == TASK_IDLE)
	{
		state = TASK_REPORT_IDLE;
	}

	/*
	 * We're lying here, but rather than expose a completely new task state
	 * to userspace, we can make this appear as if the task has gone through
	 * a regular rt_mutex_lock() call.
	 * Report frozen tasks as uninterruptible.
	 */
	if ((tsk->__state & TASK_RTLOCK_WAIT) || (tsk->exit_state & TASK_FROZEN))
	{
		state = TASK_UNINTERRUPTIBLE;
	}

	return state;
}

static inline s64 percpu_counter_read_positive(struct percpu_counter *fbc)
{
	/* Prevent reloads of fbc->count */
	s64 ret = fbc->count;

	if (ret >= 0)
	{
		return ret;
	}
	return 0;
}
static inline unsigned long get_mm_counter(struct mm_struct *mm, int member)
{
	return percpu_counter_read_positive(&mm->rss_stat[member]);
}

static inline unsigned long get_mm_rss(struct mm_struct *mm)
{
	return get_mm_counter(mm, MM_FILEPAGES) + get_mm_counter(mm, MM_ANONPAGES) +
		   get_mm_counter(mm, MM_SHMEMPAGES);
}

static __always_inline u32 new_encode_dev(dev_t dev)
{
	unsigned major = MAJOR(dev);
	unsigned minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static dev_t tty_devnum(struct tty_struct *tty)
{
	return MKDEV(tty->driver->major, tty->driver->minor_start) + tty->index;
}

static inline int task_nice(const struct task_struct *p)
{
	return PRIO_TO_NICE((p)->static_prio);
}

static inline void sigaddset(sigset_t *set, int _sig)
{
	unsigned int bit = (_sig - 1) ^ 31;
	set->sig[0] |= (1U << bit);
}

#define _NSIG 64
#define SIG_DFL ((__sighandler_t)0) /* default signal handling */
#define SIG_IGN ((__sighandler_t)1) /* ignore signal */
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
			sigaddset(sigign, i);
		}
		else if (k->sa.sa_handler != SIG_DFL)
		{
			sigaddset(sigcatch, i);
		}
	}
}

static inline __u64 delayacct_blkio_ticks(struct task_struct *tsk)
{
	if (CONFIG_TASK_DELAY_ACCT && tsk->delays)
	{
		return tsk->delays->blkio_delay;
	}
	return 0;
}

static void fill_hdr(
	struct DataHdr *hdr,
	const struct task_struct *task,
	size_t dsz,
	enum DataType dt
)
{
	hdr->dsz = dsz;
	hdr->type = dt;
	hdr->pid = task->pid;
	hdr->tgid = task->tgid;
	legacy_strncpy(hdr->comm, task->comm, sizeof(task->comm));
}

static int dump_proc_cmdline(struct task_struct *task)
{
	/**
	 * TODO:
	 */
	return 0;
}

static int dump_proc_schedstat(struct task_struct *task)
{
	struct DataHdr *hdr;
	struct ProcPidSchedstat *stat;
	size_t dsz;
	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidSchedstat);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure");
		return 1;
	}
	fill_hdr(hdr, task, dsz, PROC_PID_SCHEDSTAT);
	stat = (struct ProcPidSchedstat *)hdr->data;
	stat->cpu_time = task->se.sum_exec_runtime;
	stat->rq_wait_time = task->sched_info.run_delay;
	stat->timeslices = task->sched_info.pcount;
	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

static void cputime_adjust(
	struct task_cputime *curr,
	struct prev_cputime *prev,
	u64 *ut,
	u64 *st
)
{
	if (CONFIG_VIRT_CPU_ACCOUNTING_NATIVE)
	{
		*ut = curr->utime;
		*st = curr->stime;
		return;
	}
	u64 rtime, stime, utime;

	rtime = curr->sum_exec_runtime;
	if (prev->stime + prev->utime >= rtime)
	{
		stime = prev->stime;
		utime = prev->utime;
		goto out;
	}

	stime = curr->stime;
	utime = curr->utime;

	if (stime == 0)
	{
		utime = rtime;
		goto update;
	}

	if (utime == 0)
	{
		stime = rtime;
		goto update;
	}

	stime = stime * rtime / (stime + utime);
	if (stime > rtime)
	{
		stime = rtime;
	}

update:
	if (stime < prev->stime)
	{
		stime = prev->stime;
	}
	utime = rtime - stime;
	if (utime < prev->utime)
	{
		utime = prev->utime;
		stime = rtime - utime;
	}

out:
	*ut = utime;
	*st = stime;
}

#define CONTEXT_TRACKING_KEY "context_tracking_key"
static struct static_key_false *context_tracking_key = NULL;

static __always_inline bool context_tracking_enabled(void)
{
	if (CONFIG_CONTEXT_TRACKING_USER)
	{
		if (!context_tracking_key)
		{
			return false;
		}
		return !!BPF_CORE_READ(context_tracking_key, key.enabled.counter);
	}
	else
	{
		return false;
	}
}

static inline bool vtime_accounting_enabled(void)
{
	return context_tracking_enabled();
}
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
static u64 vtime_delta(struct vtime *vtime)
{
	unsigned long long clock;

	clock = bpf_ktime_get_boot_ns();
	if (clock < vtime->starttime)
	{
		return 0;
	}

	return clock - vtime->starttime;
}
/*
 * Fetch cputime raw values from fields of task_struct and
 * add up the pending nohz execution time since the last
 * cputime snapshot.
 */
static bool task_cputime(struct task_struct *t, u64 *utime, u64 *stime)
{
	struct vtime *vtime = &t->vtime;
	u64 delta;

	if (!vtime_accounting_enabled())
	{
		*utime = t->utime;
		*stime = t->stime;
		return false;
	}

	*utime = t->utime;
	*stime = t->stime;

	/* Task is sleeping or idle, nothing to add */
	if (vtime->state < VTIME_SYS)
	{
		return false;
	}

	delta = vtime_delta(vtime);

	/*
	 * Task runs either in user (including guest) or kernel space,
	 * add pending nohz time to the right place.
	 */
	if (vtime->state == VTIME_SYS)
	{
		*stime += vtime->stime + delta;
	}
	else
	{
		*utime += vtime->utime + delta;
	}

	return true;
}
#else
static inline bool task_cputime(struct task_struct *t, u64 *utime, u64 *stime)
{
	*utime = t->utime;
	*stime = t->stime;
	return false;
}

static inline u64 task_gtime(struct task_struct *t)
{
	return t->gtime;
}
#endif

static void task_cputime_adjusted(struct task_struct *p, u64 *ut, u64 *st)
{
	struct task_cputime cputime = {
		.sum_exec_runtime = p->se.sum_exec_runtime,
	};

	if (task_cputime(p, &cputime.utime, &cputime.stime))
	{
		bpf_warn("time code not implemented");
	}

	cputime_adjust(&cputime, &p->prev_cputime, ut, st);
}

static int dump_proc_stat(struct task_struct *task)
{
	struct DataHdr *hdr;
	struct ProcPidStat *stat;
	size_t dsz;
	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidStat);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure");
		return 1;
	}
	fill_hdr(hdr, task, dsz, PROC_PID_STAT);
	stat = (struct ProcPidStat *)hdr->data;
	DEBUG(0, "TYPE: %d DSZ: %lu", hdr->type, hdr->dsz);
	struct tty_struct *tty;
	struct signal_struct *sig;
	struct mm_struct *mm;
	sigset_t sigign = {};
	sigset_t sigcatch = {};
	sig = task->signal;
	tty = sig->tty;
	mm = task->mm;
	collect_sigign_sigcatch(task, &sigign, &sigcatch);
	stat->state = task_state(task);
	stat->ppid = task->real_parent->pid;
	stat->pgid = task->group_leader->pid;
	stat->sid = sig->pids[PIDTYPE_SID]->numbers[0].nr;
	stat->tty_nr = tty ? new_encode_dev(tty_devnum(tty)) : 0;
	stat->tty_pgrp = tty && tty->ctrl.pgrp ? tty->ctrl.pgrp->numbers[0].nr : 0;
	stat->flags = task->flags;
	stat->cmin_flt = task->min_flt;
	stat->cmaj_flt = task->maj_flt;
	stat->min_flt = task->min_flt;
	stat->maj_flt = task->maj_flt;
	u64 stime, utime;
	task_cputime_adjusted(task, &utime, &stime);
	stat->utime = utime;
	stat->stime = stime;
	stat->cutime = sig->cutime;
	stat->cstime = sig->cstime;
	stat->priority = task->prio;
	stat->nice = task_nice(task);
	stat->num_threads = sig->nr_threads;
	stat->start_time = task->start_time;
	stat->vsize = mm ? mm->total_vm << PAGE_SHIFT : 0;
	stat->rss = mm ? get_mm_rss(mm) << PAGE_SHIFT : 0;
	stat->rsslim = sig->rlim[RLIMIT_RSS].rlim_cur;
	stat->start_code = mm ? mm->start_code : 0;
	stat->end_code = mm ? mm->end_code : 0;
	stat->start_stack = mm ? mm->start_stack : 0;
	stat->kstkesp = REG_SP(task);
	stat->kstkeip = KSTK_EIP(task);
	stat->signal = task->pending.signal.sig[0] & 0x7fffffffUL;
	stat->blocked = task->blocked.sig[0] & 0x7fffffffUL;
	stat->sigignore = sigign.sig[0] & 0x7fffffffUL;
	stat->sigcatch = sigcatch.sig[0] & 0x7fffffffUL;
	stat->wchan = !(task->__state == TASK_RUNNING);
	stat->exit_signal = task->exit_signal;
	stat->processor = CURRENT_CPU(task);
	stat->rt_priority = task->rt_priority;
	stat->policy = task->policy;
	stat->delayacct_blkio_ticks = delayacct_blkio_ticks(task);
	stat->guest_time = task->gtime;
	stat->cguest_time = sig->cgtime;
	stat->start_data = mm ? mm->start_data : 0;
	stat->end_data = mm ? mm->end_data : 0;
	stat->start_brk = mm ? mm->brk : 0;
	stat->arg_start = mm ? mm->arg_start : 0;
	stat->arg_end = mm ? mm->arg_end : 0;
	stat->env_start = mm ? mm->env_start : 0;
	stat->env_end = mm ? mm->env_end : 0;
	stat->exit_code = task->exit_code;

	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

static int dump_proc_io(struct task_struct *task)
{
	skip_kthread(task);
	struct DataHdr *hdr;
	struct ProcPidIo *io;
	size_t dsz;
	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidIo);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure");
		return 1;
	}
	fill_hdr(hdr, task, dsz, PROC_PID_IO);
	io = (struct ProcPidIo *)hdr->data;
	DEBUG(0, "TYPE: %d DSZ: %lu", hdr->type, hdr->dsz);
	struct task_io_accounting *acct = &task->ioac;
#define ASSIGN_IO_FIELD(field) io->field = acct->field
	ASSIGN_IO_FIELD(rchar);
	ASSIGN_IO_FIELD(wchar);
	ASSIGN_IO_FIELD(syscr);
	ASSIGN_IO_FIELD(syscw);
	ASSIGN_IO_FIELD(read_bytes);
	ASSIGN_IO_FIELD(write_bytes);
	ASSIGN_IO_FIELD(cancelled_write_bytes);
	if (task->pid == 1)
	{
		DEBUG(
			0,
			"PID: %d Comm: %s Rchar: %lu Wchar: %lu",
			hdr->pid,
			hdr->comm,
			io->rchar,
			io->wchar
		);
		DEBUG(0, "Wchar: %llu", task->signal->ioac.wchar);
	}
	if ((task->flags & PF_KTHREAD) && (io->rchar + io->wchar))
	{
		DEBUG(0, "kthread rchar: %lu wchar: %lu", io->rchar, io->wchar);
	}
	bpf_ringbuf_submit(hdr, 0);

	return 0;
}

static int dump_proc_traffic(struct task_struct *task)
{
	skip_kthread(task);
	size_t dsz;
	struct DataHdr *hdr;
	struct ProcPidTraffic *traffic;
	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidTraffic);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure");
		return 1;
	}
	fill_hdr(hdr, task, dsz, PROC_PID_traffic);
	traffic = (struct ProcPidTraffic *)hdr->data;

	net_key_t key = {
		.pid = task->pid,
		.tgid = task->tgid,
		.start_time = task->start_time,
	};
	struct ProcPidTraffic *traff;
	traffic->rbytes = 0;
	traffic->wbytes = 0;
	traff = bpf_map_lookup_elem(&traffic_stat_map, &key);
	if (traff)
	{
		*traffic = *traff;
	}

	DEBUG(0, "TYPE: %d DSZ: %lu", hdr->type, hdr->dsz);
	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

static int dump_proc_statm(struct task_struct *task)
{
	skip_kthread(task);
	thread_leader_only(task);
	size_t dsz;
	struct DataHdr *hdr;
	struct ProcPidStatm *statm;
	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidStatm);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure");
		return 1;
	}
	fill_hdr(hdr, task, dsz, PROC_PID_STATM);
	statm = (struct ProcPidStatm *)hdr->data;
	__builtin_memset(statm, 0, sizeof(struct ProcPidStatm));
	if (task->mm)
	{
		DEBUG(0, "statm size: %d", task->mm->total_vm);
		statm->size = task->mm->total_vm;
		statm->shared = task->mm->rss_stat[MM_FILEPAGES].count +
						task->mm->rss_stat[MM_SHMEMPAGES].count;
		statm->resident =
			statm->shared + task->mm->rss_stat[MM_ANONPAGES].count;
		statm->text = task->mm->end_data - task->mm->start_data;
		statm->text = (statm->text >> PAGE_SHIFT) +
					  !!(statm->text & ((1 << PAGE_SHIFT) - 1));
		statm->data = task->mm->data_vm + task->mm->stack_vm;
	}
	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

static int dump_proc_status(struct task_struct *task)
{
	skip_kthread(task);
	thread_leader_only(task);
	size_t dsz;
	struct DataHdr *hdr;
	struct ProcPidStatus *status;
	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidStatus);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure");
		return 1;
	}
	fill_hdr(hdr, task, dsz, PROC_PID_STATUS);
	status = (struct ProcPidStatus *)hdr->data;

	const struct cred *cred;
	cred = task->real_cred;
	status->state = task_state(task);
	status->tracer_pid = task->ptrace ? task->parent->pid : 0;
	status->umask = task->fs ? task->fs->umask : -1;
	status->uid[0] = cred->uid.val;
	status->uid[1] = cred->euid.val;
	status->uid[2] = cred->suid.val;
	status->uid[3] = cred->fsuid.val;
	status->gid[0] = cred->gid.val;
	status->gid[1] = cred->egid.val;
	status->gid[2] = cred->sgid.val;
	status->gid[3] = cred->fsgid.val;
	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

static int dump_proc_ns(struct task_struct *task)
{
	skip_kthread(task);
	thread_leader_only(task);

	size_t dsz;
	struct DataHdr *hdr;
	struct ProcPidNs *ns_info;

	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidNs);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure for ns");
		return 1;
	}

	fill_hdr(hdr, task, dsz, PROC_PID_NS);
	ns_info = (struct ProcPidNs *)hdr->data;
	__builtin_memset(ns_info, 0, sizeof(struct ProcPidNs));

	struct user_namespace *user_ns = task->cred->user_ns;
	if (user_ns)
	{
		ns_info->user = BPF_CORE_READ(user_ns, ns.inum);
	}

	if (bpf_core_field_exists(task->thread_pid))
	{
		struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
		if (thread_pid)
		{
			unsigned int level;
			if (bpf_core_field_exists(thread_pid->level))
			{
				level = BPF_CORE_READ(thread_pid, level);
				if (level >= 0)
				{
					struct upid *upid =
						(struct upid *)&thread_pid->numbers[level];
					if (bpf_core_field_exists(upid->ns))
					{
						struct pid_namespace *ns = BPF_CORE_READ(upid, ns);
						if (ns)
						{
							ns_info->pid = BPF_CORE_READ(ns, ns.inum);
						}
					}
				}
			}
		}
	}

	struct nsproxy *nsproxy = task->nsproxy;
	if (nsproxy)
	{
		struct uts_namespace *uts_ns = BPF_CORE_READ(nsproxy, uts_ns);
		if (uts_ns)
		{
			ns_info->uts = BPF_CORE_READ(uts_ns, ns.inum);
		}

		struct ipc_namespace *ipc_ns = BPF_CORE_READ(nsproxy, ipc_ns);
		if (ipc_ns)
		{
			ns_info->ipc = BPF_CORE_READ(ipc_ns, ns.inum);
		}

		struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
		if (mnt_ns)
		{
			ns_info->mnt = BPF_CORE_READ(mnt_ns, ns.inum);
		}

		struct pid_namespace *pid_ns_for_children =
			BPF_CORE_READ(nsproxy, pid_ns_for_children);
		if (pid_ns_for_children)
		{
			ns_info->pid_for_children =
				BPF_CORE_READ(pid_ns_for_children, ns.inum);
		}

		struct net *net_ns = BPF_CORE_READ(nsproxy, net_ns);
		if (net_ns)
		{
			ns_info->net = BPF_CORE_READ(net_ns, ns.inum);
		}

		struct time_namespace *time_ns = BPF_CORE_READ(nsproxy, time_ns);
		if (time_ns)
		{
			ns_info->time = BPF_CORE_READ(time_ns, ns.inum);
		}

		struct time_namespace *time_ns_for_children =
			BPF_CORE_READ(nsproxy, time_ns_for_children);
		if (time_ns_for_children)
		{
			ns_info->time_for_children =
				BPF_CORE_READ(time_ns_for_children, ns.inum);
		}

		struct cgroup_namespace *cgroup_ns = BPF_CORE_READ(nsproxy, cgroup_ns);
		if (cgroup_ns)
		{
			ns_info->cgroup = BPF_CORE_READ(cgroup_ns, ns.inum);
		}
	}

	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

static int dump_proc_loginuid(struct task_struct *task)
{
	skip_kthread(task);
	thread_leader_only(task);

	size_t dsz;
	struct DataHdr *hdr;
	struct ProcPidLoginuid *loginuid;

	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidLoginuid);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure for loginuid");
		return 1;
	}

	fill_hdr(hdr, task, dsz, PROC_PID_LOGINUID);
	loginuid = (struct ProcPidLoginuid *)hdr->data;
	__builtin_memset(loginuid, 0, sizeof(struct ProcPidLoginuid));

	loginuid->loginuid.val = BPF_CORE_READ(task, loginuid.val);

	bpf_ringbuf_submit(hdr, 0);
	return 0;
}

static int put_prologue(void)
{
	return 0;
}

static int put_epilogue(void)
{
	return 0;
}

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct task_struct *task;
	task = ctx->task;
	if (!task)
	{
		DEBUG(0, "-------- epilogue -----------");
		return put_epilogue();
	}
	if (ctx->meta->seq_num == 0)
	{
		DEBUG(0, "-------- prologue -----------");
		if (put_prologue())
		{
			return 1;
		}
	}
	if (dump_proc_stat(task))
	{
		return 1;
	}
	if (dump_proc_io(task))
	{
		return 1;
	}
	if (dump_proc_traffic(task))
	{
		return 1;
	}
	if (dump_proc_statm(task))
	{
		return 1;
	}
	if (dump_proc_cmdline(task))
	{
		return 1;
	}
	if (dump_proc_schedstat(task))
	{
		return 1;
	}
	if (dump_proc_status(task))
	{
		return 1;
	}
	if (dump_proc_ns(task))
	{
		return 1;
	}
	if (dump_proc_loginuid(task))
	{
		return 1;
	}
	if (dump_proc_loginuid(task))
	{
		return 1;
	}
	DEBUG(0, "dump_task: %d %s", task->pid, task->comm);

	return 0;
}

SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx)
{
	struct task_struct *task;
	struct file *file;

	task = ctx->task;
	file = ctx->file;

	if (!task || !file)
	{
		return 0;
	}

	/**
	 * 仅用于验证 bpf_iter__task_file 是以进程为单位进行迭代的
	 */
	if (0 && task->pid != task->tgid)
	{
		/**
		 * logically never get here
		 */
		bpf_info("sub thread passed: tid(%d) tgid(%d)", task->pid, task->tgid);
		return 0;
	}

	skip_kthread(task);
	size_t dsz;
	struct DataHdr *hdr;
	struct ProcPidFd *fd;
	dsz = sizeof(struct DataHdr) + sizeof(struct ProcPidFd);
	hdr = (struct DataHdr *)bpf_ringbuf_reserve(&dk_shared_mem, dsz, 0);
	if (!hdr)
	{
		bpf_err("ringbuf allocation failure");
		return 1;
	}
	fill_hdr(hdr, task, dsz, PROC_PID_FD);
	fd = (typeof(fd))hdr->data;
	struct inode *ino;
	ino = file->f_inode;
	fd->i_mode = ino->i_mode;
	fd->fd = ctx->fd;
	fd->inode = ino->i_ino;
	fd->dev = ino->i_sb->s_dev;

	// 打印 fd 的所有字段
	DEBUG(
		0,
		"task: %s pid: %d\n"
		"\ti_mode: %d\n"
		"\tfd: %d\n"
		"\tinode: %lu\n"
		"\tdev: %u:%u",
		hdr->comm,
		hdr->pid,
		fd->i_mode,
		fd->fd,
		fd->inode,
		MAJOR(fd->dev),
		MINOR(fd->dev)
	);
	bpf_ringbuf_submit(hdr, 0);

	return 0;
}

/**
 * per thread net traffic
 */

static int traffic_stat(int ret, int dir)
{
	u32 bytes = ret;
	if (ret < 0)
	{
		return 0;
	}
	u64 tgid_pid = bpf_get_current_pid_tgid();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	net_key_t key = {
		.pid = tgid_pid,
		.tgid = tgid_pid >> 32,
	};
	bpf_read_kmem_ret(&key.start_time, &task->start_time, return 0);
	struct ProcPidTraffic zero = {};
	struct ProcPidTraffic *traffic;

	bpf_map_update_elem(&traffic_stat_map, &key, &zero, BPF_NOEXIST);
	traffic = bpf_map_lookup_elem(&traffic_stat_map, &key);
	if (!traffic)
	{
		bpf_err("bpf_map_lookup_elem failed");
		return 0;
	}
	if (TRAFFIC_IN == dir)
	{
		traffic->rbytes += bytes;
	}
	else
	{
		traffic->wbytes += bytes;
	}
	return 0;
}

SEC("kretprobe/sock_sendmsg")
int BPF_PROG(sock_sendmsg, int ret)
{
	return traffic_stat(ret, TRAFFIC_OUT);
}

SEC("kretprobe/sock_write_iter")
int BPF_PROG(sock_write_iter, int ret)
{
	return traffic_stat(ret, TRAFFIC_OUT);
}

SEC("kretprobe/__sys_sendto")
int BPF_PROG(__sys_sendto_exit, int ret)
{
	return traffic_stat(ret, TRAFFIC_OUT);
}
SEC("kretprobe/____sys_sendmsg")
int BPF_PROG(____sys_sendmsg, int ret)
{
	return traffic_stat(ret, TRAFFIC_OUT);
}

SEC("kretprobe/sock_recvmsg")
int BPF_PROG(sock_recvmsg, int ret)
{
	return traffic_stat(ret, TRAFFIC_IN);
}

// 以下fexit与上面kreprobe类似，留作需要参数时备用

SEC("?fexit/sock_sendmsg")
int BPF_PROG(fr_sock_sendmsg, struct socket *sock, struct msghdr *msg, int ret)
{
	return traffic_stat(ret, TRAFFIC_OUT);
}

SEC("?fexit/sock_write_iter")
int BPF_PROG(
	fr_sock_write_iter,
	struct kiocb *iocb,
	struct iov_iter *from,
	int ret
)
{
	return traffic_stat(ret, TRAFFIC_OUT);
}

SEC("?fexit/__sys_sendto")
int BPF_PROG(
	fr___sys_sendto_exit,
	int fd,
	void __user *buff,
	size_t len,
	unsigned int flags,
	struct sockaddr __user *addr,
	int addr_len,
	int ret
)
{
	return traffic_stat(ret, TRAFFIC_OUT);
}
SEC("?fexit/____sys_sendmsg")
int BPF_PROG(
	fr_____sys_sendmsg,
	struct socket *sock,
	struct msghdr *msg_sys,
	unsigned int flags,
	struct used_address *used_address,
	unsigned int allowed_msghdr_flags,
	int ret
)
{
	return traffic_stat(ret, TRAFFIC_OUT);
}

SEC("?fexit/sock_recvmsg")
int BPF_PROG(
	fr_sock_recvmsg,
	struct socket *sock,
	struct msghdr *msg,
	int flags,
	int ret
)
{
	return traffic_stat(ret, TRAFFIC_IN);
}

SEC("syscall")
int proc_info_init(void *ctx)
{
	if (!context_tracking_key)
	{
		long ret;
		ret = bpf_kallsyms_lookup_name(
			CONTEXT_TRACKING_KEY,
			sizeof(CONTEXT_TRACKING_KEY),
			0,
			(u64 *)&context_tracking_key
		);
		if (ret || !context_tracking_key)
		{
			bpf_warn("bpf_kallsyms_lookup_name failed: %d", ret);
		}
	}
	if (context_tracking_key)
	{
		bpf_info(
			CONTEXT_TRACKING_KEY ": %p-%d",
			context_tracking_key,
			BPF_CORE_READ(context_tracking_key, key.enabled.counter)
		);
	}
	return 0;
}