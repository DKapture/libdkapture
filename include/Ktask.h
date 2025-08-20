#ifndef _LINUX_TASK_H
#define _LINUX_TASK_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "Kmem.h"
#include "Kstr-utils.h"

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wunused-function\"")

/**
 * commit 2f064a59a1 ("sched: Change task_struct::state") changes
 * the name of task_struct::state to task_struct::__state
 * see:
 *     https://github.com/torvalds/linux/commit/2f064a59a1
 */
struct task_struct___o
{
	volatile long int state;
} __attribute__((preserve_access_index));

struct task_struct___x
{
	unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task)
{
	struct task_struct___x *t = task;

	if (bpf_core_field_exists(t->__state))
	{
		return BPF_CORE_READ(t, __state);
	}
	return BPF_CORE_READ((struct task_struct___o *)task, state);
}

/**
 * Get the current file path of the process
 * use case limited: see use case for helper function bpf_d_path
 */
static long get_current_filepath(char *buf, long bsz)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct mm_struct *mm;
	struct file *exe_file;
	struct path f_path;
	long ret = 0;

	if (bsz <= 0)
	{
		bpf_printk("invalid buffer size: %ld", bsz);
		return 0;
	}

	buf[0] = 0;

	ret = bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
	if (ret)
	{
		bpf_printk("fail to read mm: %d", ret);
		return ret;
	}

	if (!mm)
	{ // anonymous process doesn't have mm
		return 0;
	}

	ret = bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file);
	if (ret)
	{
		bpf_printk("fail to read exe_file: %d", ret);
		return ret;
	}

	ret = bpf_probe_read_kernel(&f_path, sizeof(f_path), &exe_file->f_path);
	if (ret)
	{
		bpf_printk("fail to read f_path: %d", ret);
		return ret;
	}

	ret = bpf_d_path(&f_path, buf, bsz);
	if (ret < 0)
	{
		bpf_printk("fail to get d_path: %d", ret);
		return ret;
	}

	return ret;
}

_Pragma("GCC diagnostic pop")

#endif