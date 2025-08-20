/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __spinlock_ob_H
#define __spinlock_ob_H

/* __BITS_BPF_H */
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = val)

#define MAX_ENTRIES 102400
#define TASK_COMM_LEN 16
#define PERF_MAX_STACK_DEPTH 127

struct lock_stat
{
	__u64 acq_count;
	__u64 acq_total_time;
	__u64 acq_max_time;
	__u64 acq_max_id;
	__u64 acq_max_lock_ptr;
	char acq_max_comm[TASK_COMM_LEN];
	__u64 hld_count;
	__u64 hld_total_time;
	__u64 hld_max_time;
	__u64 hld_max_id;
	__u64 hld_max_lock_ptr;
	char hld_max_comm[TASK_COMM_LEN];
};

struct ksym
{
	const char *name;
	unsigned long addr;
};

struct ksyms;

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *
ksyms__map_addr(const struct ksyms *ksyms, unsigned long addr);
const struct ksym *
ksyms__get_symbol(const struct ksyms *ksyms, const char *name);

struct sym
{
	const char *name;
	unsigned long start;
	unsigned long size;
	unsigned long offset;
};

struct sym_info
{
	const char *dso_name;
	unsigned long dso_offset;
	const char *sym_name;
	unsigned long sym_offset;
};

struct syms;

#endif /* spinlock_ob_H_ */
