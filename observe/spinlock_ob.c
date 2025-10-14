// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include "spinlock_ob.h"
#include "spinlock_ob.skel.h"

/* taken from libbpf */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#define min(x, y)                                                              \
	({                                                                         \
		typeof(x) _min1 = (x);                                                 \
		typeof(y) _min2 = (y);                                                 \
		(void)(&_min1 == &_min2);                                              \
		_min1 < _min2 ? _min1 : _min2;                                         \
	})

#define DISK_NAME_LEN 32

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

struct ksyms
{
	struct ksym *syms;
	int syms_sz;
	int syms_cap;
	char *strs;
	int strs_sz;
	int strs_cap;
};

static int
ksyms__add_symbol(struct ksyms *ksyms, const char *name, unsigned long addr)
{
	size_t new_cap, name_len = strlen(name) + 1;
	struct ksym *ksym;
	void *tmp;

	if (ksyms->strs_sz + name_len > ksyms->strs_cap)
	{
		new_cap = ksyms->strs_cap * 4 / 3;
		if (new_cap < ksyms->strs_sz + name_len)
		{
			new_cap = ksyms->strs_sz + name_len;
		}
		if (new_cap < 1024)
		{
			new_cap = 1024;
		}
		tmp = realloc(ksyms->strs, new_cap);
		if (!tmp)
		{
			return -1;
		}
		ksyms->strs = (char *)tmp;
		ksyms->strs_cap = new_cap;
	}
	if (ksyms->syms_sz + 1 > ksyms->syms_cap)
	{
		new_cap = ksyms->syms_cap * 4 / 3;
		if (new_cap < 1024)
		{
			new_cap = 1024;
		}
		tmp = realloc(ksyms->syms, sizeof(*ksyms->syms) * new_cap);
		if (!tmp)
		{
			return -1;
		}
		ksyms->syms = (struct ksym *)tmp;
		ksyms->syms_cap = new_cap;
	}

	ksym = &ksyms->syms[ksyms->syms_sz];
	/* while constructing, re-use pointer as just a plain offset */
	ksym->name = (const char *)(unsigned long)ksyms->strs_sz;
	ksym->addr = addr;

	memcpy(ksyms->strs + ksyms->strs_sz, name, name_len);
	ksyms->strs_sz += name_len;
	ksyms->syms_sz++;

	return 0;
}

static int ksym_cmp(const void *p1, const void *p2)
{
	const struct ksym *s1 = (const struct ksym *)p1,
					  *s2 = (const struct ksym *)p2;

	if (s1->addr == s2->addr)
	{
		return strcmp(s1->name, s2->name);
	}
	return s1->addr < s2->addr ? -1 : 1;
}

struct ksyms *ksyms__load(void)
{
	char sym_type, sym_name[256];
	struct ksyms *ksyms;
	unsigned long sym_addr;
	int i, ret;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
	{
		return NULL;
	}

	ksyms = (struct ksyms *)calloc(1, sizeof(*ksyms));
	if (!ksyms)
	{
		goto err_out;
	}

	while (true)
	{
		ret = fscanf(f, "%lx %c %s%*[^\n]\n", &sym_addr, &sym_type, sym_name);
		if (ret == EOF && feof(f))
		{
			break;
		}
		if (ret != 3)
		{
			goto err_out;
		}
		if (ksyms__add_symbol(ksyms, sym_name, sym_addr))
		{
			goto err_out;
		}
	}

	/* now when strings are finalized, adjust pointers properly */
	for (i = 0; i < ksyms->syms_sz; i++)
	{
		ksyms->syms[i].name += (unsigned long)ksyms->strs;
	}

	qsort(ksyms->syms, ksyms->syms_sz, sizeof(*ksyms->syms), ksym_cmp);

	fclose(f);
	return ksyms;

err_out:
	ksyms__free(ksyms);
	fclose(f);
	return NULL;
}

void ksyms__free(struct ksyms *ksyms)
{
	if (!ksyms)
	{
		return;
	}

	free(ksyms->syms);
	free(ksyms->strs);
	free(ksyms);
}

const struct ksym *
ksyms__map_addr(const struct ksyms *ksyms, unsigned long addr)
{
	int start = 0, end = ksyms->syms_sz - 1, mid;
	unsigned long sym_addr;

	/* find largest sym_addr <= addr using binary search */
	while (start < end)
	{
		mid = start + (end - start + 1) / 2;
		sym_addr = ksyms->syms[mid].addr;

		if (sym_addr <= addr)
		{
			start = mid;
		}
		else
		{
			end = mid - 1;
		}
	}

	if (start == end && ksyms->syms[start].addr <= addr)
	{
		return &ksyms->syms[start];
	}
	return NULL;
}

const struct ksym *
ksyms__get_symbol(const struct ksyms *ksyms, const char *name)
{
	int i;

	for (i = 0; i < ksyms->syms_sz; i++)
	{
		if (strcmp(ksyms->syms[i].name, name) == 0)
		{
			return &ksyms->syms[i];
		}
	}

	return NULL;
}

static inline void *libbpf_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (__builtin_mul_overflow(nmemb, size, &total))
	{
		return NULL;
	}
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
	{
		return NULL;
	}
	total = nmemb * size;
#endif
	return realloc(ptr, total);
}
/*compat.h end*/

#define warn(...) fprintf(stderr, __VA_ARGS__)

enum
{
	SORT_ACQ_MAX,
	SORT_ACQ_COUNT,
	SORT_ACQ_TOTAL,
	SORT_HLD_MAX,
	SORT_HLD_COUNT,
	SORT_HLD_TOTAL,
};

static struct prog_env
{
	pid_t pid;
	pid_t tid;
	char *caller;
	char *lock_name;
	unsigned int nr_locks;
	unsigned int nr_stack_entries;
	unsigned int sort_acq;
	unsigned int sort_hld;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool reset;
	bool timestamp;
	bool verbose;
	bool per_thread;
} env = {
	.nr_locks = 99999999,
	.nr_stack_entries = 1,
	.sort_acq = SORT_ACQ_MAX,
	.sort_hld = SORT_HLD_MAX,
	.interval = 99999999,
	.iterations = 99999999,
	.caller = NULL,
	.lock_name = NULL,
};

const char *argp_program_version = "spinlock_ob 0.2";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/"
									   "master/libbpf-tools";
static const char args_doc[] = "FUNCTION";
static const char program_doc[] =
	"Trace mutex/sem lock acquisition and hold times, in nsec\n"
	"\n"
	"Usage: spinlock_ob [-hPRTv] [-p PID] [-t TID] [-c FUNC] [-L LOCK] [-n "
	"NR_LOCKS]\n"
	"                 [-s NR_STACKS] [-S SORT] [-d DURATION] [-i INTERVAL]\n"
	"\v"
	"Examples:\n"
	"  spinlock_ob                     # trace system wide until ctrl-c\n"
	"  spinlock_ob -d 5                # trace for 5 seconds\n"
	"  spinlock_ob -i 5                # print stats every 5 seconds\n"
	"  spinlock_ob -p 181              # trace process 181 only\n"
	"  spinlock_ob -t 181              # trace thread 181 only\n"
	"  spinlock_ob -c pipe_            # print only for lock callers with "
	"'pipe_'\n"
	"                                # prefix\n"
	"  spinlock_ob -L cgroup_mutex     # trace the cgroup_mutex lock only "
	"(accepts addr too)\n"
	"  spinlock_ob -S acq_count        # sort lock acquired results by acquire "
	"count\n"
	"  spinlock_ob -S hld_total        # sort lock held results by total held "
	"time\n"
	"  spinlock_ob -S acq_count,hld_total  # combination of above\n"
	"  spinlock_ob -n 3                # display top 3 locks/threads\n"
	"  spinlock_ob -s 6                # display 6 stack entries per lock\n"
	"  spinlock_ob -P                  # print stats per thread\n";

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Filter by process ID", 0},
	{"tid", 't', "TID", 0, "Filter by thread ID", 0},
	{0, 0, 0, 0, "", 0},
	{"caller", 'c', "FUNC", 0, "Filter by caller string prefix", 0},
	{"lock", 'L', "LOCK", 0, "Filter by specific ksym lock name", 0},
	{0, 0, 0, 0, "", 0},
	{"locks", 'n', "NR_LOCKS", 0, "Number of locks or threads to print", 0},
	{"stacks",
	 's', "NR_STACKS",
	 0, "Number of stack entries to print per lock",
	 0},
	{"sort",
	 'S', "SORT",
	 0, "Sort by field:\n  acq_[max|total|count]\n  hld_[max|total|count]",
	 0},
	{0, 0, 0, 0, "", 0},
	{"duration", 'd', "SECONDS", 0, "Duration to trace", 0},
	{"interval", 'i', "SECONDS", 0, "Print interval", 0},
	{"reset", 'R', NULL, 0, "Reset stats each interval", 0},
	{"timestamp", 'T', NULL, 0, "Print timestamp", 0},
	{"verbose", 'v', NULL, 0, "Verbose debug output", 0},
	{"per-thread", 'P', NULL, 0, "Print per-thread stats", 0},

	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
	{},
};

static void *parse_lock_addr(const char *lock_name)
{
	unsigned long lock_addr;

	return sscanf(lock_name, "0x%lx", &lock_addr) ? (void *)lock_addr : NULL;
}

static void *get_lock_addr(struct ksyms *ksyms, const char *lock_name)
{
	const struct ksym *ksym = ksyms__get_symbol(ksyms, lock_name);

	return ksym ? (void *)ksym->addr : parse_lock_addr(lock_name);
}

static const char *get_lock_name(struct ksyms *ksyms, unsigned long addr)
{
	const struct ksym *ksym = ksyms__map_addr(ksyms, addr);

	return (ksym && ksym->addr == addr) ? ksym->name : "no-ksym";
}

static bool parse_one_sort(struct prog_env *env, const char *sort)
{
	const char *field = sort + 4;

	if (!strncmp(sort, "acq_", 4))
	{
		if (!strcmp(field, "max"))
		{
			env->sort_acq = SORT_ACQ_MAX;
			return true;
		}
		else if (!strcmp(field, "total"))
		{
			env->sort_acq = SORT_ACQ_TOTAL;
			return true;
		}
		else if (!strcmp(field, "count"))
		{
			env->sort_acq = SORT_ACQ_COUNT;
			return true;
		}
	}
	else if (!strncmp(sort, "hld_", 4))
	{
		if (!strcmp(field, "max"))
		{
			env->sort_hld = SORT_HLD_MAX;
			return true;
		}
		else if (!strcmp(field, "total"))
		{
			env->sort_hld = SORT_HLD_TOTAL;
			return true;
		}
		else if (!strcmp(field, "count"))
		{
			env->sort_hld = SORT_HLD_COUNT;
			return true;
		}
	}

	return false;
}

static bool parse_sorts(struct prog_env *env, char *arg)
{
	char *comma = strchr(arg, ',');

	if (comma)
	{
		*comma = '\0';
		comma++;
		if (!parse_one_sort(env, comma))
		{
			return false;
		}
	}
	return parse_one_sort(env, arg);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = (struct prog_env *)state->input;
	long duration, interval;

	switch (key)
	{
	case 'p':
		errno = 0;
		env->pid = strtol(arg, NULL, 10);
		if (errno || env->pid <= 0)
		{
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		errno = 0;
		env->tid = strtol(arg, NULL, 10);
		if (errno || env->tid <= 0)
		{
			warn("Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env->caller = arg;
		break;
	case 'L':
		env->lock_name = arg;
		break;
	case 'n':
		errno = 0;
		env->nr_locks = strtol(arg, NULL, 10);
		if (errno || env->nr_locks <= 0)
		{
			warn("Invalid NR_LOCKS: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 's':
		errno = 0;
		env->nr_stack_entries = strtol(arg, NULL, 10);
		if (errno || env->nr_stack_entries <= 0)
		{
			warn("Invalid NR_STACKS: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'S':
		if (!parse_sorts(env, arg))
		{
			warn("Bad sort string: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0)
		{
			warn("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		env->duration = duration;
		break;
	case 'i':
		errno = 0;
		interval = strtol(arg, NULL, 10);
		if (errno || interval <= 0)
		{
			warn("Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		env->interval = interval;
		break;
	case 'R':
		env->reset = true;
		break;
	case 'T':
		env->timestamp = true;
		break;
	case 'P':
		env->per_thread = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env->verbose = true;
		break;
	case ARGP_KEY_END:
		if (env->duration)
		{
			if (env->interval > env->duration)
			{
				env->interval = env->duration;
			}
			env->iterations = env->duration / env->interval;
		}
		if (env->per_thread && env->nr_stack_entries != 1)
		{
			warn("--per-thread and --stacks cannot be used together\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

struct stack_stat
{
	uint32_t stack_id;
	struct lock_stat ls;
	uint64_t bt[PERF_MAX_STACK_DEPTH];
};

static bool caller_is_traced(struct ksyms *ksyms, uint64_t caller_pc)
{
	const struct ksym *ksym;

	if (!env.caller)
	{
		return true;
	}
	ksym = ksyms__map_addr(ksyms, caller_pc);
	if (!ksym)
	{
		return true;
	}
	return strncmp(env.caller, ksym->name, strlen(env.caller)) == 0;
}

static int larger_first(uint64_t x, uint64_t y)
{
	if (x > y)
	{
		return -1;
	}
	if (x == y)
	{
		return 0;
	}
	return 1;
}

static int sort_by_acq(const void *x, const void *y)
{
	struct stack_stat *ss_x = *(struct stack_stat **)x;
	struct stack_stat *ss_y = *(struct stack_stat **)y;

	switch (env.sort_acq)
	{
	case SORT_ACQ_MAX:
		return larger_first(ss_x->ls.acq_max_time, ss_y->ls.acq_max_time);
	case SORT_ACQ_COUNT:
		return larger_first(ss_x->ls.acq_count, ss_y->ls.acq_count);
	case SORT_ACQ_TOTAL:
		return larger_first(ss_x->ls.acq_total_time, ss_y->ls.acq_total_time);
	}

	warn("bad sort_acq %d\n", env.sort_acq);
	return -1;
}

static int sort_by_hld(const void *x, const void *y)
{
	struct stack_stat *ss_x = *(struct stack_stat **)x;
	struct stack_stat *ss_y = *(struct stack_stat **)y;

	switch (env.sort_hld)
	{
	case SORT_HLD_MAX:
		return larger_first(ss_x->ls.hld_max_time, ss_y->ls.hld_max_time);
	case SORT_HLD_COUNT:
		return larger_first(ss_x->ls.hld_count, ss_y->ls.hld_count);
	case SORT_HLD_TOTAL:
		return larger_first(ss_x->ls.hld_total_time, ss_y->ls.hld_total_time);
	}

	warn("bad sort_hld %d\n", env.sort_hld);
	return -1;
}

static char *symname(struct ksyms *ksyms, uint64_t pc, char *buf, size_t n)
{
	const struct ksym *ksym = ksyms__map_addr(ksyms, pc);

	if (!ksym)
	{
		return "Unknown";
	}
	snprintf(buf, n, "%s+0x%lx", ksym->name, pc - ksym->addr);
	return buf;
}

static char *print_caller(char *buf, int size, struct stack_stat *ss)
{
	snprintf(buf, size, "%u  %16s", ss->stack_id, ss->ls.acq_max_comm);
	return buf;
}

static char *print_time(char *buf, int size, uint64_t nsec)
{
	struct
	{
		float base;
		char *unit;
	} table[] = {
		{1e9 * 3600, "h "},
		{1e9 * 60,   "m "},
		{1e9,		  "s "},
		{1e6,		  "ms"},
		{1e3,		  "us"},
		{0,			NULL},
	};

	for (int i = 0; table[i].base; i++)
	{
		if (nsec < table[i].base)
		{
			continue;
		}

		snprintf(buf, size, "%.1f %s", nsec / table[i].base, table[i].unit);
		return buf;
	}

	snprintf(buf, size, "%u ns", (unsigned)nsec);
	return buf;
}

static void print_acq_header(void)
{
	if (env.per_thread)
	{
		printf("\n                Tid              Comm");
	}
	else
	{
		printf("\n                               Caller");
	}

	printf("  Avg Wait    Count   Max Wait   Total Wait\n");
}

static void
print_acq_stat(struct ksyms *ksyms, struct stack_stat *ss, int nr_stack_entries)
{
	char buf[40];
	char avg[40];
	char max[40];
	char tot[40];
	int i;

	printf(
		"%37s %9s %8llu %10s %12s\n",
		symname(ksyms, ss->bt[0], buf, sizeof(buf)),
		print_time(avg, sizeof(avg), ss->ls.acq_total_time / ss->ls.acq_count),
		ss->ls.acq_count,
		print_time(max, sizeof(max), ss->ls.acq_max_time),
		print_time(tot, sizeof(tot), ss->ls.acq_total_time)
	);
	for (i = 1; i < nr_stack_entries; i++)
	{
		if (!ss->bt[i] || env.per_thread)
		{
			break;
		}
		printf("%37s\n", symname(ksyms, ss->bt[i], buf, sizeof(buf)));
	}
	if (nr_stack_entries > 1 && !env.per_thread)
	{
		printf(
			"                              Max PID %llu, COMM %s, Lock %s "
			"(0x%llx)\n",
			ss->ls.acq_max_id >> 32,
			ss->ls.acq_max_comm,
			get_lock_name(ksyms, ss->ls.acq_max_lock_ptr),
			ss->ls.acq_max_lock_ptr
		);
	}
}

static void print_acq_task(struct stack_stat *ss)
{
	char buf[40];
	char avg[40];
	char max[40];
	char tot[40];

	printf(
		"%37s %9s %8llu %10s %12s\n",
		print_caller(buf, sizeof(buf), ss),
		print_time(avg, sizeof(avg), ss->ls.acq_total_time / ss->ls.acq_count),
		ss->ls.acq_count,
		print_time(max, sizeof(max), ss->ls.acq_max_time),
		print_time(tot, sizeof(tot), ss->ls.acq_total_time)
	);
}

static void print_hld_header(void)
{
	if (env.per_thread)
	{
		printf("\n                Tid              Comm");
	}
	else
	{
		printf("\n                               Caller");
	}

	printf("  Avg Hold    Count   Max Hold   Total Hold\n");
}

static void
print_hld_stat(struct ksyms *ksyms, struct stack_stat *ss, int nr_stack_entries)
{
	char buf[40];
	char avg[40];
	char max[40];
	char tot[40];
	int i;

	printf(
		"%37s %9s %8llu %10s %12s\n",
		symname(ksyms, ss->bt[0], buf, sizeof(buf)),
		print_time(avg, sizeof(avg), ss->ls.hld_total_time / ss->ls.hld_count),
		ss->ls.hld_count,
		print_time(max, sizeof(max), ss->ls.hld_max_time),
		print_time(tot, sizeof(tot), ss->ls.hld_total_time)
	);
	for (i = 1; i < nr_stack_entries; i++)
	{
		if (!ss->bt[i] || env.per_thread)
		{
			break;
		}
		printf("%37s\n", symname(ksyms, ss->bt[i], buf, sizeof(buf)));
	}
	if (nr_stack_entries > 1 && !env.per_thread)
	{
		printf(
			"                              Max PID %llu, COMM %s, Lock %s "
			"(0x%llx)\n",
			ss->ls.hld_max_id >> 32,
			ss->ls.hld_max_comm,
			get_lock_name(ksyms, ss->ls.hld_max_lock_ptr),
			ss->ls.hld_max_lock_ptr
		);
	}
}

static void print_hld_task(struct stack_stat *ss)
{
	char buf[40];
	char avg[40];
	char max[40];
	char tot[40];

	printf(
		"%37s %9s %8llu %10s %12s\n",
		print_caller(buf, sizeof(buf), ss),
		print_time(avg, sizeof(avg), ss->ls.hld_total_time / ss->ls.hld_count),
		ss->ls.hld_count,
		print_time(max, sizeof(max), ss->ls.hld_max_time),
		print_time(tot, sizeof(tot), ss->ls.hld_total_time)
	);
}

static int print_stats(struct ksyms *ksyms, int stacks, int stat_map)
{
	struct stack_stat **stats, *ss;
	size_t stat_idx = 0;
	size_t stats_sz = 1;
	uint32_t lookup_key = 0;
	uint32_t stack_id;
	int ret, i;
	int nr_stack_entries;

	stats = (struct stack_stat **)calloc(stats_sz, sizeof(void *));
	if (!stats)
	{
		warn("Out of memory\n");
		return -1;
	}

	while (bpf_map_get_next_key(stat_map, &lookup_key, &stack_id) == 0)
	{
		if (stat_idx == stats_sz)
		{
			stats_sz *= 2;
			stats = (struct stack_stat **)
				libbpf_reallocarray(stats, stats_sz, sizeof(void *));
			if (!stats)
			{
				warn("Out of memory\n");
				return -1;
			}
		}
		ss = (struct stack_stat *)malloc(sizeof(struct stack_stat));
		if (!ss)
		{
			warn("Out of memory\n");
			return -1;
		}

		lookup_key = ss->stack_id = stack_id;
		ret = bpf_map_lookup_elem(stat_map, &stack_id, &ss->ls);
		if (ret)
		{
			free(ss);
			continue;
		}
		if (!env.per_thread &&
			bpf_map_lookup_elem(stacks, &stack_id, &ss->bt))
		{
			/* Can still report the results without a backtrace. */
			warn("failed to lookup stack_id %u\n", stack_id);
		}
		if (!env.per_thread && !caller_is_traced(ksyms, ss->bt[0]))
		{
			free(ss);
			continue;
		}
		stats[stat_idx++] = ss;
	}

	nr_stack_entries = MIN(env.nr_stack_entries, PERF_MAX_STACK_DEPTH);

	qsort(stats, stat_idx, sizeof(void *), sort_by_acq);
	for (i = 0; i < MIN(env.nr_locks, stat_idx); i++)
	{
		if (i == 0 || env.nr_stack_entries > 1)
		{
			print_acq_header();
		}

		if (env.per_thread)
		{
			print_acq_task(stats[i]);
		}
		else
		{
			print_acq_stat(ksyms, stats[i], nr_stack_entries);
		}
	}

	qsort(stats, stat_idx, sizeof(void *), sort_by_hld);
	for (i = 0; i < MIN(env.nr_locks, stat_idx); i++)
	{
		if (i == 0 || env.nr_stack_entries > 1)
		{
			print_hld_header();
		}

		if (env.per_thread)
		{
			print_hld_task(stats[i]);
		}
		else
		{
			print_hld_stat(ksyms, stats[i], nr_stack_entries);
		}
	}

	for (i = 0; i < stat_idx; i++)
	{
		if (env.reset)
		{
			ss = stats[i];
			bpf_map_delete_elem(stat_map, &ss->stack_id);
		}
		free(stats[i]);
	}
	free(stats);

	return 0;
}

static volatile bool exiting;

static void sig_hand(int signr)
{
	exiting = true;
}

static struct sigaction sigact = {.sa_handler = sig_hand};

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
	{
		return 0;
	}
	return vfprintf(stderr, format, args);
}

static void enable_fentry(struct spinlock_ob_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.kprobe_raw_spin_lock, false);
	bpf_program__set_autoload(obj->progs.kretprobe_raw_spin_lock, false);
	bpf_program__set_autoload(obj->progs.kprobe_raw_spin_unlock, false);
}

static void enable_kprobes(struct spinlock_ob_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.fentry_raw_spin_lock, false);
	bpf_program__set_autoload(obj->progs.fexit_raw_spin_lock, false);
	bpf_program__set_autoload(obj->progs.fentry_raw_spin_unlock, false);
}

static bool fentry_try_attach(int id)
{
	int prog_fd, attach_fd;
	char error[4096];
	struct bpf_insn insns[] = {
		{.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
		{.code = BPF_JMP | BPF_EXIT},
	};
	LIBBPF_OPTS(
		bpf_prog_load_opts,
		opts,
		.expected_attach_type = BPF_TRACE_FENTRY,
		.attach_btf_id = id,
		.log_buf = error,
		.log_size = sizeof(error),
	);

	prog_fd = bpf_prog_load(
		BPF_PROG_TYPE_TRACING,
		"test",
		"GPL",
		insns,
		sizeof(insns) / sizeof(struct bpf_insn),
		&opts
	);
	if (prog_fd < 0)
	{
		return false;
	}

	attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
	if (attach_fd >= 0)
	{
		close(attach_fd);
	}

	close(prog_fd);
	return attach_fd >= 0;
}

bool fentry_can_attach(const char *name, const char *mod)
{
	struct btf *btf, *vmlinux_btf, *module_btf = NULL;
	int err, id;

	vmlinux_btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (err)
	{
		return false;
	}

	btf = vmlinux_btf;

	if (mod)
	{
		module_btf = btf__load_module_btf(mod, vmlinux_btf);
		err = libbpf_get_error(module_btf);
		if (!err)
		{
			btf = module_btf;
		}
	}

	id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

	btf__free(module_btf);
	btf__free(vmlinux_btf);
	return id > 0 && fentry_try_attach(id);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};
	struct spinlock_ob_bpf *obj = NULL;
	struct ksyms *ksyms = NULL;
	int i, err;
	struct tm *tm;
	char ts[32];
	time_t t;
	void *lock_addr = NULL;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
	{
		return err;
	}

	sigaction(SIGINT, &sigact, 0);

	libbpf_set_print(libbpf_print_fn);

	ksyms = ksyms__load();
	if (!ksyms)
	{
		warn("failed to load kallsyms\n");
		err = 1;
		goto cleanup;
	}
	if (env.lock_name)
	{
		lock_addr = get_lock_addr(ksyms, env.lock_name);
		if (!lock_addr)
		{
			warn("failed to find lock %s\n", env.lock_name);
			err = 1;
			goto cleanup;
		}
	}

	obj = spinlock_ob_bpf__open();
	if (!obj)
	{
		warn("failed to open BPF object\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->target_tgid = env.pid;
	obj->rodata->target_pid = env.tid;
	obj->rodata->target_lock = lock_addr;
	obj->rodata->per_thread = env.per_thread;

	if (fentry_can_attach("mutex_lock", NULL) ||
		fentry_can_attach("mutex_lock_nested", NULL))
	{
		printf("Using fentry\n");
		enable_fentry(obj);
	}
	else
	{
		printf("Using kprobes\n");
		enable_kprobes(obj);
	}

	err = spinlock_ob_bpf__load(obj);
	if (err)
	{
		warn("failed to load BPF object\n");
		return 1;
	}
	err = spinlock_ob_bpf__attach(obj);
	if (err)
	{
		warn("failed to attach BPF object\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat "
		   "/sys/kernel/debug/tracing/trace_pipe` "
		   "to see output of the BPF programs.\n");

	printf("Tracing spin lock events...  Hit Ctrl-C to end\n");

	for (i = 0; i < env.iterations && !exiting; i++)
	{
		sleep(env.interval);

		printf("\n");
		if (env.timestamp)
		{
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		if (print_stats(
				ksyms,
				bpf_map__fd(obj->maps.stacks),
				bpf_map__fd(obj->maps.stat_map)
			))
		{
			warn("print_stats error, aborting.\n");
			break;
		}
		fflush(stdout);
	}

	printf("Exiting trace of spin locks\n");

cleanup:
	spinlock_ob_bpf__destroy(obj);
	ksyms__free(ksyms);

	return err != 0;
}
