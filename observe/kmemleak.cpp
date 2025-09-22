// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
//
// Based on memleak(8) from BCC by Sasha Goldshtein and others.
// 1-Mar-2023   JP Kobryn   Created this.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "kmemleak.skel.h"
#include "com.h"
#include "dkapture.h"

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240
#define NSEC_PER_SEC 1000000000ULL

struct alloc_info
{
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
};

union combined_alloc_info
{
	struct
	{
		__u64 total_size : 40;
		__u64 number_of_allocs : 24;
	};
	__u64 bits;
};

struct ksym
{
	const char *name;
	unsigned long addr;
};

struct ksyms
{
	struct ksym *syms;
	int syms_sz;
	int syms_cap;
	char *strs;
	int strs_sz;
	int strs_cap;
};

struct sym_info
{
	const char *dso_name;
	unsigned long dso_offset;
	const char *sym_name;
	unsigned long sym_offset;
};

static struct env
{
	int interval;
	int nr_intervals;
	pid_t pid;
	bool trace_all;
	bool show_allocs;
	bool combined_only;
	int min_age_ns;
	uint64_t sample_rate;
	int top_stacks;
	size_t min_size;
	size_t max_size;

	bool wa_missing_free;
	int perf_max_stack_depth;
	int stack_map_max_entries;
	long page_size;
	bool verbose;
	char command[32];
} env = {
	.interval = 5,			  // posarg 1
	.nr_intervals = -1,		  // posarg 2
	.pid = 0,				  // -p --pid
	.trace_all = false,		  // -t --trace
	.show_allocs = false,	  // -a --show-allocs
	.combined_only = false,	  // --combined-only
	.min_age_ns = 500,		  // -o --older (arg * 1e6)
	.sample_rate = 1,		  // -s --sample-rate
	.top_stacks = 10,		  // -T --top
	.min_size = 0,			  // -z --min-size
	.max_size = UINT64_MAX,	  // -Z --max-size
	.wa_missing_free = false, // --wa-missing-free
	.perf_max_stack_depth = 127,
	.stack_map_max_entries = 10240,
	.page_size = 1,
	.verbose = false,
	.command = {0}, // -c --command
};

struct allocation_node
{
	uint64_t address;
	size_t size;
	struct allocation_node *next;
};

struct allocation
{
	uint64_t stack_id;
	size_t size;
	size_t count;
	struct allocation_node *allocations;
};

#define __CHECK_PROGRAM(skel, prog_name)                                       \
	do                                                                         \
	{                                                                          \
		if (!skel->links.prog_name)                                            \
		{                                                                      \
			perror("no program attached for " #prog_name);                     \
			return -errno;                                                     \
		}                                                                      \
	} while (false)

static void sig_handler(int signo);

static long argp_parse_long(int key, const char *arg, struct argp_state *state);
static error_t parse_args(int key, char *arg, struct argp_state *state);

static int libbpf_print_fn(
	enum libbpf_print_level level,
	const char *format,
	va_list args
);

static int event_init(int *fd);
static int event_wait(int fd, uint64_t expected_event);
static int event_notify(int fd, uint64_t event);
static pid_t fork_sync_exec(const char *command, int fd);
static int alloc_size_compare(const void *a, const void *b);
static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd);
static int
print_outstanding_combined_allocs(int combined_allocs_fd, int stack1_traces_fd);

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/"
									   "master/libbpf-tools";

const char argp_args_doc[] =
	"Trace outstanding memory allocations\n"
	"\n"
	"USAGE: memleak [-h] [-c COMMAND] [-p PID] [-t] [-a] [-o AGE_MS] [-C] [-F] "
	"[-s SAMPLE_RATE] [-T TOP_STACKS] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJECT] "
	"[INTERVAL] [INTERVALS]\n"
	"\n"
	"EXAMPLES:\n"
	"./kmemleak -p $(pidof allocs)\n"
	"        Trace allocations and display a summary of 'leaked' "
	"(outstanding)\n"
	"        allocations every 5 seconds\n"
	"./kmemleak -p $(pidof allocs) -t\n"
	"        Trace allocations and display each individual allocator function "
	"call\n"
	"./kmemleak -ap $(pidof allocs) 10\n"
	"        Trace allocations and display allocated addresses, sizes, and "
	"stacks\n"
	"        every 10 seconds for outstanding allocations\n"
	"./kmemleak -c './allocs'\n"
	"        Run the specified command and trace its allocations\n"
	"./kmemleak\n"
	"        Trace allocations in kernel mode and display a summary of "
	"outstanding\n"
	"        allocations every 5 seconds\n"
	"./kmemleak -o 60000\n"
	"        Trace allocations in kernel mode and display a summary of "
	"outstanding\n"
	"        allocations that are at least one minute (60 seconds) old\n"
	"./kmemleak -s 5\n"
	"        Trace roughly every 5th allocation, to reduce overhead\n"
	"";

static const struct argp_option argp_options[] = {
	{"pid",
	 'p', "PID",
	 0, "process ID to trace. if not specified, trace kernel allocs",
	 0},
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call", 0},
	{"show-allocs",
	 'a', 0,
	 0, "show allocation addresses and sizes as well as call stacks",
	 0},
	{"older",
	 'o', "AGE_MS",
	 0, "prune allocations younger than this age in milliseconds",
	 0},
	{"command", 'c', "COMMAND", 0, "execute and trace the specified command", 0
	},
	{"combined-only", 'C', 0, 0, "show combined allocation statistics only", 0},
	{"wa-missing-free",
	 'F', 0,
	 0, "workaround to alleviate misjudgments when free is missing",
	 0},
	{"sample-rate",
	 's', "SAMPLE_RATE",
	 0, "sample every N-th allocation to decrease the overhead",
	 0},
	{"top",
	 'T', "TOP_STACKS",
	 0, "display only this many top allocating stacks (by size)",
	 0},
	{"min-size",
	 'z', "MIN_SIZE",
	 0, "capture only allocations larger than this size",
	 0},
	{"max-size",
	 'Z', "MAX_SIZE",
	 0, "capture only allocations smaller than this size",
	 0},
	{"verbose", 'v', NULL, 0, "verbose debug output", 0},
	{},
};

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t child_exited;
static struct sigaction sig_action;
static int allocs_fd = -1;
static int combined_allocs_fd = -1;
static int stack_traces_fd = -1;
#ifdef BUILTIN
static DKapture::DKCallback stack_print_callback = nullptr;
static void *callback_ctx = nullptr;
#endif

static int child_exec_event_fd = -1;
struct kmemleak_bpf *skel = NULL;

struct ksyms *ksyms;

static uint64_t *stack;

static struct allocation *allocs;

static int ksym_cmp(const void *p1, const void *p2)
{
	const struct ksym *s1 = (typeof(s1))p1, *s2 = (typeof(s2))p2;

	if (s1->addr == s2->addr)
	{
		return strcmp(s1->name, s2->name);
	}
	return s1->addr < s2->addr ? -1 : 1;
}

void ksyms_free(struct ksyms *ksyms)
{
	if (!ksyms)
	{
		return;
	}

	free(ksyms->syms);
	free(ksyms->strs);
	free(ksyms);
}

unsigned long long get_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

const struct ksym *ksyms_find(const struct ksyms *ksyms, unsigned long addr)
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

static int ksyms_add(struct ksyms *ksyms, const char *name, unsigned long addr)
{
	size_t new_cap, name_len = strlen(name) + 1;
	struct ksym *ksym;
	void *tmp;

	if (ksyms->strs_sz + name_len > (size_t)ksyms->strs_cap)
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
	/* while constructing, re-use pointe r as just a plain offset */
	ksym->name = (char *)(unsigned long)ksyms->strs_sz;
	ksym->addr = addr;

	memcpy(ksyms->strs + ksyms->strs_sz, name, name_len);
	ksyms->strs_sz += name_len;
	ksyms->syms_sz++;

	return 0;
}

struct ksyms *ksyms_load(void)
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

	ksyms = (typeof(ksyms))calloc(1, sizeof(*ksyms));
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
		if (ksyms_add(ksyms, sym_name, sym_addr))
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
	ksyms_free(ksyms);
	fclose(f);
	return NULL;
}

void setup_filter(struct bpf_object *obj)
{
	int filter_fd;
	int key = 0;
	filter_fd = bpf_get_map_fd(obj, "filter", goto err_out);

	if (0 != bpf_map_update_elem(filter_fd, &key, &env.pid, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
	}
err_out:
	return;
}

#ifdef BUILTIN
int kmemleak_stop(void)
{
	print_outstanding_allocs(allocs_fd, stack_traces_fd);
	if (ksyms)
	{
		ksyms_free(ksyms);
	}

	kmemleak_bpf__destroy(skel);

	free(allocs);
	free(stack);
	return 0;
}
int kmemleak_start(int argc, char **argv, DKapture::DKCallback cb, void *ctx)
#else
int main(int argc, char **argv)
#endif
{
	int ret = 0;
	static const struct argp argp = {
		.options = argp_options,
		.parser = parse_args,
		.doc = argp_args_doc,
	};
	sig_action.sa_handler = sig_handler;
#ifndef BUILTIN
	Trace trace;
	trace.start();
	trace.async_follow();
#else
	stack_print_callback = cb;
	callback_ctx = ctx;
#endif

	// parse command line args to env settings
	if (argp_parse(&argp, argc, argv, 0, NULL, NULL))
	{
		fprintf(stderr, "failed to parse args\n");

		goto cleanup;
	}

#ifndef BUILTIN
	// install signal handler
	if (sigaction(SIGINT, &sig_action, NULL) ||
		sigaction(SIGCHLD, &sig_action, NULL))
	{
		perror("failed to set up signal handling");
		ret = -errno;

		goto cleanup;
	}
#endif

	// post-processing and validation of env settings
	if (env.min_size > env.max_size)
	{
		fprintf(stderr, "min size (-z) can't be greater than max_size (-Z)\n");
		return 1;
	}

	env.page_size = sysconf(_SC_PAGE_SIZE);
	DEBUG(0, "using page size: %ld\n", env.page_size);

	// if specific userspace program was specified,
	// create the child process and use an eventfd to synchronize the call to
	// exec()
	if (strlen(env.command))
	{
		if (env.pid > 0)
		{
			fprintf(stderr, "cannot specify both command and pid\n");
			ret = 1;

			goto cleanup;
		}

		if (event_init(&child_exec_event_fd))
		{
			fprintf(stderr, "failed to init child event\n");

			goto cleanup;
		}

		const pid_t child_pid =
			fork_sync_exec(env.command, child_exec_event_fd);
		if (child_pid < 0)
		{
			perror("failed to spawn child process");
			ret = -errno;

			goto cleanup;
		}

		env.pid = child_pid;
	}

	// allocate space for storing a stack trace
	stack = (typeof(stack))calloc(env.perf_max_stack_depth, sizeof(*stack));
	if (!stack)
	{
		fprintf(stderr, "failed to allocate stack array\n");
		ret = -ENOMEM;

		goto cleanup;
	}

	// allocate space for storing "allocation" structs
	if (env.combined_only)
	{
		allocs = (typeof(allocs)
		)calloc(COMBINED_ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	}
	else
	{
		allocs = (typeof(allocs))calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	}

	if (!allocs)
	{
		fprintf(stderr, "failed to allocate array\n");
		ret = -ENOMEM;

		goto cleanup;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = kmemleak_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "failed to open bpf object\n");
		ret = 1;
		goto cleanup;
	}

	skel->rodata->min_size = env.min_size;
	skel->rodata->max_size = env.max_size;
	skel->rodata->page_size = env.page_size;
	skel->rodata->sample_rate = env.sample_rate;
	skel->rodata->trace_all = env.trace_all;
	skel->rodata->stack_flags = 0;
	skel->rodata->wa_missing_free = env.wa_missing_free;

	bpf_map__set_value_size(
		skel->maps.stack_traces,
		env.perf_max_stack_depth * sizeof(unsigned long)
	);
	bpf_map__set_max_entries(
		skel->maps.stack_traces,
		env.stack_map_max_entries
	);

	ret = kmemleak_bpf__load(skel);
	if (ret)
	{
		fprintf(stderr, "failed to load bpf object\n");

		goto cleanup;
	}

	setup_filter(skel->obj);

	allocs_fd = bpf_map__fd(skel->maps.allocs);
	combined_allocs_fd = bpf_map__fd(skel->maps.combined_allocs);
	stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);

	ret = kmemleak_bpf__attach(skel);
	if (ret)
	{
		fprintf(stderr, "failed to attach bpf program(s)\n");

		goto cleanup;
	}

	// if running a specific userspace program,
	// notify the child process that it can exec its program
	if (strlen(env.command))
	{
		ret = event_notify(child_exec_event_fd, 1);
		if (ret)
		{
			fprintf(stderr, "failed to notify child to perform exec\n");

			goto cleanup;
		}
	}

	ksyms = ksyms_load();
	if (!ksyms)
	{
		fprintf(stderr, "Failed to load ksyms\n");
		ret = -ENOMEM;

		goto cleanup;
	}

	printf("Tracing outstanding memory allocs...  Hit Ctrl-C to end\n");

#ifdef BUILTIN
	return 0;
#endif
	// main loop
	while (!exiting && env.nr_intervals)
	{
		env.nr_intervals--;

		sleep(env.interval);

		if (env.combined_only)
		{
			print_outstanding_combined_allocs(
				combined_allocs_fd,
				stack_traces_fd
			);
		}
		else
		{
			print_outstanding_allocs(allocs_fd, stack_traces_fd);
		}
	}

	// after loop ends, check for child process and cleanup accordingly
	if (env.pid > 0 && strlen(env.command))
	{
		if (!child_exited)
		{
			if (kill(env.pid, SIGTERM))
			{
				perror("failed to signal child process");
				ret = -errno;

				goto cleanup;
			}
			printf("signaled child process\n");
		}

		if (waitpid(env.pid, NULL, 0) < 0)
		{
			perror("failed to reap child process");
			ret = -errno;

			goto cleanup;
		}
		printf("reaped child process\n");
	}

cleanup:

	if (ksyms)
	{
		ksyms_free(ksyms);
	}

	kmemleak_bpf__destroy(skel);

	free(allocs);
	free(stack);

	printf("done\n");

	return ret;
}

long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0)
	{
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

error_t parse_args(int key, char *arg, struct argp_state *state)
{
	static int pos_args = 0;

	switch (key)
	{
	case 'p':
		env.pid = atoi(arg);
		break;
	case 't':
		env.trace_all = true;
		break;
	case 'a':
		env.show_allocs = true;
		break;
	case 'o':
		env.min_age_ns = 1e6 * atoi(arg);
		break;
	case 'c':
		strncpy(env.command, arg, sizeof(env.command) - 1);
		break;
	case 'C':
		env.combined_only = true;
		break;
	case 'F':
		env.wa_missing_free = true;
		break;
	case 's':
		env.sample_rate = argp_parse_long(key, arg, state);
		break;
	case 'T':
		env.top_stacks = atoi(arg);
		break;
	case 'z':
		env.min_size = argp_parse_long(key, arg, state);
		break;
	case 'Z':
		env.max_size = argp_parse_long(key, arg, state);
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		pos_args++;

		if (pos_args == 1)
		{
			env.interval = argp_parse_long(key, arg, state);
		}
		else if (pos_args == 2)
		{
			env.nr_intervals = argp_parse_long(key, arg, state);
		}
		else
		{
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int libbpf_print_fn(
	enum libbpf_print_level level,
	const char *format,
	va_list args
)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
	{
		return 0;
	}

	return vfprintf(stderr, format, args);
}

void sig_handler(int signo)
{
	if (signo == SIGCHLD)
	{
		child_exited = 1;
	}

	exiting = 1;
}

int event_init(int *fd)
{
	if (!fd)
	{
		fprintf(stderr, "pointer to fd is null\n");

		return 1;
	}

	const int tmp_fd = eventfd(0, EFD_CLOEXEC);
	if (tmp_fd < 0)
	{
		perror("failed to create event fd");

		return -errno;
	}

	*fd = tmp_fd;

	return 0;
}

int event_wait(int fd, uint64_t expected_event)
{
	uint64_t event = 0;
	const ssize_t bytes = read(fd, &event, sizeof(event));
	if (bytes < 0)
	{
		perror("failed to read from fd");

		return -errno;
	}
	else if (bytes != sizeof(event))
	{
		fprintf(stderr, "read unexpected size\n");

		return 1;
	}

	if (event != expected_event)
	{
		fprintf(
			stderr,
			"read event %lu, expected %lu\n",
			event,
			expected_event
		);

		return 1;
	}

	return 0;
}

int event_notify(int fd, uint64_t event)
{
	const ssize_t bytes = write(fd, &event, sizeof(event));
	if (bytes < 0)
	{
		perror("failed to write to fd");

		return -errno;
	}
	else if (bytes != sizeof(event))
	{
		fprintf(
			stderr,
			"attempted to write %zu bytes, wrote %zd bytes\n",
			sizeof(event),
			bytes
		);

		return 1;
	}

	return 0;
}

pid_t fork_sync_exec(const char *command, int fd)
{
	const pid_t pid = fork();

	switch (pid)
	{
	case -1:
		perror("failed to create child process");
		break;
	case 0:
	{
		const uint64_t event = 1;
		if (event_wait(fd, event))
		{
			fprintf(stderr, "failed to wait on event");
			exit(EXIT_FAILURE);
		}

		printf("received go event. executing child command\n");

		const int err = execl(command, command, NULL);
		if (err)
		{
			perror("failed to execute child command");
			return -1;
		}

		break;
	}
	default:
		printf("child created with pid: %d\n", pid);

		break;
	}

	return pid;
}

void print_stack_frames_by_ksyms(char *buf, size_t bsz)
{
	ssize_t left = bsz;
	for (size_t i = 0; i < (size_t)env.perf_max_stack_depth; ++i)
	{
		ssize_t sz;
		const uint64_t addr = stack[i];

		if (addr == 0)
		{
			break;
		}

		const struct ksym *ksym = ksyms_find(ksyms, addr);
		if (ksym)
		{
			sz = snprintf(
				buf,
				left,
				"\t%zu [<%016lx>] %s+0x%lx\n",
				i,
				addr,
				ksym->name,
				addr - ksym->addr
			);
		}
		else
		{
			sz = snprintf(
				buf,
				left,
				"\t%zu [<%016lx>] <%s>\n",
				i,
				addr,
				"unknown"
			);
		}
		buf += sz;
		left -= sz;
		if (left <= 0)
		{
			break;
		}
	}
}

int print_stack_frames(
	struct allocation *allocs,
	size_t nr_allocs,
	int stack_traces_fd
)
{
	size_t idx = 0;
	size_t bsz = env.perf_max_stack_depth * 256;
	char *buf = (char *)malloc(bsz);
	if (!buf)
	{
		return -ENOMEM;
	}
	for (size_t i = 0; i < nr_allocs; ++i)
	{
		const struct allocation *alloc = &allocs[i];

		idx = snprintf(
			buf,
			bsz,
			"%zu bytes in %zu allocations from stack\n",
			alloc->size,
			alloc->count
		);

		if (env.show_allocs)
		{
			struct allocation_node *it = alloc->allocations;
			while (it != NULL)
			{
				pr_info("\taddr = %#lx size = %zu\n", it->address, it->size);
				it = it->next;
			}
		}

		if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack))
		{
			if (errno == ENOENT)
			{
				continue;
			}

			pr_error("failed to lookup stack trace");
			free(buf);
			return -errno;
		}
		print_stack_frames_by_ksyms(buf + idx, bsz - idx);
#ifdef BUILTIN
		stack_print_callback(callback_ctx, buf, bsz);
#else
		printf("%s", buf);
#endif
	}
	free(buf);
	return 0;
}

int alloc_size_compare(const void *a, const void *b)
{
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order

	if (x->size > y->size)
	{
		return -1;
	}

	if (x->size < y->size)
	{
		return 1;
	}

	return 0;
}

int print_outstanding_allocs(int allocs_fd, int stack_traces_fd)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	int ret = 0;
	size_t nr_allocs = 0;
	size_t nr_allocs_to_show = 0;

	// for each struct alloc_info "alloc_info" in the bpf map "allocs"
	for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key)
	{
		struct alloc_info alloc_info = {};
		memset(&alloc_info, 0, sizeof(alloc_info));

		if (bpf_map_get_next_key(allocs_fd, &prev_key, &curr_key))
		{
			if (errno == ENOENT)
			{
				break; // no more keys, done
			}

			perror("map get next key error");

			ret = -errno;
			goto cleanup;
		}

		if (bpf_map_lookup_elem(allocs_fd, &curr_key, &alloc_info))
		{
			if (errno == ENOENT)
			{
				continue;
			}

			perror("map lookup error");

			ret = -errno;
			goto cleanup;
		}

		// filter by age
		if (get_ns() - env.min_age_ns < alloc_info.timestamp_ns)
		{
			continue;
		}

		// filter invalid stacks
		if (alloc_info.stack_id < 0)
		{
			continue;
		}

		// when the stack_id exists in the allocs array,
		//   increment size with alloc_info.size
		bool stack_exists = false;

		for (size_t i = 0; !stack_exists && i < nr_allocs; ++i)
		{
			struct allocation *alloc = &allocs[i];

			if (alloc->stack_id == (uint64_t)alloc_info.stack_id)
			{
				alloc->size += alloc_info.size;
				alloc->count++;

				if (env.show_allocs)
				{
					struct allocation_node *node;
					node = (typeof(node))malloc(sizeof(struct allocation_node));
					if (!node)
					{
						perror("malloc failed");
						ret = -ENOMEM;
						goto cleanup;
					}
					node->address = curr_key;
					node->size = alloc_info.size;
					node->next = alloc->allocations;
					alloc->allocations = node;
				}

				stack_exists = true;
				break;
			}
		}

		if (stack_exists)
		{
			continue;
		}

		// when the stack_id does not exist in the allocs array,
		//   create a new entry in the array
		struct allocation alloc = {
			.stack_id = (uint64_t)alloc_info.stack_id,
			.size = alloc_info.size,
			.count = 1,
			.allocations = NULL
		};

		if (env.show_allocs)
		{
			struct allocation_node *node;
			node = (typeof(node))malloc(sizeof(struct allocation_node));
			if (!node)
			{
				perror("malloc failed");
				ret = -ENOMEM;
				goto cleanup;
			}
			node->address = curr_key;
			node->size = alloc_info.size;
			node->next = NULL;
			alloc.allocations = node;
		}

		memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
	}

	// sort the allocs array in descending order
	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	// get min of allocs we stored vs the top N requested stacks
	nr_allocs_to_show =
		nr_allocs < (size_t)env.top_stacks ? nr_allocs : env.top_stacks;

	printf(
		"[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec,
		nr_allocs_to_show
	);

	print_stack_frames(allocs, nr_allocs_to_show, stack_traces_fd);

cleanup:
	// Reset allocs list so that we dont accidentaly reuse data the next time we
	// call this function
	for (size_t i = 0; i < nr_allocs; i++)
	{
		allocs[i].stack_id = 0;
		if (env.show_allocs)
		{
			struct allocation_node *it = allocs[i].allocations;
			while (it != NULL)
			{
				struct allocation_node *tmp = it;
				it = it->next;
				free(tmp);
			}
			allocs[i].allocations = NULL;
		}
	}

	return ret;
}

int print_outstanding_combined_allocs(
	int combined_allocs_fd,
	int stack_traces_fd
)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	size_t nr_allocs = 0;

	// for each stack_id "curr_key" and union combined_alloc_info "alloc"
	// in bpf_map "combined_allocs"
	for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key)
	{
		union combined_alloc_info combined_alloc_info;
		memset(&combined_alloc_info, 0, sizeof(combined_alloc_info));

		if (bpf_map_get_next_key(combined_allocs_fd, &prev_key, &curr_key))
		{
			if (errno == ENOENT)
			{
				break; // no more keys, done
			}

			perror("map get next key error");

			return -errno;
		}

		if (bpf_map_lookup_elem(
				combined_allocs_fd,
				&curr_key,
				&combined_alloc_info
			))
		{
			if (errno == ENOENT)
			{
				continue;
			}

			perror("map lookup error");
			return -errno;
		}

		const struct allocation alloc = {
			.stack_id = curr_key,
			.size = combined_alloc_info.total_size,
			.count = combined_alloc_info.number_of_allocs,
			.allocations = NULL
		};

		memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
	}

	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	// get min of allocs we stored vs the top N requested stacks
	nr_allocs = nr_allocs < (size_t)env.top_stacks ? nr_allocs : env.top_stacks;

	printf(
		"[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec,
		nr_allocs
	);

	print_stack_frames(allocs, nr_allocs, stack_traces_fd);

	return 0;
}
