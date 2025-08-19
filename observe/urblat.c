// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on urblat(8) from BCC by Brendan Gregg.
// 15-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include "blk_types.h"
#include "urblat.h"
#include "urblat.skel.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static struct env
{
	char *disk;
	time_t interval;
	int times;
	bool timestamp;
	bool queued;
	bool per_disk;
	bool per_flag;
	bool milliseconds;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "urblat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Summarize block device I/O latency as a histogram.\n"
	"\n"
	"USAGE:urblat [--help] [-T] [-m] [-Q] [-D] [-F] [-d DISK] [-c CG] [interval] [count]\n"
	"\n"
	"EXAMPLES:\n"
	"   urblat              # summarize block I/O latency as a histogram\n"
	"   urblat 1 10         # print 1 second summaries, 10 times\n"
	"   urblat -mT 1        # 1s summaries, milliseconds, and timestamps\n"
	"   urblat -Q           # include OS queued time in I/O time\n"
	"   urblat -D           # show each disk device separately\n"
	"   urblat -F           # show I/O flags separately\n"
	"   urblat -d sdc       # Trace sdc only\n"
	"   urblat -c CG        # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram", 0 },
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time", 0 },
	{ "disk", 'D', NULL, 0, "Print a histogram per disk device", 0 },
	{ "flag", 'F', NULL, 0, "Print a histogram per set of I/O flags", 0 },
	{ "disk", 'd', "DISK", 0, "Trace this disk only", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0,
	  "Trace process in cgroup path", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'Q':
		env.queued = true;
		break;
	case 'D':
		env.per_disk = true;
		break;
	case 'F':
		env.per_flag = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > DISK_NAME_LEN)
		{
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0)
		{
			env.interval = strtol(arg, NULL, 10);
			if (errno)
			{
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		}
		else if (pos_args == 1)
		{
			env.times = strtol(arg, NULL, 10);
			if (errno)
			{
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		}
		else
		{
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_cmd_flags(int cmd_flags)
{
	static struct
	{
		int bit;
		const char *str;
	} flags[] = {
		{ REQ_NOWAIT, "NoWait-" },    { REQ_BACKGROUND, "Background-" },
		{ REQ_RAHEAD, "ReadAhead-" }, { REQ_PREFLUSH, "PreFlush-" },
		{ REQ_FUA, "FUA-" },	      { REQ_INTEGRITY, "Integrity-" },
		{ REQ_IDLE, "Idle-" },	      { REQ_NOMERGE, "NoMerge-" },
		{ REQ_PRIO, "Priority-" },    { REQ_META, "Metadata-" },
		{ REQ_SYNC, "Sync-" },
	};
	static const char *ops[] = {
		[REQ_OP_READ] = "Read",
		[REQ_OP_WRITE] = "Write",
		[REQ_OP_FLUSH] = "Flush",
		[REQ_OP_DISCARD] = "Discard",
		[REQ_OP_SECURE_ERASE] = "SecureErase",
		[REQ_OP_ZONE_RESET] = "ZoneReset",
		[REQ_OP_WRITE_SAME] = "WriteSame",
		[REQ_OP_ZONE_RESET_ALL] = "ZoneResetAll",
		[REQ_OP_WRITE_ZEROES] = "WriteZeroes",
		[REQ_OP_ZONE_OPEN] = "ZoneOpen",
		[REQ_OP_ZONE_CLOSE] = "ZoneClose",
		[REQ_OP_ZONE_FINISH] = "ZoneFinish",
		[REQ_OP_SCSI_IN] = "SCSIIn",
		[REQ_OP_SCSI_OUT] = "SCSIOut",
		[REQ_OP_DRV_IN] = "DrvIn",
		[REQ_OP_DRV_OUT] = "DrvOut",
	};
	int i;

	printf("flags = ");

	for (i = 0; i < ARRAY_SIZE(flags); i++)
	{
		if (cmd_flags & flags[i].bit)
			printf("%s", flags[i].str);
	}

	if ((cmd_flags & REQ_OP_MASK) < ARRAY_SIZE(ops))
		printf("%s", ops[cmd_flags & REQ_OP_MASK]);
	else
		printf("Unknown");
}

struct partitions
{
	struct partition *items;
	int sz;
};

static int partitions__add_partition(struct partitions *partitions,
				     const char *name, unsigned int dev)
{
	struct partition *partition;
	void *tmp;

	tmp = realloc(partitions->items,
		      (partitions->sz + 1) * sizeof(*partitions->items));
	if (!tmp)
		return -1;
	partitions->items = tmp;
	partition = &partitions->items[partitions->sz];
	partition->name = strdup(name);
	partition->dev = dev;
	partitions->sz++;

	return 0;
}

void partitions__free(struct partitions *partitions);
struct partitions *partitions__load(void)
{
	char part_name[DISK_NAME_LEN];
	unsigned int devmaj, devmin;
	unsigned long long nop;
	struct partitions *partitions;
	char buf[64];
	FILE *f;

	f = fopen("/proc/partitions", "r");
	if (!f)
		return NULL;

	partitions = calloc(1, sizeof(*partitions));
	if (!partitions)
		goto err_out;

	while (fgets(buf, sizeof(buf), f) != NULL)
	{
		/* skip heading */
		if (buf[0] != ' ' || buf[0] == '\n')
			continue;
		if (sscanf(buf, "%u %u %llu %s", &devmaj, &devmin, &nop,
			   part_name) != 4)
			goto err_out;
		if (partitions__add_partition(partitions, part_name,
					      MKDEV(devmaj, devmin)))
			goto err_out;
	}

	fclose(f);
	return partitions;

err_out:
	partitions__free(partitions);
	fclose(f);
	return NULL;
}

void partitions__free(struct partitions *partitions)
{
	int i;

	if (!partitions)
		return;

	for (i = 0; i < partitions->sz; i++)
		free(partitions->items[i].name);
	free(partitions->items);
	free(partitions);
}

const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev)
{
	int i;

	for (i = 0; i < partitions->sz; i++)
	{
		if (partitions->items[i].dev == dev)
			return &partitions->items[i];
	}

	return NULL;
}

const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name)
{
	int i;

	for (i = 0; i < partitions->sz; i++)
	{
		if (strcmp(partitions->items[i].name, name) == 0)
			return &partitions->items[i];
	}

	return NULL;
}

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int stars, width, i;

	for (i = 0; i < vals_size; i++)
	{
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
	       idx_max <= 32 ? 19 : 29, val_type);

	if (idx_max <= 32)
		stars = stars_max;
	else
		stars = stars_max / 2;

	for (i = 0; i <= idx_max; i++)
	{
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		val = vals[i];
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high,
		       val);
		print_stars(val, val_max, stars);
		printf("|\n");
	}
}

static int print_log2_hists(struct bpf_map *hists,
			    struct partitions *partitions)
{
	struct hist_key lookup_key = { .cmd_flags = -1 }, next_key;
	const char *units = env.milliseconds ? "msecs" : "usecs";
	const struct partition *partition;
	int err, fd = bpf_map__fd(hists);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
	{
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0)
		{
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_disk)
		{
			partition = partitions__get_by_dev(partitions,
							   next_key.dev);
			printf("\ndisk = %s\t",
			       partition ? partition->name : "Unknown");
		}
		if (env.per_flag)
			print_cmd_flags(next_key.cmd_flags);
		printf("\n");
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key.cmd_flags = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
	{
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0)
		{
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

bool probe_tp_btf(const char *name)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		    .expected_attach_type = BPF_TRACE_RAW_TP);
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K,
		  .dst_reg = BPF_REG_0,
		  .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	int fd, insn_cnt = sizeof(insns) / sizeof(struct bpf_insn);

	opts.attach_btf_id = libbpf_find_vmlinux_btf_id(name, BPF_TRACE_RAW_TP);
	fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", insns, insn_cnt,
			   &opts);
	if (fd >= 0)
		close(fd);
	return fd >= 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
/*
 * BTF has a func proto for each tracepoint, let's check it like
 *   typedef void (*btf_trace_block_rq_issue)(void *, struct request *);
 *
 * Actually it's a typedef for a pointer to the func proto.
 */
static bool has_block_rq_issue_single_arg(void)
{
	const struct btf *btf = btf__load_vmlinux_btf();
	const struct btf_type *t1, *t2, *t3;
	__s32 type_id;
	bool ret = true; // assuming recent kernels

	type_id = btf__find_by_name_kind(btf, "btf_trace_block_rq_issue",
					 BTF_KIND_TYPEDEF);
	if (type_id < 0)
		return false;

	t1 = btf__type_by_id(btf, type_id);
	if (t1 == NULL)
		return false;

	t2 = btf__type_by_id(btf, t1->type);
	if (t2 == NULL || !btf_is_ptr(t2))
		return false;

	t3 = btf__type_by_id(btf, t2->type);
	if (t3 && btf_is_func_proto(t3))
		ret = (btf_vlen(t3) == 2); // ctx + arg

	return ret;
}
#pragma GCC diagnostic pop

int main(int argc, char **argv)
{
	struct partitions *partitions = NULL;
	const struct partition *partition;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct urblat_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = urblat_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	partitions = partitions__load();
	if (!partitions)
	{
		fprintf(stderr, "failed to load partitions info\n");
		goto cleanup;
	}

	/* initialize global data (filtering options) */
	if (env.disk)
	{
		partition = partitions__get_by_name(partitions, env.disk);
		if (!partition)
		{
			fprintf(stderr, "invaild partition name: not exist\n");
			goto cleanup;
		}
		obj->rodata->filter_dev = true;
		obj->rodata->targ_dev = partition->dev;
	}
	obj->rodata->targ_per_disk = env.per_disk;
	obj->rodata->targ_per_flag = env.per_flag;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_queued = env.queued;
	obj->rodata->filter_cg = env.cg;
	// obj->rodata->targ_single = has_block_rq_issue_single_arg();

	// bpf_program__set_autoload(obj->progs.usb_submit_urb, false);
	// bpf_program__set_autoload(obj->progs.usb_kill_urb, false);

	// bpf_program__set_autoload(obj->progs.usb_submit_urb, true);
	// bpf_program__set_autoload(obj->progs.usb_kill_urb, true);

	err = urblat_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg)
	{
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0)
		{
			fprintf(stderr, "Failed opening Cgroup path: %s",
				env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY))
		{
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	err = urblat_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

	/* main: poll */
	while (1)
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

		err = print_log2_hists(obj->maps.hists, partitions);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	urblat_bpf__destroy(obj);
	partitions__free(partitions);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
