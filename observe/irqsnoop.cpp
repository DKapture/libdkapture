// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on softirq(8) from BCC by Brendan Gregg & Sasha Goldshtein.
// 15-Aug-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <thread>

#include "irqsnoop.skel.h"
#include "dkapture.h"

static struct ring_buffer *rb = NULL;
static struct irqsnoop_bpf *obj = NULL;
#ifdef BUILTIN
static std::thread *rb_thread = nullptr;
#endif

struct env
{
	bool distributed;
	bool nanoseconds;
	bool count;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
} env = {
	.count = false,
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;
const char argp_program_doc[] =
	"Summarize soft irq event time as histograms.\n"
	"\n"
	"USAGE: irqsnoop [--help] [-T] [-N] [-d] [interval] [count]\n"
	"\n"
	"EXAMPLES:\n"
	"    irqsnoop            # sum soft irq event time\n"
	"    irqsnoop -d         # show soft irq event time as histograms\n"
	"    irqsnoop 1 10       # print 1 second summaries, 10 times\n"
	"    irqsnoop -NT 1      # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
	{ "distributed", 'd', NULL, 0, "Show distributions as histograms", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds", 0 },
	{ "count", 'C', NULL, 0, "Show event counts with timing", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
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
	case 'd':
		env.distributed = true;
		break;
	case 'N':
		env.nanoseconds = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'C':
		env.count = true;
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

#ifndef BUILTIN

static const char *vec_names[] = {
	[HI_SOFTIRQ] = "hi",	       [TIMER_SOFTIRQ] = "timer",
	[NET_TX_SOFTIRQ] = "net_tx",   [NET_RX_SOFTIRQ] = "net_rx",
	[BLOCK_SOFTIRQ] = "block",     [IRQ_POLL_SOFTIRQ] = "irq_poll",
	[TASKLET_SOFTIRQ] = "tasklet", [SCHED_SOFTIRQ] = "sched",
	[HRTIMER_SOFTIRQ] = "hrtimer", [RCU_SOFTIRQ] = "rcu",
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct irq_event_t *e = (struct irq_event_t *)data;
	if (e->pid == 0)
		return 0;
	// 只处理IRQ类型事件
	if (e->type == IRQ)
	{
		printf("[IRQ] pid=%d tid=%d comm=%s irq=%d name=%s delta=%lluns ret=%d\n",
		       e->pid, e->tid, e->comm, e->vec_nr, e->name, e->delta,
		       e->ret);
	}
	else if (e->type == SOFT_IRQ)
	{
		printf("[SOFTIRQ] pid=%d tid=%d comm=%s vec=%s delta=%lluns ret=%d\n",
		       e->pid, e->tid, e->comm, vec_names[e->vec_nr], e->delta,
		       e->ret);
	}
	return 0;
}
#endif

void ringbuffer_worker(void)
{
	int err;
	while (!exiting && --env.times != 0)
	{
		err = ring_buffer__poll(rb, 500);
		if (err < 0 && err != -EINTR)
		{
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}
}

#ifdef BUILTIN
int irqsnoop_deinit(void)
{
	exiting = true;
	if (rb_thread)
	{
		rb_thread->join();
		delete rb_thread;
		rb_thread = nullptr;
	}
	if (rb)
	{
		ring_buffer__free(rb);
		rb = nullptr;
	}
	if (obj)
	{
		irqsnoop_bpf__destroy(obj);
		obj = nullptr;
	}
	return 0;
}
int irqsnoop_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx)
#else
int main(int argc, char **argv)
#endif
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	int err;

	exiting = false;
	signal(SIGINT, sig_handler);
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = irqsnoop_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_dist = env.distributed;
	obj->rodata->targ_ns = env.nanoseconds;

	err = irqsnoop_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (!obj->bss)
	{
		fprintf(stderr, "Memory-mapping BPF maps is supported "
				"starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = irqsnoop_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

#ifdef BUILTIN
	rb = ring_buffer__new(bpf_map__fd(obj->maps.irq_map),
			      (ring_buffer_sample_fn)cb, ctx, NULL);
#else
	rb = ring_buffer__new(bpf_map__fd(obj->maps.irq_map), handle_event,
			      NULL, NULL);
#endif
	if (!rb)
	{
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

#ifdef BUILTIN
	rb_thread = new std::thread(ringbuffer_worker);
	return 0;
#endif

	printf("Tracing IRQ/SoftIRQ events... Hit Ctrl-C to end.\n");
	ringbuffer_worker();

cleanup:
	if (rb)
		ring_buffer__free(rb);
	irqsnoop_bpf__destroy(obj);

	return err != 0;
}
