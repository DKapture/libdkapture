// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "dkapture.h"
#include "Kcom.h"

const volatile bool targ_dist = false;
const volatile bool targ_ns = false;

static struct irq_event_t zero = {};

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct irq_event_t);
} start SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} irq_map SEC(".maps");

__u64 counts[NR_SOFTIRQS] = {};
__u64 time[NR_SOFTIRQS] = {};

SEC("tracepoint/irq/softirq_raise")
int softirq_raise(struct trace_event_raw_softirq *ctx)
{
	return 0;
}

SEC("tracepoint/irq/softirq_entry")
int softirq_entry(struct trace_event_raw_softirq *ctx)
{
	int key = 0;
	long ret;
	struct soft_irq_event_t *irq_event;
	ret = bpf_map_update_elem(&start, &key, &zero, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem err: %ld", ret);
		return 0;
	}
	irq_event = bpf_map_lookup_elem(&start, &key);
	if (!irq_event)
	{
		bpf_err("bpf_map_lookup_elem err");
		return 0;
	}
	irq_event->type = SOFT_IRQ;
	irq_event->delta = bpf_ktime_get_ns();
	irq_event->vec_nr = ctx->vec;
	return 0;
}

SEC("tracepoint/irq/softirq_exit")
int softirq_exit(struct trace_event_raw_softirq *ctx)
{
	long ret;
	int key = 0;
	u64 pid_tgid;
	struct soft_irq_event_t *irq_event;
	irq_event = bpf_map_lookup_elem(&start, &key);
	if (!irq_event)
	{
		bpf_err("bpf_map_lookup_elem err");
		return 0;
	}
	irq_event->delta = bpf_ktime_get_ns() - irq_event->delta;
	pid_tgid = bpf_get_current_pid_tgid();
	irq_event->pid = pid_tgid >> 32;
	irq_event->tid = pid_tgid;
	bpf_get_current_comm(irq_event->comm, sizeof(irq_event->comm));
	ret = bpf_ringbuf_output(&irq_map, irq_event, sizeof(*irq_event), 0);
	if (ret)
	{
		bpf_err("bpf_ringbuf_output err: %ld", ret);
	}
	return 0;
}

SEC("tracepoint/irq/irq_handler_entry")
int irq_handler_entry(struct trace_event_raw_irq_handler_entry *ctx)
{
	int key = 0;
	long ret;
	char *buf;
	void *irq_name;
	struct irq_event_t *irq_event;
	ret = bpf_map_update_elem(&start, &key, &zero, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem err: %ld", ret);
		return 0;
	}
	irq_event = bpf_map_lookup_elem(&start, &key);
	if (!irq_event)
	{
		bpf_err("bpf_map_lookup_elem err");
		return 0;
	}
	irq_event->type = IRQ;
	irq_event->delta = bpf_ktime_get_ns();
	irq_event->vec_nr = ctx->irq;
	buf = irq_event->name;
	irq_name = (void *)ctx + (ctx->__data_loc_name & 0xffff);
	bpf_read_kstr(buf, sizeof(irq_event->name), irq_name);
	DEBUG(0, "=== %s", buf);
	return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int irq_handler_exit(struct trace_event_raw_irq_handler_exit *ctx)
{
	long ret;
	int key = 0;
	u64 pid_tgid;
	struct irq_event_t *irq_event;
	irq_event = bpf_map_lookup_elem(&start, &key);
	if (!irq_event)
	{
		bpf_err("bpf_map_lookup_elem err");
		return 0;
	}
	irq_event->delta = bpf_ktime_get_ns() - irq_event->delta;
	irq_event->ret = ctx->ret;
	pid_tgid = bpf_get_current_pid_tgid();
	irq_event->pid = pid_tgid >> 32;
	irq_event->tid = pid_tgid;
	bpf_get_current_comm(irq_event->comm, sizeof(irq_event->comm));
	ret = bpf_ringbuf_output(&irq_map, irq_event, sizeof(*irq_event), 0);
	if (ret)
	{
		bpf_err("bpf_ringbuf_output err: %ld", ret);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
