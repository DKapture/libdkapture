// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "urblat.h"

struct request_queue___x
{
	struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x
{
	struct request_queue___x *q;
	struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

_Pragma("GCC diagnostic push");
_Pragma("GCC diagnostic ignored \"-Wunused-function\"");
static __always_inline struct gendisk *get_disk(void *request)
{
	struct request___x *r = request;

	if (bpf_core_field_exists(r->rq_disk))
	{
		return BPF_CORE_READ(r, rq_disk);
	}
	return BPF_CORE_READ(r, q, disk);
}
_Pragma("GCC diagnostic pop")

#define MAX_ENTRIES 10240

extern int LINUX_KERNEL_VERSION __kconfig;

const volatile bool filter_cg = false;
const volatile bool targ_per_disk = false;
const volatile bool targ_per_flag = false;
const volatile bool targ_queued = false;
const volatile bool targ_ms = false;
const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;
const volatile bool targ_single = true;

struct
{
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct urb *);
	__type(value, u64);
} start SEC(".maps");

static struct hist initial_hist;

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static int handle_urb_complete(struct urb *urb)
{
	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist_key hkey = {};
	struct hist *histp;
	s64 delta;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
	{
		return 0;
	}

	tsp = bpf_map_lookup_elem(&start, &urb);
	if (!tsp)
	{
		return 0;
	}

	delta = (s64)(ts - *tsp);
	if (delta < 0)
	{
		goto cleanup;
	}

	// if (targ_per_disk) {
	// 	struct gendisk *disk = get_disk(urb);

	// 	hkey.dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
	// 				BPF_CORE_READ(disk, first_minor)) : 0;
	// }
	// if (targ_per_flag)
	// 	hkey.cmd_flags = BPF_CORE_READ(urb, cmd_flags);

	histp = bpf_map_lookup_elem(&hists, &hkey);
	if (!histp)
	{
		bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &hkey);
		if (!histp)
		{
			goto cleanup;
		}
	}

	if (targ_ms)
	{
		delta /= 1000000U;
	}
	else
	{
		delta /= 1000U;
	}
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
	{
		slot = MAX_SLOTS - 1;
	}
	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &urb);
	return 0;
}

static int __always_inline trace_urb_start(struct urb *urb)
{
	u64 ts;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
	{
		return 0;
	}

	// if (issue && targ_queued && BPF_CORE_READ(urb, q, elevator))
	// 	return 0;

	ts = bpf_ktime_get_ns();

	// if (filter_dev) {
	// 	struct gendisk *disk = get_disk(rq);
	// 	u32 dev;

	// 	dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
	// 			BPF_CORE_READ(disk, first_minor)) : 0;
	// 	if (targ_dev != dev)
	// 		return 0;
	// }
	bpf_map_update_elem(&start, &urb, &ts, 0);
	return 0;
}

static int handle_urb_submit(struct urb *urb)
{
	/**
	 * commit a54895fa (v5.11-rc1) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 */
	if (!targ_single)
	{
		return trace_urb_start(urb);
	}
	else
	{
		return trace_urb_start(urb);
	}
}

SEC("kprobe/usb_submit_urb")
int BPF_PROG(usb_submit_urb, struct urb *urb, gfp_t mem_flags)
{
	// bpf_printk("usb_submit_urb urb=%u\n",urb);
	bpf_printk("usb_submit_urb \n");

	return handle_urb_submit(urb);
}

SEC("kprobe/usb_free_urb")
int BPF_PROG(usb_free_urb, struct urb *urb)
{
	// bpf_printk("usb_kill_urb urb=%u\n",urb);
	bpf_printk("usb_free_urb \n");

	return handle_urb_complete(urb);
}

char LICENSE[] SEC("license") = "GPL";
