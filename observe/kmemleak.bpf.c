// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno.h>

#include "kmemleak.h"
#include "Kcom.h"

const volatile size_t min_size = 0;
const volatile size_t max_size = -1;
const volatile size_t page_size = 4096;
const volatile __u64 sample_rate = 1;
const volatile bool trace_all = false;
const volatile __u64 stack_flags = 0;
const volatile bool wa_missing_free = false;

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, pid_t);
	__uint(max_entries, 1);
} filter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* address */
	__type(value, struct alloc_info);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* stack id */
	__type(value, union combined_alloc_info);
	__uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps");

static union combined_alloc_info initial_cinfo;

struct RuleCallBckCtx
{
	pid_t pid;
	int ret;
};

static long rule_filter_callback(
	struct bpf_map *map,
	const void *key,
	void *value,
	void *ctx
)
{
	struct RuleCallBckCtx *cbctx;
	cbctx = (struct RuleCallBckCtx *)ctx;
	pid_t pid = cbctx->pid;
	pid_t fpid = *(pid_t *)value;
	cbctx->ret = fpid == 0 ? 1 : pid == fpid;
	return cbctx->ret;
}

static int rule_filter(pid_t pid)
{
	long ret = 0;
	struct RuleCallBckCtx ctx;
	ctx.pid = pid;
	ret = bpf_for_each_map_elem(&filter, rule_filter_callback, &ctx, 0);
	if (ret < 0)
	{
		bpf_printk("error: bpf_for_each_map_elem: %ld", ret);
		return 0;
	}
	return ctx.ret;
}

static int filter_pid(void)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (rule_filter(pid))
	{
		DEBUG(0, "filtered by rule, pid = %d", pid);
		return 1;
	}
	return 0;
}

static void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	int err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
	{
		return val;
	}

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -EEXIST)
	{
		return 0;
	}

	return bpf_map_lookup_elem(map, key);
}

static void update_statistics_add(u64 stack_id, u64 sz)
{
	union combined_alloc_info *existing_cinfo;

	existing_cinfo =
		bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
	if (!existing_cinfo)
	{
		return;
	}

	const union combined_alloc_info incremental_cinfo = {
		.total_size = sz,
		.number_of_allocs = 1
	};

	__sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}

static void update_statistics_del(u64 stack_id, u64 sz)
{
	union combined_alloc_info *existing_cinfo;

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (!existing_cinfo)
	{
		bpf_printk("failed to lookup combined allocs\n");

		return;
	}

	const union combined_alloc_info decremental_cinfo = {
		.total_size = sz,
		.number_of_allocs = 1
	};

	__sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}

static int trace_alloc(size_t size, void *ctx, u64 address)
{
	struct alloc_info info;
	if (size < min_size || size > max_size)
	{
		return 0;
	}

	if (sample_rate > 1)
	{
		if (bpf_ktime_get_ns() % sample_rate != 0)
		{
			return 0;
		}
	}

	__builtin_memset(&info, 0, sizeof(info));

	info.size = size;

	if (address != 0)
	{
		info.timestamp_ns = bpf_ktime_get_ns();
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);
		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
		update_statistics_add(info.stack_id, info.size);
	}

	if (trace_all)
	{
		bpf_printk(
			"alloc exited, size = %lu, result = %lx\n",
			info.size,
			address
		);
	}

	return 0;
}

static int trace_free_enter(const void *address)
{
	const u64 addr = (u64)address;

	const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info)
	{
		return 0;
	}

	bpf_map_delete_elem(&allocs, &addr);
	update_statistics_del(info->stack_id, info->size);

	if (trace_all)
	{
		bpf_printk(
			"free entered, address = %lx, size = %lu\n",
			address,
			info->size
		);
	}

	return 0;
}

SEC("tracepoint/kmem/kmalloc")
int tp_kmalloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (!filter_pid())
	{
		return 0;
	}

	struct trace_event_raw_kmalloc *args = ctx;
	ptr = BPF_CORE_READ(args, ptr);
	bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

	if (wa_missing_free)
	{
		trace_free_enter(ptr);
	}

	return trace_alloc(bytes_alloc, ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kfree")
int tp_kfree(void *ctx)
{
	const void *ptr;

	if (!filter_pid())
	{
		return 0;
	}

	struct trace_event_raw_kfree *args = ctx;
	ptr = BPF_CORE_READ(args, ptr);

	return trace_free_enter(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int tp_kmem_cache_alloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (!filter_pid())
	{
		return 0;
	}

	struct trace_event_raw_kmem_cache_alloc *args = ctx;
	ptr = BPF_CORE_READ(args, ptr);
	bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

	if (wa_missing_free)
	{
		trace_free_enter(ptr);
	}

	return trace_alloc(bytes_alloc, ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_free")
int tp_kmem_cache_free(void *ctx)
{
	const void *ptr;

	if (!filter_pid())
	{
		return 0;
	}

	struct trace_event_raw_kmem_cache_free *args = ctx;
	ptr = BPF_CORE_READ(args, ptr);

	return trace_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int tp_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	if (!filter_pid())
	{
		return 0;
	}
	return trace_alloc(page_size << ctx->order, ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int tp_mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	if (!filter_pid())
	{
		return 0;
	}
	return trace_free_enter((void *)ctx->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int tp_percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx)
{
	if (!filter_pid())
	{
		return 0;
	}
	return trace_alloc(ctx->bytes_alloc, ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/percpu/percpu_free_percpu")
int tp_percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx)
{
	if (!filter_pid())
	{
		return 0;
	}
	return trace_free_enter(ctx->ptr);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
