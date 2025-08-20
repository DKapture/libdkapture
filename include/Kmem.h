#ifndef __MEM_POOL_H
#define __MEM_POOL_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "Kcom.h"

static char __page[PAGE_SIZE] = {0};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, typeof(__page));
	__uint(max_entries, 10240); // 40 MB
} __pages SEC(".maps");

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wunused-function\"")

/**
 * malloc_page and free_page must be called in pair in the same ebpf program
 * context
 */
static char *malloc_page(u32 key)
{
	long ret;
	pid_t pid;
	pid = bpf_get_current_pid_tgid();
	u64 _key = (u64)pid << 32 | key;

	ret = bpf_map_update_elem(&__pages, &_key, __page, BPF_NOEXIST);
	if (ret != 0)
	{
		bpf_printk("error: bpf_map_update_elem: %ld", ret);
		return NULL;
	}

	char *page = bpf_map_lookup_elem(&__pages, &_key);
	return page;
}

/**
 * lookup the malloced page by key
 */
static char *lookup_page(u32 key)
{
	pid_t pid;
	pid = bpf_get_current_pid_tgid();
	u64 _key = (u64)pid << 32 | key;

	char *page = bpf_map_lookup_elem(&__pages, &_key);
	return page;
}

/**
 * malloc_page and free_page must be called in pair in the same ebpf program
 * context
 */
static void free_page(u32 key)
{
	long ret;
	pid_t pid;
	pid = bpf_get_current_pid_tgid(); // Get current PID
	u64 _key = (u64)pid << 32 | key;

	// Delete the log entry from the log buffer
	ret = bpf_map_delete_elem(&__pages, &_key);
	if (ret != 0)
	{
		bpf_printk("error: bpf_map_delete_elem: %ld", ret);
	}
}

_Pragma("GCC diagnostic pop")

#endif