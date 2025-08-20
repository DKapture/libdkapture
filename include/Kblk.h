#pragma once

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wunused-function\"")
/**
 * commit d152c682f03c ("block: add an explicit ->disk backpointer to the
 * request_queue") and commit f3fa33acca9f ("block: remove the ->rq_disk
 * field in struct request") make some changes to `struct request` and
 * `struct request_queue`. Now, to get the `struct gendisk *` field in a CO-RE
 * way, we need both `struct request` and `struct request_queue`.
 * see:
 *     https://github.com/torvalds/linux/commit/d152c682f03c
 *     https://github.com/torvalds/linux/commit/f3fa33acca9f
 */
struct request_queue___x
{
	struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x
{
	struct request_queue___x *q;
	struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

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