#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "btrfs-snoop.h"

#define MAX_ENTRIES 1000
#define MAX_EVENT_SIZE 10240
#define RINGBUF_SIZE (1024 * 256)

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, char[4096]);
} filter SEC(".maps");

struct tp___extent_writepage_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	unsigned long index;
	long nr_to_write;
	long pages_skipped;
	loff_t range_start;
	loff_t range_end;
	char for_kupdate;
	char for_reclaim;
	char range_cyclic;
	unsigned long writeback_index;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/__extent_writepage")
int tp___extent_writepage(struct tp___extent_writepage_t *ctx)
{
	struct btrfs_extent_writepage_event event = {};

	event.base.event_type = BTRFS_EXTENT_WRITEPAGE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.index = ctx->index;
	event.nr_to_write = ctx->nr_to_write;
	event.pages_skipped = ctx->pages_skipped;
	event.range_start = ctx->range_start;
	event.range_end = ctx->range_end;
	event.for_kupdate = ctx->for_kupdate;
	event.for_reclaim = ctx->for_reclaim;
	event.range_cyclic = ctx->range_cyclic;
	event.writeback_index = ctx->writeback_index;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_add_delayed_data_ref_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 num_bytes;
	int action;
	u64 parent;
	u64 ref_root;
	u64 owner;
	u64 offset;
	int type;
	u64 seq;
};

SEC("tracepoint/btrfs/add_delayed_data_ref")
int tp_add_delayed_data_ref(struct tp_add_delayed_data_ref_t *ctx)
{
	struct btrfs_add_delayed_data_ref_event event = {};

	event.base.event_type = BTRFS_ADD_DELAYED_DATA_REF;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;
	event.action = ctx->action;
	event.parent = ctx->parent;
	event.ref_root = ctx->ref_root;
	event.owner = ctx->owner;
	event.offset = ctx->offset;
	event.type = ctx->type;
	event.seq = ctx->seq;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_add_delayed_ref_head_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 num_bytes;
	int action;
	int is_data;
};

SEC("tracepoint/btrfs/add_delayed_ref_head")
int tp_add_delayed_ref_head(struct tp_add_delayed_ref_head_t *ctx)
{
	struct btrfs_add_delayed_ref_head_event event = {};

	event.base.event_type = BTRFS_ADD_DELAYED_REF_HEAD;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;
	event.action = ctx->action;
	event.is_data = ctx->is_data;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_add_delayed_tree_ref_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 num_bytes;
	int action;
	u64 parent;
	u64 ref_root;
	int level;
	int type;
	u64 seq;
};

SEC("tracepoint/btrfs/add_delayed_tree_ref")
int tp_add_delayed_tree_ref(struct tp_add_delayed_tree_ref_t *ctx)
{
	struct btrfs_add_delayed_tree_ref_event event = {};

	event.base.event_type = BTRFS_ADD_DELAYED_TREE_REF;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;
	event.action = ctx->action;
	event.parent = ctx->parent;
	event.ref_root = ctx->ref_root;
	event.level = ctx->level;
	event.type = ctx->type;
	event.seq = ctx->seq;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct extent_state
{
	u64 start;
	u64 end;
	struct rb_node rb_node;
	wait_queue_head_t wq;
	refcount_t refs;
	u32 state;
};

struct tp_alloc_extent_state_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	const struct extent_state *state;
	unsigned long mask;
	const void *ip;
};

SEC("tracepoint/btrfs/alloc_extent_state")
int tp_alloc_extent_state(struct tp_alloc_extent_state_t *ctx)
{
	struct btrfs_alloc_extent_state_event event = {};

	event.base.event_type = BTRFS_ALLOC_EXTENT_STATE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	event.state = ctx->state->state;
	event.mask = ctx->mask;
	event.ip = (unsigned long)ctx->ip;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_add_block_group_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 offset;
	u64 size;
	u64 flags;
	u64 bytes_used;
	u64 bytes_super;
	int create;
};

SEC("tracepoint/btrfs/btrfs_add_block_group")
int tp_btrfs_add_block_group(struct tp_btrfs_add_block_group_t *ctx)
{
	struct btrfs_add_block_group_event event = {};

	event.base.event_type = BTRFS_ADD_BLOCK_GROUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.offset = ctx->offset;
	event.size = ctx->size;
	event.flags = ctx->flags;
	event.bytes_used = ctx->bytes_used;
	event.bytes_super = ctx->bytes_super;
	event.create = ctx->create;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_add_reclaim_block_group_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 len;
	u64 used;
	u64 flags;
};

SEC("tracepoint/btrfs/btrfs_add_reclaim_block_group")
int tp_btrfs_add_reclaim_block_group(
	struct tp_btrfs_add_reclaim_block_group_t *ctx
)
{
	struct btrfs_add_reclaim_block_group_event event = {};

	event.base.event_type = BTRFS_ADD_RECLAIM_BLOCK_GROUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.len = ctx->len;
	event.used = ctx->used;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_add_unused_block_group_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 len;
	u64 used;
	u64 flags;
};

SEC("tracepoint/btrfs/btrfs_add_unused_block_group")
int tp_btrfs_add_unused_block_group(
	struct tp_btrfs_add_unused_block_group_t *ctx
)
{
	struct btrfs_add_unused_block_group_event event = {};

	event.base.event_type = BTRFS_ADD_UNUSED_BLOCK_GROUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.len = ctx->len;
	event.used = ctx->used;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_all_work_done_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	const void *wtag;
};

SEC("tracepoint/btrfs/btrfs_all_work_done")
int tp_btrfs_all_work_done(struct tp_btrfs_all_work_done_t *ctx)
{
	struct btrfs_all_work_done_event event = {};

	event.base.event_type = BTRFS_ALL_WORK_DONE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.wtag = ctx->wtag;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_chunk_alloc_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	int num_stripes;
	u64 type;
	int sub_stripes;
	u64 offset;
	u64 size;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_chunk_alloc")
int tp_btrfs_chunk_alloc(struct tp_btrfs_chunk_alloc_t *ctx)
{
	struct btrfs_chunk_alloc_event event = {};

	event.base.event_type = BTRFS_CHUNK_ALLOC;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.num_stripes = ctx->num_stripes;
	event.type = ctx->type;
	event.sub_stripes = ctx->sub_stripes;
	event.offset = ctx->offset;
	event.size = ctx->size;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_chunk_free_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	int num_stripes;
	u64 type;
	int sub_stripes;
	u64 offset;
	u64 size;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_chunk_free")
int tp_btrfs_chunk_free(struct tp_btrfs_chunk_free_t *ctx)
{
	struct btrfs_chunk_free_event event = {};

	event.base.event_type = BTRFS_CHUNK_FREE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.num_stripes = ctx->num_stripes;
	event.type = ctx->type;
	event.sub_stripes = ctx->sub_stripes;
	event.offset = ctx->offset;
	event.size = ctx->size;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_clear_extent_bit_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	unsigned owner;
	u64 ino;
	u64 rootid;
	u64 start;
	u64 len;
	unsigned clear_bits;
};

SEC("tracepoint/btrfs/btrfs_clear_extent_bit")
int tp_btrfs_clear_extent_bit(struct tp_btrfs_clear_extent_bit_t *ctx)
{
	struct btrfs_clear_extent_bit_event event = {};

	event.base.event_type = BTRFS_CLEAR_EXTENT_BIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.owner = ctx->owner;
	event.ino = ctx->ino;
	event.rootid = ctx->rootid;
	event.start = ctx->start;
	event.len = ctx->len;
	event.clear_bits = ctx->clear_bits;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_convert_extent_bit_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	unsigned owner;
	u64 ino;
	u64 rootid;
	u64 start;
	u64 len;
	unsigned set_bits;
	unsigned clear_bits;
};

SEC("tracepoint/btrfs/btrfs_convert_extent_bit")
int tp_btrfs_convert_extent_bit(struct tp_btrfs_convert_extent_bit_t *ctx)
{
	struct btrfs_convert_extent_bit_event event = {};

	event.base.event_type = BTRFS_CONVERT_EXTENT_BIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.owner = ctx->owner;
	event.ino = ctx->ino;
	event.rootid = ctx->rootid;
	event.start = ctx->start;
	event.len = ctx->len;
	event.set_bits = ctx->set_bits;
	event.clear_bits = ctx->clear_bits;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_cow_block_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_objectid;
	u64 buf_start;
	int refs;
	u64 cow_start;
	int buf_level;
	int cow_level;
};

SEC("tracepoint/btrfs/btrfs_cow_block")
int tp_btrfs_cow_block(struct tp_btrfs_cow_block_t *ctx)
{
	struct btrfs_cow_block_event event = {};

	event.base.event_type = BTRFS_COW_BLOCK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_objectid = ctx->root_objectid;
	event.buf_start = ctx->buf_start;
	event.refs = ctx->refs;
	event.cow_start = ctx->cow_start;
	event.buf_level = ctx->buf_level;
	event.cow_level = ctx->cow_level;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_done_preemptive_reclaim_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 flags;
	u64 total_bytes;
	u64 bytes_used;
	u64 bytes_pinned;
	u64 bytes_reserved;
	u64 bytes_may_use;
	u64 bytes_readonly;
	u64 reclaim_size;
	int clamp;
	u64 global_reserved;
	u64 trans_reserved;
	u64 delayed_refs_reserved;
	u64 delayed_reserved;
	u64 free_chunk_space;
	u64 delalloc_bytes;
	u64 ordered_bytes;
};

SEC("tracepoint/btrfs/btrfs_done_preemptive_reclaim")
int tp_btrfs_done_preemptive_reclaim(
	struct tp_btrfs_done_preemptive_reclaim_t *ctx
)
{
	struct btrfs_done_preemptive_reclaim_event event = {};

	event.base.event_type = BTRFS_DONE_PREEMPTIVE_RECLAIM;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.flags = ctx->flags;
	event.total_bytes = ctx->total_bytes;
	event.bytes_used = ctx->bytes_used;
	event.bytes_pinned = ctx->bytes_pinned;
	event.bytes_reserved = ctx->bytes_reserved;
	event.bytes_may_use = ctx->bytes_may_use;
	event.bytes_readonly = ctx->bytes_readonly;
	event.reclaim_size = ctx->reclaim_size;
	event.clamp = ctx->clamp;
	event.global_reserved = ctx->global_reserved;
	event.trans_reserved = ctx->trans_reserved;
	event.delayed_refs_reserved = ctx->delayed_refs_reserved;
	event.delayed_reserved = ctx->delayed_reserved;
	event.free_chunk_space = ctx->free_chunk_space;
	event.delalloc_bytes = ctx->delalloc_bytes;
	event.ordered_bytes = ctx->ordered_bytes;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_fail_all_tickets_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 flags;
	u64 total_bytes;
	u64 bytes_used;
	u64 bytes_pinned;
	u64 bytes_reserved;
	u64 bytes_may_use;
	u64 bytes_readonly;
	u64 reclaim_size;
	int clamp;
	u64 global_reserved;
	u64 trans_reserved;
	u64 delayed_refs_reserved;
	u64 delayed_reserved;
	u64 free_chunk_space;
	u64 delalloc_bytes;
	u64 ordered_bytes;
};

SEC("tracepoint/btrfs/btrfs_fail_all_tickets")
int tp_btrfs_fail_all_tickets(struct tp_btrfs_fail_all_tickets_t *ctx)
{
	struct btrfs_fail_all_tickets_event event = {};

	event.base.event_type = BTRFS_FAIL_ALL_TICKETS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.flags = ctx->flags;
	event.total_bytes = ctx->total_bytes;
	event.bytes_used = ctx->bytes_used;
	event.bytes_pinned = ctx->bytes_pinned;
	event.bytes_reserved = ctx->bytes_reserved;
	event.bytes_may_use = ctx->bytes_may_use;
	event.bytes_readonly = ctx->bytes_readonly;
	event.reclaim_size = ctx->reclaim_size;
	event.clamp = ctx->clamp;
	event.global_reserved = ctx->global_reserved;
	event.trans_reserved = ctx->trans_reserved;
	event.delayed_refs_reserved = ctx->delayed_refs_reserved;
	event.delayed_reserved = ctx->delayed_reserved;
	event.free_chunk_space = ctx->free_chunk_space;
	event.delalloc_bytes = ctx->delalloc_bytes;
	event.ordered_bytes = ctx->ordered_bytes;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_failed_cluster_setup_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bg_objectid;
};

SEC("tracepoint/btrfs/btrfs_failed_cluster_setup")
int tp_btrfs_failed_cluster_setup(struct tp_btrfs_failed_cluster_setup_t *ctx)
{
	struct btrfs_failed_cluster_setup_event event = {};

	event.base.event_type = BTRFS_FAILED_CLUSTER_SETUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bg_objectid = ctx->bg_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_find_cluster_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bg_objectid;
	u64 flags;
	u64 start;
	u64 bytes;
	u64 empty_size;
	u64 min_bytes;
};

SEC("tracepoint/btrfs/btrfs_find_cluster")
int tp_btrfs_find_cluster(struct tp_btrfs_find_cluster_t *ctx)
{
	struct btrfs_find_cluster_event event = {};

	event.base.event_type = BTRFS_FIND_CLUSTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bg_objectid = ctx->bg_objectid;
	event.flags = ctx->flags;
	event.start = ctx->start;
	event.bytes = ctx->bytes;
	event.empty_size = ctx->empty_size;
	event.min_bytes = ctx->min_bytes;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_finish_ordered_extent_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 start;
	u64 len;
	bool uptodate;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_finish_ordered_extent")
int tp_btrfs_finish_ordered_extent(struct tp_btrfs_finish_ordered_extent_t *ctx)
{
	struct btrfs_finish_ordered_extent_event event = {};

	event.base.event_type = BTRFS_FINISH_ORDERED_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.start = ctx->start;
	event.len = ctx->len;
	event.uptodate = ctx->uptodate;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_flush_space_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 flags;
	u64 num_bytes;
	int state;
	int ret;
	bool for_preempt;
};

SEC("tracepoint/btrfs/btrfs_flush_space")
int tp_btrfs_flush_space(struct tp_btrfs_flush_space_t *ctx)
{
	struct btrfs_flush_space_event event = {};

	event.base.event_type = BTRFS_FLUSH_SPACE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.flags = ctx->flags;
	event.num_bytes = ctx->num_bytes;
	event.state = ctx->state;
	event.ret = ctx->ret;
	event.for_preempt = ctx->for_preempt;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_get_extent_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_objectid;
	u64 ino;
	u64 start;
	u64 len;
	u64 orig_start;
	u64 block_start;
	u64 block_len;
	unsigned long flags;
	int refs;
	unsigned int compress_type;
};

SEC("tracepoint/btrfs/btrfs_get_extent")
int tp_btrfs_get_extent(struct tp_btrfs_get_extent_t *ctx)
{
	struct btrfs_get_extent_event event = {};

	event.base.event_type = BTRFS_GET_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_objectid = ctx->root_objectid;
	event.ino = ctx->ino;
	event.start = ctx->start;
	event.len = ctx->len;
	event.orig_start = ctx->orig_start;
	event.block_start = ctx->block_start;
	event.block_len = ctx->block_len;
	event.flags = ctx->flags;
	event.refs = ctx->refs;
	event.compress_type = ctx->compress_type;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_get_extent_show_fi_inline_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_obj;
	u64 ino;
	loff_t isize;
	u64 disk_isize;
	u8 extent_type;
	u8 compression;
	u64 extent_start;
	u64 extent_end;
};

SEC("tracepoint/btrfs/btrfs_get_extent_show_fi_inline")
int tp_btrfs_get_extent_show_fi_inline(
	struct tp_btrfs_get_extent_show_fi_inline_t *ctx
)
{
	struct btrfs_get_extent_show_fi_inline_event event = {};

	event.base.event_type = BTRFS_GET_EXTENT_SHOW_FI_INLINE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_obj = ctx->root_obj;
	event.ino = ctx->ino;
	event.isize = ctx->isize;
	event.disk_isize = ctx->disk_isize;
	event.extent_type = ctx->extent_type;
	event.compression = ctx->compression;
	event.extent_start = ctx->extent_start;
	event.extent_end = ctx->extent_end;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_get_extent_show_fi_regular_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_obj;
	u64 ino;
	loff_t isize;
	u64 disk_isize;
	u64 num_bytes;
	u64 ram_bytes;
	u64 disk_bytenr;
	u64 disk_num_bytes;
	u64 extent_offset;
	u8 extent_type;
	u8 compression;
	u64 extent_start;
	u64 extent_end;
};

SEC("tracepoint/btrfs/btrfs_get_extent_show_fi_regular")
int tp_btrfs_get_extent_show_fi_regular(
	struct tp_btrfs_get_extent_show_fi_regular_t *ctx
)
{
	struct btrfs_get_extent_show_fi_regular_event event = {};

	event.base.event_type = BTRFS_GET_EXTENT_SHOW_FI_REGULAR;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_obj = ctx->root_obj;
	event.ino = ctx->ino;
	event.isize = ctx->isize;
	event.disk_isize = ctx->disk_isize;
	event.num_bytes = ctx->num_bytes;
	event.ram_bytes = ctx->ram_bytes;
	event.disk_bytenr = ctx->disk_bytenr;
	event.disk_num_bytes = ctx->disk_num_bytes;
	event.extent_offset = ctx->extent_offset;
	event.extent_type = ctx->extent_type;
	event.compression = ctx->compression;
	event.extent_start = ctx->extent_start;
	event.extent_end = ctx->extent_end;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_handle_em_exist_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 e_start;
	u64 e_len;
	u64 map_start;
	u64 map_len;
	u64 start;
	u64 len;
};

SEC("tracepoint/btrfs/btrfs_handle_em_exist")
int tp_btrfs_handle_em_exist(struct tp_btrfs_handle_em_exist_t *ctx)
{
	struct btrfs_handle_em_exist_event event = {};

	event.base.event_type = BTRFS_HANDLE_EM_EXIST;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.e_start = ctx->e_start;
	event.e_len = ctx->e_len;
	event.map_start = ctx->map_start;
	event.map_len = ctx->map_len;
	event.start = ctx->start;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_inode_evict_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 blocks;
	u64 disk_i_size;
	u64 generation;
	u64 last_trans;
	u64 logged_trans;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_inode_evict")
int tp_btrfs_inode_evict(struct tp_btrfs_inode_evict_t *ctx)
{
	struct btrfs_inode_evict_event event = {};

	event.base.event_type = BTRFS_INODE_EVICT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.blocks = ctx->blocks;
	event.disk_i_size = ctx->disk_i_size;
	event.generation = ctx->generation;
	event.last_trans = ctx->last_trans;
	event.logged_trans = ctx->logged_trans;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_inode_mod_outstanding_extents_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_objectid;
	u64 ino;
	int mod;
	unsigned outstanding;
};

SEC("tracepoint/btrfs/btrfs_inode_mod_outstanding_extents")
int tp_btrfs_inode_mod_outstanding_extents(
	struct tp_btrfs_inode_mod_outstanding_extents_t *ctx
)
{
	struct btrfs_inode_mod_outstanding_extents_event event = {};

	event.base.event_type = BTRFS_INODE_MOD_OUTSTANDING_EXTENTS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_objectid = ctx->root_objectid;
	event.ino = ctx->ino;
	event.mod = ctx->mod;
	event.outstanding = ctx->outstanding;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_inode_new_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 blocks;
	u64 disk_i_size;
	u64 generation;
	u64 last_trans;
	u64 logged_trans;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_inode_new")
int tp_btrfs_inode_new(struct tp_btrfs_inode_new_t *ctx)
{
	struct btrfs_inode_new_event event = {};

	event.base.event_type = BTRFS_INODE_NEW;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.blocks = ctx->blocks;
	event.disk_i_size = ctx->disk_i_size;
	event.generation = ctx->generation;
	event.last_trans = ctx->last_trans;
	event.logged_trans = ctx->logged_trans;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_inode_request_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 blocks;
	u64 disk_i_size;
	u64 generation;
	u64 last_trans;
	u64 logged_trans;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_inode_request")
int tp_btrfs_inode_request(struct tp_btrfs_inode_request_t *ctx)
{
	struct btrfs_inode_request_event event = {};

	event.base.event_type = BTRFS_INODE_REQUEST;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.blocks = ctx->blocks;
	event.disk_i_size = ctx->disk_i_size;
	event.generation = ctx->generation;
	event.last_trans = ctx->last_trans;
	event.logged_trans = ctx->logged_trans;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_add_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_add")
int tp_btrfs_ordered_extent_add(struct tp_btrfs_ordered_extent_add_t *ctx)
{
	struct btrfs_ordered_extent_add_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_ADD;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_dec_test_pending_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_dec_test_pending")
int tp_btrfs_ordered_extent_dec_test_pending(
	struct tp_btrfs_ordered_extent_dec_test_pending_t *ctx
)
{
	struct btrfs_ordered_extent_dec_test_pending_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_DEC_TEST_PENDING;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_lookup_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_lookup")
int tp_btrfs_ordered_extent_lookup(struct tp_btrfs_ordered_extent_lookup_t *ctx)
{
	struct btrfs_ordered_extent_lookup_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_LOOKUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_lookup_first_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_lookup_first")
int tp_btrfs_ordered_extent_lookup_first(
	struct tp_btrfs_ordered_extent_lookup_first_t *ctx
)
{
	struct btrfs_ordered_extent_lookup_first_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_LOOKUP_FIRST;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_lookup_first_range_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_lookup_first_range")
int tp_btrfs_ordered_extent_lookup_first_range(
	struct tp_btrfs_ordered_extent_lookup_first_range_t *ctx
)
{
	struct btrfs_ordered_extent_lookup_first_range_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_LOOKUP_FIRST_RANGE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_lookup_for_logging_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_lookup_for_logging")
int tp_btrfs_ordered_extent_lookup_for_logging(
	struct tp_btrfs_ordered_extent_lookup_for_logging_t *ctx
)
{
	struct btrfs_ordered_extent_lookup_for_logging_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_LOOKUP_FOR_LOGGING;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_lookup_range_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_lookup_range")
int tp_btrfs_ordered_extent_lookup_range(
	struct tp_btrfs_ordered_extent_lookup_range_t *ctx
)
{
	struct btrfs_ordered_extent_lookup_range_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_LOOKUP_RANGE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_mark_finished_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_mark_finished")
int tp_btrfs_ordered_extent_mark_finished(
	struct tp_btrfs_ordered_extent_mark_finished_t *ctx
)
{
	struct btrfs_ordered_extent_mark_finished_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_MARK_FINISHED;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_put_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_put")
int tp_btrfs_ordered_extent_put(struct tp_btrfs_ordered_extent_put_t *ctx)
{
	struct btrfs_ordered_extent_put_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_PUT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_remove_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_remove")
int tp_btrfs_ordered_extent_remove(struct tp_btrfs_ordered_extent_remove_t *ctx)
{
	struct btrfs_ordered_extent_remove_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_REMOVE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_split_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_split")
int tp_btrfs_ordered_extent_split(struct tp_btrfs_ordered_extent_split_t *ctx)
{
	struct btrfs_ordered_extent_split_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_SPLIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_extent_start_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 file_offset;
	u64 start;
	u64 len;
	u64 disk_len;
	u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	u64 root_objectid;
	u64 truncated_len;
};

SEC("tracepoint/btrfs/btrfs_ordered_extent_start")
int tp_btrfs_ordered_extent_start(struct tp_btrfs_ordered_extent_start_t *ctx)
{
	struct btrfs_ordered_extent_start_event event = {};

	event.base.event_type = BTRFS_ORDERED_EXTENT_START;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.file_offset = ctx->file_offset;
	event.start = ctx->start;
	event.len = ctx->len;
	event.disk_len = ctx->disk_len;
	event.bytes_left = ctx->bytes_left;
	event.flags = ctx->flags;
	event.compress_type = ctx->compress_type;
	event.refs = ctx->refs;
	event.root_objectid = ctx->root_objectid;
	event.truncated_len = ctx->truncated_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_ordered_sched_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	const void *work;
	const void *wq;
	const void *func;
	const void *ordered_func;
	const void *ordered_free;
	const void *normal_work;
};

SEC("tracepoint/btrfs/btrfs_ordered_sched")
int tp_btrfs_ordered_sched(struct tp_btrfs_ordered_sched_t *ctx)
{
	struct btrfs_ordered_sched_event event = {};

	event.base.event_type = BTRFS_ORDERED_SCHED;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	// No fsid in this tracepoint, leave as zeroed
	event.work = ctx->work;
	event.wq = ctx->wq;
	event.func = ctx->func;
	event.ordered_func = ctx->ordered_func;
	event.ordered_free = ctx->ordered_free;
	event.normal_work = ctx->normal_work;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_prelim_ref_insert_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_id;
	u64 objectid;
	u8 type;
	u64 offset;
	int level;
	int old_count;
	u64 parent;
	u64 bytenr;
	int mod_count;
	u64 tree_size;
};

SEC("tracepoint/btrfs/btrfs_prelim_ref_insert")
int tp_btrfs_prelim_ref_insert(struct tp_btrfs_prelim_ref_insert_t *ctx)
{
	struct btrfs_prelim_ref_insert_event event = {};

	event.base.event_type = BTRFS_PRELIM_REF_INSERT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_id = ctx->root_id;
	event.objectid = ctx->objectid;
	event.type = ctx->type;
	event.offset = ctx->offset;
	event.level = ctx->level;
	event.old_count = ctx->old_count;
	event.parent = ctx->parent;
	event.bytenr = ctx->bytenr;
	event.mod_count = ctx->mod_count;
	event.tree_size = ctx->tree_size;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_prelim_ref_merge_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_id;
	u64 objectid;
	u8 type;
	u64 offset;
	int level;
	int old_count;
	u64 parent;
	u64 bytenr;
	int mod_count;
	u64 tree_size;
};

SEC("tracepoint/btrfs/btrfs_prelim_ref_merge")
int tp_btrfs_prelim_ref_merge(struct tp_btrfs_prelim_ref_merge_t *ctx)
{
	struct btrfs_prelim_ref_merge_event event = {};

	event.base.event_type = BTRFS_PRELIM_REF_MERGE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_id = ctx->root_id;
	event.objectid = ctx->objectid;
	event.type = ctx->type;
	event.offset = ctx->offset;
	event.level = ctx->level;
	event.old_count = ctx->old_count;
	event.parent = ctx->parent;
	event.bytenr = ctx->bytenr;
	event.mod_count = ctx->mod_count;
	event.tree_size = ctx->tree_size;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_qgroup_account_extent_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 transid;
	u64 bytenr;
	u64 num_bytes;
	u64 nr_old_roots;
	u64 nr_new_roots;
};

SEC("tracepoint/btrfs/btrfs_qgroup_account_extent")
int tp_btrfs_qgroup_account_extent(struct tp_btrfs_qgroup_account_extent_t *ctx)
{
	struct btrfs_qgroup_account_extent_event event = {};

	event.base.event_type = BTRFS_QGROUP_ACCOUNT_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.transid = ctx->transid;
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;
	event.nr_old_roots = ctx->nr_old_roots;
	event.nr_new_roots = ctx->nr_new_roots;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_qgroup_account_extents_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 num_bytes;
};

SEC("tracepoint/btrfs/btrfs_qgroup_account_extents")
int tp_btrfs_qgroup_account_extents(
	struct tp_btrfs_qgroup_account_extents_t *ctx
)
{
	struct btrfs_qgroup_account_extents_event event = {};

	event.base.event_type = BTRFS_QGROUP_ACCOUNT_EXTENTS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_qgroup_release_data_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 rootid;
	u64 ino;
	u64 start;
	u64 len;
	u64 reserved;
	int op;
};

SEC("tracepoint/btrfs/btrfs_qgroup_release_data")
int tp_btrfs_qgroup_release_data(struct tp_btrfs_qgroup_release_data_t *ctx)
{
	struct btrfs_qgroup_release_data_event event = {};

	event.base.event_type = BTRFS_QGROUP_RELEASE_DATA;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.rootid = ctx->rootid;
	event.ino = ctx->ino;
	event.start = ctx->start;
	event.len = ctx->len;
	event.reserved = ctx->reserved;
	event.op = ctx->op;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_qgroup_reserve_data_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 rootid;
	u64 ino;
	u64 start;
	u64 len;
	u64 reserved;
	int op;
};

SEC("tracepoint/btrfs/btrfs_qgroup_reserve_data")
int tp_btrfs_qgroup_reserve_data(struct tp_btrfs_qgroup_reserve_data_t *ctx)
{
	struct btrfs_qgroup_reserve_data_event event = {};

	event.base.event_type = BTRFS_QGROUP_RESERVE_DATA;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.rootid = ctx->rootid;
	event.ino = ctx->ino;
	event.start = ctx->start;
	event.len = ctx->len;
	event.reserved = ctx->reserved;
	event.op = ctx->op;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_qgroup_trace_extent_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 num_bytes;
};

SEC("tracepoint/btrfs/btrfs_qgroup_trace_extent")
int tp_btrfs_qgroup_trace_extent(struct tp_btrfs_qgroup_trace_extent_t *ctx)
{
	struct btrfs_qgroup_trace_extent_event event = {};

	event.base.event_type = BTRFS_QGROUP_TRACE_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_reclaim_block_group_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 len;
	u64 used;
	u64 flags;
};

SEC("tracepoint/btrfs/btrfs_reclaim_block_group")
int tp_btrfs_reclaim_block_group(struct tp_btrfs_reclaim_block_group_t *ctx)
{
	struct btrfs_reclaim_block_group_event event = {};

	event.base.event_type = BTRFS_RECLAIM_BLOCK_GROUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.len = ctx->len;
	event.used = ctx->used;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_remove_block_group_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 len;
	u64 used;
	u64 flags;
};

SEC("tracepoint/btrfs/btrfs_remove_block_group")
int tp_btrfs_remove_block_group(struct tp_btrfs_remove_block_group_t *ctx)
{
	struct btrfs_remove_block_group_event event = {};

	event.base.event_type = BTRFS_REMOVE_BLOCK_GROUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.len = ctx->len;
	event.used = ctx->used;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_reserve_extent_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bg_objectid;
	u64 flags;
	int bg_size_class;
	u64 start;
	u64 len;
	u64 loop;
	bool hinted;
	int size_class;
};

SEC("tracepoint/btrfs/btrfs_reserve_extent")
int tp_btrfs_reserve_extent(struct tp_btrfs_reserve_extent_t *ctx)
{
	struct btrfs_reserve_extent_event event = {};

	event.base.event_type = BTRFS_RESERVE_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bg_objectid = ctx->bg_objectid;
	event.flags = ctx->flags;
	event.bg_size_class = ctx->bg_size_class;
	event.start = ctx->start;
	event.len = ctx->len;
	event.loop = ctx->loop;
	event.hinted = ctx->hinted;
	event.size_class = ctx->size_class;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_reserve_extent_cluster_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bg_objectid;
	u64 flags;
	int bg_size_class;
	u64 start;
	u64 len;
	u64 loop;
	bool hinted;
	int size_class;
};

SEC("tracepoint/btrfs/btrfs_reserve_extent_cluster")
int tp_btrfs_reserve_extent_cluster(
	struct tp_btrfs_reserve_extent_cluster_t *ctx
)
{
	struct btrfs_reserve_extent_cluster_event event = {};

	event.base.event_type = BTRFS_RESERVE_EXTENT_CLUSTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bg_objectid = ctx->bg_objectid;
	event.flags = ctx->flags;
	event.bg_size_class = ctx->bg_size_class;
	event.start = ctx->start;
	event.len = ctx->len;
	event.loop = ctx->loop;
	event.hinted = ctx->hinted;
	event.size_class = ctx->size_class;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_reserve_ticket_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 flags;
	u64 bytes;
	u64 start_ns;
	int flush;
	int error;
};

SEC("tracepoint/btrfs/btrfs_reserve_ticket")
int tp_btrfs_reserve_ticket(struct tp_btrfs_reserve_ticket_t *ctx)
{
	struct btrfs_reserve_ticket_event event = {};

	event.base.event_type = BTRFS_RESERVE_TICKET;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.flags = ctx->flags;
	event.bytes = ctx->bytes;
	event.start_ns = ctx->start_ns;
	event.flush = ctx->flush;
	event.error = ctx->error;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_reserved_extent_alloc_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 start;
	u64 len;
};

SEC("tracepoint/btrfs/btrfs_reserved_extent_alloc")
int tp_btrfs_reserved_extent_alloc(struct tp_btrfs_reserved_extent_alloc_t *ctx)
{
	struct btrfs_reserved_extent_alloc_event event = {};

	event.base.event_type = BTRFS_RESERVED_EXTENT_ALLOC;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.start = ctx->start;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_reserved_extent_free_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 start;
	u64 len;
};

SEC("tracepoint/btrfs/btrfs_reserved_extent_free")
int tp_btrfs_reserved_extent_free(struct tp_btrfs_reserved_extent_free_t *ctx)
{
	struct btrfs_reserved_extent_free_event event = {};

	event.base.event_type = BTRFS_RESERVED_EXTENT_FREE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.start = ctx->start;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_set_extent_bit_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	unsigned owner;
	u64 ino;
	u64 rootid;
	u64 start;
	u64 len;
	unsigned set_bits;
};

SEC("tracepoint/btrfs/btrfs_set_extent_bit")
int tp_btrfs_set_extent_bit(struct tp_btrfs_set_extent_bit_t *ctx)
{
	struct btrfs_set_extent_bit_event event = {};

	event.base.event_type = BTRFS_SET_EXTENT_BIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.owner = ctx->owner;
	event.ino = ctx->ino;
	event.rootid = ctx->rootid;
	event.start = ctx->start;
	event.len = ctx->len;
	event.set_bits = ctx->set_bits;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_set_lock_blocking_read_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_set_lock_blocking_read")
int tp_btrfs_set_lock_blocking_read(
	struct tp_btrfs_set_lock_blocking_read_t *ctx
)
{
	struct btrfs_set_lock_blocking_read_event event = {};

	event.base.event_type = BTRFS_SET_LOCK_BLOCKING_READ;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_set_lock_blocking_write_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_set_lock_blocking_write")
int tp_btrfs_set_lock_blocking_write(
	struct tp_btrfs_set_lock_blocking_write_t *ctx
)
{
	struct btrfs_set_lock_blocking_write_event event = {};

	event.base.event_type = BTRFS_SET_LOCK_BLOCKING_WRITE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_setup_cluster_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bg_objectid;
	u64 flags;
	u64 start;
	u64 max_size;
	u64 size;
	int bitmap;
};

SEC("tracepoint/btrfs/btrfs_setup_cluster")
int tp_btrfs_setup_cluster(struct tp_btrfs_setup_cluster_t *ctx)
{
	struct btrfs_setup_cluster_event event = {};
	event.base.event_type = BTRFS_SETUP_CLUSTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bg_objectid = ctx->bg_objectid;
	event.flags = ctx->flags;
	event.start = ctx->start;
	event.max_size = ctx->max_size;
	event.size = ctx->size;
	event.bitmap = ctx->bitmap;
	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_skip_unused_block_group_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 len;
	u64 used;
	u64 flags;
};

SEC("tracepoint/btrfs/btrfs_skip_unused_block_group")
int tp_btrfs_skip_unused_block_group(
	struct tp_btrfs_skip_unused_block_group_t *ctx
)
{
	struct btrfs_skip_unused_block_group_event event = {};
	event.base.event_type = BTRFS_SKIP_UNUSED_BLOCK_GROUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.len = ctx->len;
	event.used = ctx->used;
	event.flags = ctx->flags;
	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_space_reservation_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	char *type;
	u64 val;
	u64 bytes;
	int reserve;
};

SEC("tracepoint/btrfs/btrfs_space_reservation")
int tp_btrfs_space_reservation(struct tp_btrfs_space_reservation_t *ctx)
{
	struct btrfs_space_reservation_event event = {};
	event.base.event_type = BTRFS_SPACE_RESERVATION;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.type = ctx->type;
	event.val = ctx->val;
	event.bytes = ctx->bytes;
	event.reserve = ctx->reserve;
	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_sync_file_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 parent;
	int datasync;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_sync_file")
int tp_btrfs_sync_file(struct tp_btrfs_sync_file_t *ctx)
{
	struct btrfs_sync_file_event event;
	event.base.event_type = BTRFS_SYNC_FILE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.parent = ctx->parent;
	event.datasync = ctx->datasync;
	event.root_objectid = ctx->root_objectid;
	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_sync_fs_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	int wait;
};

SEC("tracepoint/btrfs/btrfs_sync_fs")
int tp_btrfs_sync_fs(struct tp_btrfs_sync_fs_t *ctx)
{
	struct btrfs_sync_fs_event event = {};
	event.base.event_type = BTRFS_SYNC_FS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.wait = ctx->wait;
	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_transaction_commit_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 generation;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_transaction_commit")
int tp_btrfs_transaction_commit(struct tp_btrfs_transaction_commit_t *ctx)
{
	struct btrfs_transaction_commit_event event = {};

	event.base.event_type = BTRFS_TRANSACTION_COMMIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.generation = ctx->generation;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_tree_lock_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 start_ns;
	u64 end_ns;
	u64 diff_ns;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_tree_lock")
int tp_btrfs_tree_lock(struct tp_btrfs_tree_lock_t *ctx)
{
	struct btrfs_tree_lock_event event = {};

	event.base.event_type = BTRFS_TREE_LOCK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.start_ns = ctx->start_ns;
	event.end_ns = ctx->end_ns;
	event.diff_ns = ctx->diff_ns;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_tree_read_lock_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 start_ns;
	u64 end_ns;
	u64 diff_ns;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_tree_read_lock")
int tp_btrfs_tree_read_lock(struct tp_btrfs_tree_read_lock_t *ctx)
{
	struct btrfs_tree_read_lock_event event = {};

	event.base.event_type = BTRFS_TREE_READ_LOCK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.start_ns = ctx->start_ns;
	event.end_ns = ctx->end_ns;
	event.diff_ns = ctx->diff_ns;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_tree_read_lock_atomic_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_tree_read_lock_atomic")
int tp_btrfs_tree_read_lock_atomic(struct tp_btrfs_tree_read_lock_atomic_t *ctx)
{
	struct btrfs_tree_read_lock_atomic_event event = {};

	event.base.event_type = BTRFS_TREE_READ_LOCK_ATOMIC;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_tree_read_unlock_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_tree_read_unlock")
int tp_btrfs_tree_read_unlock(struct tp_btrfs_tree_read_unlock_t *ctx)
{
	struct btrfs_tree_read_unlock_event event = {};

	event.base.event_type = BTRFS_TREE_READ_UNLOCK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_tree_read_unlock_blocking_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_tree_read_unlock_blocking")
int tp_btrfs_tree_read_unlock_blocking(
	struct tp_btrfs_tree_read_unlock_blocking_t *ctx
)
{
	struct btrfs_tree_read_unlock_blocking_event event = {};

	event.base.event_type = BTRFS_TREE_READ_UNLOCK_BLOCKING;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_tree_unlock_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_tree_unlock")
int tp_btrfs_tree_unlock(struct tp_btrfs_tree_unlock_t *ctx)
{
	struct btrfs_tree_unlock_event event = {};

	event.base.event_type = BTRFS_TREE_UNLOCK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_trigger_flush_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 flags;
	u64 bytes;
	int flush;
	char *reason;
};

SEC("tracepoint/btrfs/btrfs_trigger_flush")
int tp_btrfs_trigger_flush(struct tp_btrfs_trigger_flush_t *ctx)
{
	struct btrfs_trigger_flush_event event = {};

	event.base.event_type = BTRFS_TRIGGER_FLUSH;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.flags = ctx->flags;
	event.bytes = ctx->bytes;
	event.flush = ctx->flush;
	event.reason = ctx->reason;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_truncate_show_fi_inline_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_obj;
	u64 ino;
	loff_t isize;
	u64 disk_isize;
	u8 extent_type;
	u8 compression;
	u64 extent_start;
	u64 extent_end;
};

SEC("tracepoint/btrfs/btrfs_truncate_show_fi_inline")
int tp_btrfs_truncate_show_fi_inline(
	struct tp_btrfs_truncate_show_fi_inline_t *ctx
)
{
	struct btrfs_truncate_show_fi_inline_event event = {};

	event.base.event_type = BTRFS_TRUNCATE_SHOW_FI_INLINE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_obj = ctx->root_obj;
	event.ino = ctx->ino;
	event.isize = ctx->isize;
	event.disk_isize = ctx->disk_isize;
	event.extent_type = ctx->extent_type;
	event.compression = ctx->compression;
	event.extent_start = ctx->extent_start;
	event.extent_end = ctx->extent_end;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_truncate_show_fi_regular_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_obj;
	u64 ino;
	loff_t isize;
	u64 disk_isize;
	u64 num_bytes;
	u64 ram_bytes;
	u64 disk_bytenr;
	u64 disk_num_bytes;
	u64 extent_offset;
	u8 extent_type;
	u8 compression;
	u64 extent_start;
	u64 extent_end;
};

SEC("tracepoint/btrfs/btrfs_truncate_show_fi_regular")
int tp_btrfs_truncate_show_fi_regular(
	struct tp_btrfs_truncate_show_fi_regular_t *ctx
)
{
	struct btrfs_truncate_show_fi_regular_event event = {};

	event.base.event_type = BTRFS_TRUNCATE_SHOW_FI_REGULAR;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_obj = ctx->root_obj;
	event.ino = ctx->ino;
	event.isize = ctx->isize;
	event.disk_isize = ctx->disk_isize;
	event.num_bytes = ctx->num_bytes;
	event.ram_bytes = ctx->ram_bytes;
	event.disk_bytenr = ctx->disk_bytenr;
	event.disk_num_bytes = ctx->disk_num_bytes;
	event.extent_offset = ctx->extent_offset;
	event.extent_type = ctx->extent_type;
	event.compression = ctx->compression;
	event.extent_start = ctx->extent_start;
	event.extent_end = ctx->extent_end;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_try_tree_read_lock_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_try_tree_read_lock")
int tp_btrfs_try_tree_read_lock(struct tp_btrfs_try_tree_read_lock_t *ctx)
{
	struct btrfs_try_tree_read_lock_event event = {};

	event.base.event_type = BTRFS_TRY_TREE_READ_LOCK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_try_tree_write_lock_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 block;
	u64 generation;
	u64 owner;
	int is_log_tree;
};

SEC("tracepoint/btrfs/btrfs_try_tree_write_lock")
int tp_btrfs_try_tree_write_lock(struct tp_btrfs_try_tree_write_lock_t *ctx)
{
	struct btrfs_try_tree_write_lock_event event = {};

	event.base.event_type = BTRFS_TRY_TREE_WRITE_LOCK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.block = ctx->block;
	event.generation = ctx->generation;
	event.owner = ctx->owner;
	event.is_log_tree = ctx->is_log_tree;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_work_queued_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	const void *work;
	const void *wq;
	const void *func;
	const void *ordered_func;
	const void *ordered_free;
	const void *normal_work;
};

SEC("tracepoint/btrfs/btrfs_work_queued")
int tp_btrfs_work_queued(struct tp_btrfs_work_queued_t *ctx)
{
	struct btrfs_work_queued_event event = {};

	event.base.event_type = BTRFS_WORK_QUEUED;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.work = ctx->work;
	event.wq = ctx->wq;
	event.func = ctx->func;
	event.ordered_func = ctx->ordered_func;
	event.ordered_free = ctx->ordered_free;
	event.normal_work = ctx->normal_work;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_work_sched_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	const void *work;
	const void *wq;
	const void *func;
	const void *ordered_func;
	const void *ordered_free;
	const void *normal_work;
};

SEC("tracepoint/btrfs/btrfs_work_sched")
int tp_btrfs_work_sched(struct tp_btrfs_work_sched_t *ctx)
{
	struct btrfs_work_sched_event event = {};

	event.base.event_type = BTRFS_WORK_SCHED;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.work = ctx->work;
	event.wq = ctx->wq;
	event.func = ctx->func;
	event.ordered_func = ctx->ordered_func;
	event.ordered_free = ctx->ordered_free;
	event.normal_work = ctx->normal_work;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_workqueue_alloc_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	const void *wq;
	char *name;
};

SEC("tracepoint/btrfs/btrfs_workqueue_alloc")
int tp_btrfs_workqueue_alloc(struct tp_btrfs_workqueue_alloc_t *ctx)
{
	struct btrfs_workqueue_alloc_event event = {};

	event.base.event_type = BTRFS_WORKQUEUE_ALLOC;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.wq = ctx->wq;
	event.name = ctx->name;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_workqueue_destroy_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	const void *wq;
};

SEC("tracepoint/btrfs/btrfs_workqueue_destroy")
int tp_btrfs_workqueue_destroy(struct tp_btrfs_workqueue_destroy_t *ctx)
{
	struct btrfs_workqueue_destroy_event event = {};

	event.base.event_type = BTRFS_WORKQUEUE_DESTROY;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.wq = ctx->wq;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_btrfs_writepage_end_io_hook_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 ino;
	u64 start;
	u64 end;
	int uptodate;
	u64 root_objectid;
};

SEC("tracepoint/btrfs/btrfs_writepage_end_io_hook")
int tp_btrfs_writepage_end_io_hook(struct tp_btrfs_writepage_end_io_hook_t *ctx)
{
	struct btrfs_writepage_end_io_hook_event event = {};

	event.base.event_type = BTRFS_WRITEPAGE_END_IO_HOOK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.ino = ctx->ino;
	event.start = ctx->start;
	event.end = ctx->end;
	event.uptodate = ctx->uptodate;
	event.root_objectid = ctx->root_objectid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_find_free_extent_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_objectid;
	u64 num_bytes;
	u64 empty_size;
	u64 flags;
};

SEC("tracepoint/btrfs/find_free_extent")
int tp_find_free_extent(struct tp_find_free_extent_t *ctx)
{
	struct btrfs_find_free_extent_event event = {};

	event.base.event_type = BTRFS_FIND_FREE_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_objectid = ctx->root_objectid;
	event.num_bytes = ctx->num_bytes;
	event.empty_size = ctx->empty_size;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_find_free_extent_have_block_group_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_objectid;
	u64 num_bytes;
	u64 empty_size;
	u64 flags;
	u64 loop;
	bool hinted;
	u64 bg_start;
	u64 bg_flags;
};

SEC("tracepoint/btrfs/find_free_extent_have_block_group")
int tp_find_free_extent_have_block_group(
	struct tp_find_free_extent_have_block_group_t *ctx
)
{
	struct btrfs_find_free_extent_have_block_group_event event = {};

	event.base.event_type = BTRFS_FIND_FREE_EXTENT_HAVE_BLOCK_GROUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_objectid = ctx->root_objectid;
	event.num_bytes = ctx->num_bytes;
	event.empty_size = ctx->empty_size;
	event.flags = ctx->flags;
	event.loop = ctx->loop;
	event.hinted = ctx->hinted;
	event.bg_start = ctx->bg_start;
	event.bg_flags = ctx->bg_flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_find_free_extent_search_loop_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 root_objectid;
	u64 num_bytes;
	u64 empty_size;
	u64 flags;
	u64 loop;
};

SEC("tracepoint/btrfs/find_free_extent_search_loop")
int tp_find_free_extent_search_loop(
	struct tp_find_free_extent_search_loop_t *ctx
)
{
	struct btrfs_find_free_extent_search_loop_event event = {};

	event.base.event_type = BTRFS_FIND_FREE_EXTENT_SEARCH_LOOP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.root_objectid = ctx->root_objectid;
	event.num_bytes = ctx->num_bytes;
	event.empty_size = ctx->empty_size;
	event.flags = ctx->flags;
	event.loop = ctx->loop;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_free_extent_state_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	const struct extent_state *state;
	const void *ip;
};

SEC("tracepoint/btrfs/free_extent_state")
int tp_free_extent_state(struct tp_free_extent_state_t *ctx)
{
	struct btrfs_free_extent_state_event event = {};

	event.base.event_type = BTRFS_FREE_EXTENT_STATE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	event.state = ctx->state->state;
	event.ip = (unsigned long)ctx->ip;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_qgroup_meta_convert_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 refroot;
	s64 diff;
};

SEC("tracepoint/btrfs/qgroup_meta_convert")
int tp_qgroup_meta_convert(struct tp_qgroup_meta_convert_t *ctx)
{
	struct btrfs_qgroup_meta_convert_event event = {};

	event.base.event_type = BTRFS_QGROUP_META_CONVERT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.refroot = ctx->refroot;
	event.diff = ctx->diff;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_qgroup_meta_free_all_pertrans_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 refroot;
	s64 diff;
	int type;
};

SEC("tracepoint/btrfs/qgroup_meta_free_all_pertrans")
int tp_qgroup_meta_free_all_pertrans(
	struct tp_qgroup_meta_free_all_pertrans_t *ctx
)
{
	struct btrfs_qgroup_meta_free_all_pertrans_event event = {};

	event.base.event_type = BTRFS_QGROUP_META_FREE_ALL_PERTRANS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.refroot = ctx->refroot;
	event.diff = ctx->diff;
	event.type = ctx->type;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_qgroup_meta_reserve_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 refroot;
	s64 diff;
	int type;
};

SEC("tracepoint/btrfs/qgroup_meta_reserve")
int tp_qgroup_meta_reserve(struct tp_qgroup_meta_reserve_t *ctx)
{
	struct btrfs_qgroup_meta_reserve_event event = {};

	event.base.event_type = BTRFS_QGROUP_META_RESERVE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.refroot = ctx->refroot;
	event.diff = ctx->diff;
	event.type = ctx->type;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_qgroup_num_dirty_extents_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 transid;
	u64 num_dirty_extents;
};

SEC("tracepoint/btrfs/qgroup_num_dirty_extents")
int tp_qgroup_num_dirty_extents(struct tp_qgroup_num_dirty_extents_t *ctx)
{
	struct btrfs_qgroup_num_dirty_extents_event event = {};

	event.base.event_type = BTRFS_QGROUP_NUM_DIRTY_EXTENTS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.transid = ctx->transid;
	event.num_dirty_extents = ctx->num_dirty_extents;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_qgroup_update_counters_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 qgid;
	u64 old_rfer;
	u64 old_excl;
	u64 cur_old_count;
	u64 cur_new_count;
};

SEC("tracepoint/btrfs/qgroup_update_counters")
int tp_qgroup_update_counters(struct tp_qgroup_update_counters_t *ctx)
{
	struct btrfs_qgroup_update_counters_event event = {};

	event.base.event_type = BTRFS_QGROUP_UPDATE_COUNTERS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.qgid = ctx->qgid;
	event.old_rfer = ctx->old_rfer;
	event.old_excl = ctx->old_excl;
	event.cur_old_count = ctx->cur_old_count;
	event.cur_new_count = ctx->cur_new_count;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_qgroup_update_reserve_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 qgid;
	u64 cur_reserved;
	s64 diff;
	int type;
};

SEC("tracepoint/btrfs/qgroup_update_reserve")
int tp_qgroup_update_reserve(struct tp_qgroup_update_reserve_t *ctx)
{
	struct btrfs_qgroup_update_reserve_event event = {};

	event.base.event_type = BTRFS_QGROUP_UPDATE_RESERVE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.qgid = ctx->qgid;
	event.cur_reserved = ctx->cur_reserved;
	event.diff = ctx->diff;
	event.type = ctx->type;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_raid56_read_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 full_stripe;
	u64 physical;
	u64 devid;
	u32 offset;
	u32 len;
	u8 opf;
	u8 total_stripes;
	u8 real_stripes;
	u8 nr_data;
	u8 stripe_nr;
};

SEC("tracepoint/btrfs/raid56_read")
int tp_raid56_read(struct tp_raid56_read_t *ctx)
{
	struct btrfs_raid56_read_event event = {};

	event.base.event_type = BTRFS_RAID56_READ;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.full_stripe = ctx->full_stripe;
	event.physical = ctx->physical;
	event.devid = ctx->devid;
	event.offset = ctx->offset;
	event.len = ctx->len;
	event.opf = ctx->opf;
	event.total_stripes = ctx->total_stripes;
	event.real_stripes = ctx->real_stripes;
	event.nr_data = ctx->nr_data;
	event.stripe_nr = ctx->stripe_nr;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_raid56_write_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 full_stripe;
	u64 physical;
	u64 devid;
	u32 offset;
	u32 len;
	u8 opf;
	u8 total_stripes;
	u8 real_stripes;
	u8 nr_data;
	u8 stripe_nr;
};

SEC("tracepoint/btrfs/raid56_write")
int tp_raid56_write(struct tp_raid56_write_t *ctx)
{
	struct btrfs_raid56_write_event event = {};

	event.base.event_type = BTRFS_RAID56_WRITE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.full_stripe = ctx->full_stripe;
	event.physical = ctx->physical;
	event.devid = ctx->devid;
	event.offset = ctx->offset;
	event.len = ctx->len;
	event.opf = ctx->opf;
	event.total_stripes = ctx->total_stripes;
	event.real_stripes = ctx->real_stripes;
	event.nr_data = ctx->nr_data;
	event.stripe_nr = ctx->stripe_nr;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_run_delayed_data_ref_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 num_bytes;
	int action;
	u64 parent;
	u64 ref_root;
	u64 owner;
	u64 offset;
	int type;
	u64 seq;
};

SEC("tracepoint/btrfs/run_delayed_data_ref")
int tp_run_delayed_data_ref(struct tp_run_delayed_data_ref_t *ctx)
{
	struct btrfs_run_delayed_data_ref_event event = {};

	event.base.event_type = BTRFS_RUN_DELAYED_DATA_REF;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;
	event.action = ctx->action;
	event.parent = ctx->parent;
	event.ref_root = ctx->ref_root;
	event.owner = ctx->owner;
	event.offset = ctx->offset;
	event.type = ctx->type;
	event.seq = ctx->seq;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_run_delayed_ref_head_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 num_bytes;
	int action;
	int is_data;
};

SEC("tracepoint/btrfs/run_delayed_ref_head")
int tp_run_delayed_ref_head(struct tp_run_delayed_ref_head_t *ctx)
{
	struct btrfs_run_delayed_ref_head_event event = {};

	event.base.event_type = BTRFS_RUN_DELAYED_REF_HEAD;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;
	event.action = ctx->action;
	event.is_data = ctx->is_data;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_run_delayed_tree_ref_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 bytenr;
	u64 num_bytes;
	int action;
	u64 parent;
	u64 ref_root;
	int level;
	int type;
	u64 seq;
};

SEC("tracepoint/btrfs/run_delayed_tree_ref")
int tp_run_delayed_tree_ref(struct tp_run_delayed_tree_ref_t *ctx)
{
	struct btrfs_run_delayed_tree_ref_event event = {};

	event.base.event_type = BTRFS_RUN_DELAYED_TREE_REF;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.bytenr = ctx->bytenr;
	event.num_bytes = ctx->num_bytes;
	event.action = ctx->action;
	event.parent = ctx->parent;
	event.ref_root = ctx->ref_root;
	event.level = ctx->level;
	event.type = ctx->type;
	event.seq = ctx->seq;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_update_bytes_may_use_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 type;
	u64 old;
	s64 diff;
};

SEC("tracepoint/btrfs/update_bytes_may_use")
int tp_update_bytes_may_use(struct tp_update_bytes_may_use_t *ctx)
{
	struct btrfs_update_bytes_may_use_event event = {};

	event.base.event_type = BTRFS_UPDATE_BYTES_MAY_USE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.type = ctx->type;
	event.old = ctx->old;
	event.diff = ctx->diff;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_update_bytes_pinned_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 type;
	u64 old;
	s64 diff;
};

SEC("tracepoint/btrfs/update_bytes_pinned")
int tp_update_bytes_pinned(struct tp_update_bytes_pinned_t *ctx)
{
	struct btrfs_update_bytes_pinned_event event = {};

	event.base.event_type = BTRFS_UPDATE_BYTES_PINNED;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.type = ctx->type;
	event.old = ctx->old;
	event.diff = ctx->diff;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

struct tp_update_bytes_zone_unusable_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u8 fsid[16];
	u64 type;
	u64 old;
	s64 diff;
};

SEC("tracepoint/btrfs/update_bytes_zone_unusable")
int tp_update_bytes_zone_unusable(struct tp_update_bytes_zone_unusable_t *ctx)
{
	struct btrfs_update_bytes_zone_unusable_event event = {};

	event.base.event_type = BTRFS_UPDATE_BYTES_ZONE_UNUSABLE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));

	bpf_probe_read_kernel(&event.fsid, sizeof(event.fsid), ctx->fsid);
	event.type = ctx->type;
	event.old = ctx->old;
	event.diff = ctx->diff;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}
