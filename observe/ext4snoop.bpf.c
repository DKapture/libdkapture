#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "Kcom.h"
#include "ext4snoop.h"

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

struct tp_ext4_alloc_da_blocks_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned int data_blocks;
};

struct tp_ext4_allocate_blocks_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 block;
	unsigned int len;
	__u32 logical;
	__u32 lleft;
	__u32 lright;
	__u64 goal;
	__u64 pleft;
	__u64 pright;
	unsigned int flags;
};

struct tp_ext4_allocate_inode_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	ino_t dir;
	__u16 mode;
};

struct tp_ext4_begin_ordered_truncate_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t new_size;
};

struct tp_ext4_collapse_range_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
};

struct tp_ext4_da_release_space_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 i_blocks;
	int freed_blocks;
	int reserved_data_blocks;
	__u16 mode;
};

struct tp_ext4_da_reserve_space_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 i_blocks;
	int reserved_data_blocks;
	__u16 mode;
};

struct tp_ext4_da_update_reserve_space_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 i_blocks;
	int used_blocks;
	int reserved_data_blocks;
	int quota_claim;
	__u16 mode;
};

struct tp_ext4_da_write_begin_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
};

struct tp_ext4_da_write_end_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
	unsigned int copied;
};

struct tp_ext4_da_write_pages_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned long first_page;
	long nr_to_write;
	int sync_mode;
};

struct tp_ext4_da_write_pages_extent_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 lblk;
	__u32 len;
	__u32 flags;
};

struct tp_ext4_discard_blocks_t
{
	struct trace_entry ent;
	dev_t dev;
	__u64 blk;
	__u64 count;
};

struct tp_ext4_discard_preallocations_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned int len;
	unsigned int needed;
};

struct tp_ext4_drop_inode_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	int drop;
};

struct tp_ext4_error_t
{
	struct trace_entry ent;
	dev_t dev;
	char function[64];
	unsigned line;
};

struct tp_ext4_es_cache_extent_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
};

struct tp_ext4_es_find_extent_range_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
};

struct tp_ext4_es_find_extent_range_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
};

struct tp_ext4_es_insert_delayed_block_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
	bool allocated;
};

struct tp_ext4_es_insert_extent_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
};

struct tp_ext4_es_lookup_extent_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
};

struct tp_ext4_es_lookup_extent_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
	int found;
};

struct tp_ext4_es_remove_extent_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t lblk;
	loff_t len;
};

struct tp_ext4_es_shrink_t
{
	struct trace_entry ent;
	dev_t dev;
	int nr_shrunk;
	unsigned long long scan_time;
	int nr_skipped;
	int retried;
};

struct tp_ext4_es_shrink_count_t
{
	struct trace_entry ent;
	dev_t dev;
	int nr_to_scan;
	int cache_cnt;
};

struct tp_ext4_es_shrink_scan_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	int nr_to_scan;
	int cache_cnt;
};

struct tp_ext4_es_shrink_scan_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	int nr_shrunk;
	int cache_cnt;
};

struct tp_ext4_evict_inode_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	int nlink;
};

struct tp_ext4_ext_convert_to_initialized_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 m_lblk;
	unsigned m_len;
	__u32 u_lblk;
	unsigned u_len;
	__u64 u_pblk;
};

struct tp_ext4_ext_convert_to_initialized_fastpath_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 m_lblk;
	unsigned m_len;
	__u32 u_lblk;
	unsigned u_len;
	__u64 u_pblk;
	__u32 i_lblk;
	unsigned i_len;
	__u64 i_pblk;
};

struct tp_ext4_ext_handle_unwritten_extents_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	int flags;
	__u32 lblk;
	__u64 pblk;
	unsigned int len;
	unsigned int allocated;
	__u64 newblk;
};

struct tp_ext4_ext_load_extent_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 pblk;
	__u32 lblk;
};

struct tp_ext4_ext_map_blocks_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	unsigned int len;
	unsigned int flags;
};

struct tp_ext4_ext_map_blocks_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned int flags;
	__u64 pblk;
	__u32 lblk;
	unsigned int len;
	unsigned int mflags;
	int ret;
};

struct tp_ext4_ext_remove_space_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 start;
	__u32 end;
	int depth;
};

struct tp_ext4_ext_remove_space_done_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 start;
	__u32 end;
	int depth;
	__u64 pc_pclu;
	__u32 pc_lblk;
	int pc_state;
	unsigned short eh_entries;
};

struct tp_ext4_ext_rm_idx_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 pblk;
};

struct tp_ext4_ext_rm_leaf_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 start;
	__u32 ee_lblk;
	__u64 ee_pblk;
	short ee_len;
	__u64 pc_pclu;
	__u32 pc_lblk;
	int pc_state;
};

struct tp_ext4_ext_show_extent_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 pblk;
	__u32 lblk;
	unsigned short len;
};

struct tp_ext4_fallocate_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
	int mode;
};

struct tp_ext4_fallocate_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int blocks;
	int ret;
};

struct tp_ext4_fc_cleanup_t
{
	struct trace_entry ent;
	dev_t dev;
	int j_fc_off;
	int full;
	unsigned int tid;
};

struct tp_ext4_fc_commit_start_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned int tid;
};

struct tp_ext4_fc_commit_stop_t
{
	struct trace_entry ent;
	dev_t dev;
	int nblks;
	int reason;
	int num_fc;
	int num_fc_ineligible;
	int nblks_agg;
	unsigned int tid;
};

struct tp_ext4_fc_replay_t
{
	struct trace_entry ent;
	dev_t dev;
	int tag;
	int ino;
	int priv1;
	int priv2;
};

struct tp_ext4_fc_replay_scan_t
{
	struct trace_entry ent;
	dev_t dev;
	int error;
	int off;
};

struct tp_ext4_fc_stats_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned long fc_commits;
	unsigned long fc_ineligible_commits;
	unsigned long fc_numblks;
};

struct tp_ext4_fc_track_create_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	int error;
};

struct tp_ext4_fc_track_inode_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	int error;
};

struct tp_ext4_fc_track_link_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	int error;
};

struct tp_ext4_fc_track_range_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	long start;
	long end;
	int error;
};

struct tp_ext4_fc_track_unlink_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	int error;
};

struct tp_ext4_forget_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 block;
	int is_metadata;
	__u16 mode;
};

struct tp_ext4_free_blocks_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 block;
	unsigned long count;
	int flags;
	__u16 mode;
};

struct tp_ext4_free_inode_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	uid_t uid;
	gid_t gid;
	__u64 blocks;
	__u16 mode;
};

struct tp_ext4_fsmap_high_key_t
{
	struct trace_entry ent;
	dev_t dev;
	dev_t keydev;
	__u32 agno;
	__u64 bno;
	__u64 len;
	__u64 owner;
};

struct tp_ext4_fsmap_low_key_t
{
	struct trace_entry ent;
	dev_t dev;
	dev_t keydev;
	__u32 agno;
	__u64 bno;
	__u64 len;
	__u64 owner;
};

struct tp_ext4_fsmap_mapping_t
{
	struct trace_entry ent;
	dev_t dev;
	dev_t keydev;
	__u32 agno;
	__u64 bno;
	__u64 len;
	__u64 owner;
};

struct tp_ext4_get_implied_cluster_alloc_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned int flags;
	__u32 lblk;
	__u64 pblk;
	unsigned int len;
	int ret;
};

struct tp_ext4_getfsmap_high_key_t
{
	struct trace_entry ent;
	dev_t dev;
	dev_t keydev;
	__u64 block;
	__u64 len;
	__u64 owner;
	__u64 flags;
};

struct tp_ext4_getfsmap_low_key_t
{
	struct trace_entry ent;
	dev_t dev;
	dev_t keydev;
	__u64 block;
	__u64 len;
	__u64 owner;
	__u64 flags;
};

struct tp_ext4_getfsmap_mapping_t
{
	struct trace_entry ent;
	dev_t dev;
	dev_t keydev;
	__u64 block;
	__u64 len;
	__u64 owner;
	__u64 flags;
};

struct tp_ext4_ind_map_blocks_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	unsigned int len;
	unsigned int flags;
};

struct tp_ext4_ind_map_blocks_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned int flags;
	__u64 pblk;
	__u32 lblk;
	unsigned int len;
	unsigned int mflags;
	int ret;
};

struct tp_ext4_insert_range_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
};

struct tp_ext4_invalidate_folio_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned long index;
	size_t offset;
	size_t length;
};

struct tp_ext4_journal_start_inode_t
{
	struct trace_entry ent;
	unsigned long ino;
	dev_t dev;
	unsigned long ip;
	int blocks;
	int rsv_blocks;
	int revoke_creds;
	int type;
};

struct tp_ext4_journal_start_reserved_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned long ip;
	int blocks;
};

struct tp_ext4_journal_start_sb_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned long ip;
	int blocks;
	int rsv_blocks;
	int revoke_creds;
	int type;
};

struct tp_ext4_journalled_invalidate_folio_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned long index;
	size_t offset;
	size_t length;
};

struct tp_ext4_journalled_write_end_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
	unsigned int copied;
};

struct tp_ext4_lazy_itable_init_t
{
	struct trace_entry ent;
	dev_t dev;
	__u32 group;
};

struct tp_ext4_load_inode_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
};

struct tp_ext4_load_inode_bitmap_t
{
	struct trace_entry ent;
	dev_t dev;
	__u32 group;
};

struct tp_ext4_mark_inode_dirty_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned long ip;
};

struct tp_ext4_mb_bitmap_load_t
{
	struct trace_entry ent;
	dev_t dev;
	__u32 group;
};

struct tp_ext4_mb_buddy_bitmap_load_t
{
	struct trace_entry ent;
	dev_t dev;
	__u32 group;
};

struct tp_ext4_mb_discard_preallocations_t
{
	struct trace_entry ent;
	dev_t dev;
	int needed;
};

struct tp_ext4_mb_new_group_pa_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 pa_pstart;
	__u64 pa_lstart;
	__u32 pa_len;
};

struct tp_ext4_mb_new_inode_pa_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 pa_pstart;
	__u64 pa_lstart;
	__u32 pa_len;
};

struct tp_ext4_mb_release_group_pa_t
{
	struct trace_entry ent;
	dev_t dev;
	__u64 pa_pstart;
	__u32 pa_len;
};

struct tp_ext4_mb_release_inode_pa_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 block;
	__u32 count;
};

struct tp_ext4_mballoc_alloc_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 orig_logical;
	int orig_start;
	__u32 orig_group;
	int orig_len;
	__u32 goal_logical;
	int goal_start;
	__u32 goal_group;
	int goal_len;
	__u32 result_logical;
	int result_start;
	__u32 result_group;
	int result_len;
	__u16 found;
	__u16 groups;
	__u16 buddy;
	__u16 flags;
	__u16 tail;
	__u8 cr;
};

struct tp_ext4_mballoc_discard_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	int result_start;
	__u32 result_group;
	int result_len;
};

struct tp_ext4_mballoc_free_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	int result_start;
	__u32 result_group;
	int result_len;
};

struct tp_ext4_mballoc_prealloc_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 orig_logical;
	int orig_start;
	__u32 orig_group;
	int orig_len;
	__u32 result_logical;
	int result_start;
	__u32 result_group;
	int result_len;
};

struct tp_ext4_nfs_commit_metadata_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
};

struct tp_ext4_other_inode_update_time_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	ino_t orig_ino;
	uid_t uid;
	gid_t gid;
	__u16 mode;
};

struct tp_ext4_prefetch_bitmaps_t
{
	struct trace_entry ent;
	dev_t dev;
	__u32 group;
	__u32 next;
	__u32 ios;
};

struct tp_ext4_punch_hole_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
	int mode;
};

struct tp_ext4_read_block_bitmap_load_t
{
	struct trace_entry ent;
	dev_t dev;
	__u32 group;
	bool prefetch;
};

struct tp_ext4_read_folio_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned long index;
};

struct tp_ext4_release_folio_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned long index;
};

struct tp_ext4_remove_blocks_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u32 from;
	__u32 to;
	__u64 ee_pblk;
	__u32 ee_lblk;
	unsigned short ee_len;
	__u64 pc_pclu;
	__u32 pc_lblk;
	int pc_state;
};

struct tp_ext4_request_blocks_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	unsigned int len;
	__u32 logical;
	__u32 lleft;
	__u32 lright;
	__u64 goal;
	__u64 pleft;
	__u64 pright;
	unsigned int flags;
};

struct tp_ext4_request_inode_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t dir;
	__u16 mode;
};

struct tp_ext4_shutdown_t
{
	struct trace_entry ent;
	dev_t dev;
	unsigned flags;
};

struct tp_ext4_sync_file_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	ino_t parent;
	int datasync;
};

struct tp_ext4_sync_file_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	int ret;
};

struct tp_ext4_sync_fs_t
{
	struct trace_entry ent;
	dev_t dev;
	int wait;
};

struct tp_ext4_trim_all_free_t
{
	struct trace_entry ent;
	int dev_major;
	int dev_minor;
	__u32 group;
	int start;
	int len;
};

struct tp_ext4_trim_extent_t
{
	struct trace_entry ent;
	int dev_major;
	int dev_minor;
	__u32 group;
	int start;
	int len;
};

struct tp_ext4_truncate_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 blocks;
};

struct tp_ext4_truncate_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	__u64 blocks;
};

struct tp_ext4_unlink_enter_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	ino_t parent;
	loff_t size;
};

struct tp_ext4_unlink_exit_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	int ret;
};

struct tp_ext4_update_sb_t
{
	struct trace_entry ent;
	dev_t dev;
	__u64 fsblk;
	unsigned int flags;
};

struct tp_ext4_write_begin_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
};

struct tp_ext4_write_end_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
	unsigned int copied;
};

struct tp_ext4_writepages_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	long nr_to_write;
	long pages_skipped;
	loff_t range_start;
	loff_t range_end;
	unsigned long writeback_index;
	int sync_mode;
	char for_kupdate;
	char range_cyclic;
};

struct tp_ext4_writepages_result_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	int ret;
	int pages_written;
	long pages_skipped;
	unsigned long writeback_index;
	int sync_mode;
};

struct tp_ext4_zero_range_t
{
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
	int mode;
};

SEC("tracepoint/ext4/ext4_alloc_da_blocks")
int tp_ext4_alloc_da_blocks(struct tp_ext4_alloc_da_blocks_t *ctx)
{
	long ret = 0;
	struct ext4_alloc_da_blocks_t event;
	event.base.type = EXT4_ALLOC_DA_BLOCKS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, data_blocks: %u",
		ctx->dev,
		ctx->ino,
		ctx->data_blocks
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.data_blocks = ctx->data_blocks;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_begin_ordered_truncate")
int tp_ext4_begin_ordered_truncate(struct tp_ext4_begin_ordered_truncate_t *ctx)
{
	long ret = 0;
	struct ext4_begin_ordered_truncate_t event;
	event.base.type = EXT4_BEGIN_ORDERED_TRUNCATE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, new_size: %llu",
		ctx->dev,
		ctx->ino,
		ctx->new_size
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.new_size = ctx->new_size;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_collapse_range")
int tp_ext4_collapse_range(struct tp_ext4_collapse_range_t *ctx)
{
	long ret = 0;
	struct ext4_collapse_range_t event;
	event.base.type = EXT4_COLLAPSE_RANGE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, offset: %llu, len: %llu",
		ctx->dev,
		ctx->ino,
		ctx->offset,
		ctx->len
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.offset = ctx->offset;
	event.len = ctx->len;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_da_release_space")
int ext4_da_release_space(struct tp_ext4_da_release_space_t *ctx)
{
	long ret = 0;
	struct ext4_da_release_space_t event;
	event.base.type = EXT4_DA_RELEASE_SPACE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu i_blocks: %llu, freed_blocks: %d"
		" reserved_data_blocks: %d, mode: %d",
		ctx->dev,
		ctx->ino,
		ctx->i_blocks,
		ctx->freed_blocks,
		ctx->reserved_data_blocks,
		ctx->mode
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.i_blocks = ctx->i_blocks;
	event.freed_blocks = ctx->freed_blocks;
	event.reserved_data_blocks = ctx->reserved_data_blocks;
	event.mode = ctx->mode;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_da_reserve_space")
int tp_ext4_da_reserve_space(struct tp_ext4_da_reserve_space_t *ctx)
{
	long ret = 0;
	struct ext4_da_reserve_space_t event;
	event.base.type = EXT4_DA_RESERVE_SPACE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, i_blocks: %llu, reserved_data_blocks: %d, mode: %u",
		ctx->dev,
		ctx->ino,
		ctx->i_blocks,
		ctx->reserved_data_blocks,
		ctx->mode
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.i_blocks = ctx->i_blocks;
	event.reserved_data_blocks = ctx->reserved_data_blocks;
	event.mode = ctx->mode;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_da_write_pages")
int tp_ext4_da_write_pages(struct tp_ext4_da_write_pages_t *ctx)
{
	long ret = 0;
	struct ext4_da_write_pages_t event;
	event.base.type = EXT4_DA_WRITE_PAGES;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, first_page: %lu, nr_to_write: %ld, sync_mode: %d",
		ctx->dev,
		ctx->ino,
		ctx->first_page,
		ctx->nr_to_write,
		ctx->sync_mode
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.first_page = ctx->first_page;
	event.nr_to_write = ctx->nr_to_write;
	event.sync_mode = ctx->sync_mode;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_allocate_blocks")
int tp_ext4_allocate_blocks(struct tp_ext4_allocate_blocks_t *ctx)
{
	long ret = 0;
	struct ext4_allocate_blocks_t event;
	event.base.type = EXT4_ALLOCATE_BLOCKS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, block: %llu, len: %u, logical: %u",
		ctx->dev,
		ctx->ino,
		ctx->block,
		ctx->len,
		ctx->logical
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.block = ctx->block;
	event.len = ctx->len;
	event.logical = ctx->logical;
	event.lleft = ctx->lleft;
	event.lright = ctx->lright;
	event.goal = ctx->goal;
	event.pleft = ctx->pleft;
	event.pright = ctx->pright;
	event.flags = ctx->flags;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_da_write_begin")
int tp_ext4_da_write_begin(struct tp_ext4_da_write_begin_t *ctx)
{
	long ret = 0;
	struct ext4_da_write_begin_t event;
	event.base.type = EXT4_DA_WRITE_BEGIN;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, pos: %lld, len: %u",
		ctx->dev,
		ctx->ino,
		ctx->pos,
		ctx->len
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pos = ctx->pos;
	event.len = ctx->len;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_da_write_end")
int tp_ext4_da_write_end(struct tp_ext4_da_write_end_t *ctx)
{
	long ret = 0;
	struct ext4_da_write_end_t event;
	event.base.type = EXT4_DA_WRITE_END;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, pos: %lld, len: %u, copied: %u",
		ctx->dev,
		ctx->ino,
		ctx->pos,
		ctx->len,
		ctx->copied
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pos = ctx->pos;
	event.len = ctx->len;
	event.copied = ctx->copied;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

SEC("tracepoint/ext4/ext4_allocate_inode")
int tp_ext4_allocate_inode(struct tp_ext4_allocate_inode_t *ctx)
{
	long ret = 0;
	struct ext4_allocate_inode_t event;
	event.base.type = EXT4_ALLOCATE_INODE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	DEBUG(
		0,
		"dev: %d, ino: %lu, dir: %lu, mode: %o",
		ctx->dev,
		ctx->ino,
		ctx->dir,
		ctx->mode
	);
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.dir = ctx->dir;
	event.mode = ctx->mode;
	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}
	return 0;
}

// Implementation for tp_ext4_da_update_reserve_space

SEC("tracepoint/ext4/ext4_da_update_reserve_space")
int tp_ext4_da_update_reserve_space(
	struct tp_ext4_da_update_reserve_space_t *ctx
)
{
	struct ext4_da_update_reserve_space_t event = {};

	event.base.type = EXT4_DA_UPDATE_RESERVE_SPACE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.i_blocks = ctx->i_blocks;
	event.used_blocks = ctx->used_blocks;
	event.reserved_data_blocks = ctx->reserved_data_blocks;
	event.quota_claim = ctx->quota_claim;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_da_write_pages_extent

SEC("tracepoint/ext4/ext4_da_write_pages_extent")
int tp_ext4_da_write_pages_extent(struct tp_ext4_da_write_pages_extent_t *ctx)
{
	struct ext4_da_write_pages_extent_t event = {};

	event.base.type = EXT4_DA_WRITE_PAGES_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_discard_blocks

SEC("racepoint/ext4/discard_blocks")
int tp_ext4_discard_blocks(struct tp_ext4_discard_blocks_t *ctx)
{
	struct ext4_discard_blocks_t event = {};

	event.base.type = EXT4_DISCARD_BLOCKS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.blk = ctx->blk;
	event.count = ctx->count;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_discard_preallocations

SEC("racepoint/ext4/discard_preallocations")
int tp_ext4_discard_preallocations(struct tp_ext4_discard_preallocations_t *ctx)
{
	struct ext4_discard_preallocations_t event = {};

	event.base.type = EXT4_DISCARD_PREALLOCATIONS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.len = ctx->len;
	event.needed = ctx->needed;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_drop_inode

SEC("racepoint/ext4/drop_inode")
int tp_ext4_drop_inode(struct tp_ext4_drop_inode_t *ctx)
{
	struct ext4_drop_inode_t event = {};

	event.base.type = EXT4_DROP_INODE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.drop = ctx->drop;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_error

SEC("racepoint/ext4/error")
int tp_ext4_error(struct tp_ext4_error_t *ctx)
{
	struct ext4_error_t event = {};

	event.base.type = EXT4_ERROR;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	__builtin_memcpy(event.function, ctx->function, sizeof(ctx->function));
	event.line = ctx->line;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_cache_extent

SEC("racepoint/ext4/es_cache_extent")
int tp_ext4_es_cache_extent(struct tp_ext4_es_cache_extent_t *ctx)
{
	struct ext4_es_cache_extent_t event = {};

	event.base.type = EXT4_ES_CACHE_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.pblk = ctx->pblk;
	event.status = ctx->status;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_find_extent_range_enter

SEC("racepoint/ext4/es_find_extent_range_enter")
int tp_ext4_es_find_extent_range_enter(
	struct tp_ext4_es_find_extent_range_enter_t *ctx
)
{
	struct ext4_es_find_extent_range_enter_t event = {};

	event.base.type = EXT4_ES_FIND_EXTENT_RANGE_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_find_extent_range_exit

SEC("racepoint/ext4/es_find_extent_range_exit")
int tp_ext4_es_find_extent_range_exit(
	struct tp_ext4_es_find_extent_range_exit_t *ctx
)
{
	struct ext4_es_find_extent_range_exit_t event = {};

	event.base.type = EXT4_ES_FIND_EXTENT_RANGE_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.pblk = ctx->pblk;
	event.status = ctx->status;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_insert_delayed_block

SEC("racepoint/ext4/es_insert_delayed_block")
int tp_ext4_es_insert_delayed_block(
	struct tp_ext4_es_insert_delayed_block_t *ctx
)
{
	struct ext4_es_insert_delayed_block_t event = {};

	event.base.type = EXT4_ES_INSERT_DELAYED_BLOCK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.pblk = ctx->pblk;
	event.status = ctx->status;
	event.allocated = ctx->allocated;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_insert_extent

SEC("racepoint/ext4/es_insert_extent")
int tp_ext4_es_insert_extent(struct tp_ext4_es_insert_extent_t *ctx)
{
	struct ext4_es_insert_extent_t event = {};

	event.base.type = EXT4_ES_INSERT_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.pblk = ctx->pblk;
	event.status = ctx->status;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_lookup_extent_enter

SEC("racepoint/ext4/es_lookup_extent_enter")
int tp_ext4_es_lookup_extent_enter(struct tp_ext4_es_lookup_extent_enter_t *ctx)
{
	struct ext4_es_lookup_extent_enter_t event = {};

	event.base.type = EXT4_ES_LOOKUP_EXTENT_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_lookup_extent_exit

SEC("racepoint/ext4/es_lookup_extent_exit")
int tp_ext4_es_lookup_extent_exit(struct tp_ext4_es_lookup_extent_exit_t *ctx)
{
	struct ext4_es_lookup_extent_exit_t event = {};

	event.base.type = EXT4_ES_LOOKUP_EXTENT_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.pblk = ctx->pblk;
	event.status = ctx->status;
	event.found = ctx->found;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_remove_extent

SEC("racepoint/ext4/es_remove_extent")
int tp_ext4_es_remove_extent(struct tp_ext4_es_remove_extent_t *ctx)
{
	struct ext4_es_remove_extent_t event = {};

	event.base.type = EXT4_ES_REMOVE_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_shrink

SEC("racepoint/ext4/es_shrink")
int tp_ext4_es_shrink(struct tp_ext4_es_shrink_t *ctx)
{
	struct ext4_es_shrink_t event = {};

	event.base.type = EXT4_ES_SHRINK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.nr_shrunk = ctx->nr_shrunk;
	event.scan_time = ctx->scan_time;
	event.nr_skipped = ctx->nr_skipped;
	event.retried = ctx->retried;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_shrink_count

SEC("racepoint/ext4/es_shrink_count")
int tp_ext4_es_shrink_count(struct tp_ext4_es_shrink_count_t *ctx)
{
	struct ext4_es_shrink_count_t event = {};

	event.base.type = EXT4_ES_SHRINK_COUNT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.nr_to_scan = ctx->nr_to_scan;
	event.cache_cnt = ctx->cache_cnt;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_shrink_scan_enter

SEC("racepoint/ext4/es_shrink_scan_enter")
int tp_ext4_es_shrink_scan_enter(struct tp_ext4_es_shrink_scan_enter_t *ctx)
{
	struct ext4_es_shrink_scan_enter_t event = {};

	event.base.type = EXT4_ES_SHRINK_SCAN_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.nr_to_scan = ctx->nr_to_scan;
	event.cache_cnt = ctx->cache_cnt;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_es_shrink_scan_exit

SEC("racepoint/ext4/es_shrink_scan_exit")
int tp_ext4_es_shrink_scan_exit(struct tp_ext4_es_shrink_scan_exit_t *ctx)
{
	struct ext4_es_shrink_scan_exit_t event = {};

	event.base.type = EXT4_ES_SHRINK_SCAN_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.nr_shrunk = ctx->nr_shrunk;
	event.cache_cnt = ctx->cache_cnt;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_evict_inode

SEC("racepoint/ext4/evict_inode")
int tp_ext4_evict_inode(struct tp_ext4_evict_inode_t *ctx)
{
	struct ext4_evict_inode_t event = {};

	event.base.type = EXT4_EVICT_INODE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.nlink = ctx->nlink;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_convert_to_initialized_enter

SEC("racepoint/ext4/ext_convert_to_initialized_enter")
int tp_ext4_ext_convert_to_initialized_enter(
	struct tp_ext4_ext_convert_to_initialized_enter_t *ctx
)
{
	struct ext4_ext_convert_to_initialized_enter_t event = {};

	event.base.type = EXT4_EXT_CONVERT_TO_INITIALIZED_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.m_lblk = ctx->m_lblk;
	event.m_len = ctx->m_len;
	event.u_lblk = ctx->u_lblk;
	event.u_len = ctx->u_len;
	event.u_pblk = ctx->u_pblk;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_convert_to_initialized_fastpath

SEC("racepoint/ext4/ext_convert_to_initialized_fastpath")
int tp_ext4_ext_convert_to_initialized_fastpath(
	struct tp_ext4_ext_convert_to_initialized_fastpath_t *ctx
)
{
	struct ext4_ext_convert_to_initialized_fastpath_t event = {};

	event.base.type = EXT4_EXT_CONVERT_TO_INITIALIZED_FASTPATH;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.m_lblk = ctx->m_lblk;
	event.m_len = ctx->m_len;
	event.u_lblk = ctx->u_lblk;
	event.u_len = ctx->u_len;
	event.u_pblk = ctx->u_pblk;
	event.i_lblk = ctx->i_lblk;
	event.i_len = ctx->i_len;
	event.i_pblk = ctx->i_pblk;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_handle_unwritten_extents

SEC("racepoint/ext4/ext_handle_unwritten_extents")
int tp_ext4_ext_handle_unwritten_extents(
	struct tp_ext4_ext_handle_unwritten_extents_t *ctx
)
{
	struct ext4_ext_handle_unwritten_extents_t event = {};

	event.base.type = EXT4_EXT_HANDLE_UNWRITTEN_EXTENTS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.flags = ctx->flags;
	event.lblk = ctx->lblk;
	event.pblk = ctx->pblk;
	event.len = ctx->len;
	event.allocated = ctx->allocated;
	event.newblk = ctx->newblk;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_load_extent

SEC("racepoint/ext4/ext_load_extent")
int tp_ext4_ext_load_extent(struct tp_ext4_ext_load_extent_t *ctx)
{
	struct ext4_ext_load_extent_t event = {};

	event.base.type = EXT4_EXT_LOAD_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pblk = ctx->pblk;
	event.lblk = ctx->lblk;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_map_blocks_enter

SEC("racepoint/ext4/ext_map_blocks_enter")
int tp_ext4_ext_map_blocks_enter(struct tp_ext4_ext_map_blocks_enter_t *ctx)
{
	struct ext4_ext_map_blocks_enter_t event = {};

	event.base.type = EXT4_EXT_MAP_BLOCKS_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_map_blocks_exit

SEC("racepoint/ext4/ext_map_blocks_exit")
int tp_ext4_ext_map_blocks_exit(struct tp_ext4_ext_map_blocks_exit_t *ctx)
{
	struct ext4_ext_map_blocks_exit_t event = {};

	event.base.type = EXT4_EXT_MAP_BLOCKS_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.flags = ctx->flags;
	event.pblk = ctx->pblk;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.mflags = ctx->mflags;
	event.ret = ctx->ret;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_remove_space

SEC("racepoint/ext4/ext_remove_space")
int tp_ext4_ext_remove_space(struct tp_ext4_ext_remove_space_t *ctx)
{
	struct ext4_ext_remove_space_t event = {};

	event.base.type = EXT4_EXT_REMOVE_SPACE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.start = ctx->start;
	event.end = ctx->end;
	event.depth = ctx->depth;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_remove_space_done

SEC("racepoint/ext4/ext_remove_space_done")
int tp_ext4_ext_remove_space_done(struct tp_ext4_ext_remove_space_done_t *ctx)
{
	struct ext4_ext_remove_space_done_t event = {};

	event.base.type = EXT4_EXT_REMOVE_SPACE_DONE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.start = ctx->start;
	event.end = ctx->end;
	event.depth = ctx->depth;
	event.pc_pclu = ctx->pc_pclu;
	event.pc_lblk = ctx->pc_lblk;
	event.pc_state = ctx->pc_state;
	event.eh_entries = ctx->eh_entries;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_rm_idx

SEC("racepoint/ext4/ext_rm_idx")
int tp_ext4_ext_rm_idx(struct tp_ext4_ext_rm_idx_t *ctx)
{
	struct ext4_ext_rm_idx_t event = {};

	event.base.type = EXT4_EXT_RM_IDX;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pblk = ctx->pblk;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_rm_leaf

SEC("racepoint/ext4/ext_rm_leaf")
int tp_ext4_ext_rm_leaf(struct tp_ext4_ext_rm_leaf_t *ctx)
{
	struct ext4_ext_rm_leaf_t event = {};

	event.base.type = EXT4_EXT_RM_LEAF;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.start = ctx->start;
	event.ee_lblk = ctx->ee_lblk;
	event.ee_pblk = ctx->ee_pblk;
	event.ee_len = ctx->ee_len;
	event.pc_pclu = ctx->pc_pclu;
	event.pc_lblk = ctx->pc_lblk;
	event.pc_state = ctx->pc_state;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ext_show_extent

SEC("racepoint/ext4/ext_show_extent")
int tp_ext4_ext_show_extent(struct tp_ext4_ext_show_extent_t *ctx)
{
	struct ext4_ext_show_extent_t event = {};

	event.base.type = EXT4_EXT_SHOW_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pblk = ctx->pblk;
	event.lblk = ctx->lblk;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fallocate_enter

SEC("racepoint/ext4/fallocate_enter")
int tp_ext4_fallocate_enter(struct tp_ext4_fallocate_enter_t *ctx)
{
	struct ext4_fallocate_enter_t event = {};

	event.base.type = EXT4_FALLOCATE_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.offset = ctx->offset;
	event.len = ctx->len;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fallocate_exit

SEC("racepoint/ext4/fallocate_exit")
int tp_ext4_fallocate_exit(struct tp_ext4_fallocate_exit_t *ctx)
{
	struct ext4_fallocate_exit_t event = {};

	event.base.type = EXT4_FALLOCATE_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pos = ctx->pos;
	event.blocks = ctx->blocks;
	event.ret = ctx->ret;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_cleanup

SEC("racepoint/ext4/fc_cleanup")
int tp_ext4_fc_cleanup(struct tp_ext4_fc_cleanup_t *ctx)
{
	struct ext4_fc_cleanup_t event = {};

	event.base.type = EXT4_FC_CLEANUP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.j_fc_off = ctx->j_fc_off;
	event.full = ctx->full;
	event.tid = ctx->tid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_commit_start

SEC("racepoint/ext4/fc_commit_start")
int tp_ext4_fc_commit_start(struct tp_ext4_fc_commit_start_t *ctx)
{
	struct ext4_fc_commit_start_t event = {};

	event.base.type = EXT4_FC_COMMIT_START;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.tid = ctx->tid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_commit_stop

SEC("racepoint/ext4/fc_commit_stop")
int tp_ext4_fc_commit_stop(struct tp_ext4_fc_commit_stop_t *ctx)
{
	struct ext4_fc_commit_stop_t event = {};

	event.base.type = EXT4_FC_COMMIT_STOP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.nblks = ctx->nblks;
	event.reason = ctx->reason;
	event.num_fc = ctx->num_fc;
	event.num_fc_ineligible = ctx->num_fc_ineligible;
	event.nblks_agg = ctx->nblks_agg;
	event.tid = ctx->tid;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_replay

SEC("racepoint/ext4/fc_replay")
int tp_ext4_fc_replay(struct tp_ext4_fc_replay_t *ctx)
{
	struct ext4_fc_replay_t event = {};

	event.base.type = EXT4_FC_REPLAY;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.tag = ctx->tag;
	event.ino = ctx->ino;
	event.priv1 = ctx->priv1;
	event.priv2 = ctx->priv2;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_replay_scan

SEC("racepoint/ext4/fc_replay_scan")
int tp_ext4_fc_replay_scan(struct tp_ext4_fc_replay_scan_t *ctx)
{
	struct ext4_fc_replay_scan_t event = {};

	event.base.type = EXT4_FC_REPLAY_SCAN;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.error = ctx->error;
	event.off = ctx->off;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_stats

SEC("racepoint/ext4/fc_stats")
int tp_ext4_fc_stats(struct tp_ext4_fc_stats_t *ctx)
{
	struct ext4_fc_stats_t event = {};

	event.base.type = EXT4_FC_STATS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.fc_commits = ctx->fc_commits;
	event.fc_ineligible_commits = ctx->fc_ineligible_commits;
	event.fc_numblks = ctx->fc_numblks;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_track_create

SEC("racepoint/ext4/fc_track_create")
int tp_ext4_fc_track_create(struct tp_ext4_fc_track_create_t *ctx)
{
	struct ext4_fc_track_create_t event = {};

	event.base.type = EXT4_FC_TRACK_CREATE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.t_tid = ctx->t_tid;
	event.i_ino = ctx->i_ino;
	event.i_sync_tid = ctx->i_sync_tid;
	event.error = ctx->error;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_track_inode

SEC("racepoint/ext4/fc_track_inode")
int tp_ext4_fc_track_inode(struct tp_ext4_fc_track_inode_t *ctx)
{
	struct ext4_fc_track_inode_t event = {};

	event.base.type = EXT4_FC_TRACK_INODE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.t_tid = ctx->t_tid;
	event.i_ino = ctx->i_ino;
	event.i_sync_tid = ctx->i_sync_tid;
	event.error = ctx->error;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_track_link

SEC("racepoint/ext4/fc_track_link")
int tp_ext4_fc_track_link(struct tp_ext4_fc_track_link_t *ctx)
{
	struct ext4_fc_track_link_t event = {};

	event.base.type = EXT4_FC_TRACK_LINK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.t_tid = ctx->t_tid;
	event.i_ino = ctx->i_ino;
	event.i_sync_tid = ctx->i_sync_tid;
	event.error = ctx->error;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_track_range

SEC("racepoint/ext4/fc_track_range")
int tp_ext4_fc_track_range(struct tp_ext4_fc_track_range_t *ctx)
{
	struct ext4_fc_track_range_t event = {};

	event.base.type = EXT4_FC_TRACK_RANGE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.t_tid = ctx->t_tid;
	event.i_ino = ctx->i_ino;
	event.i_sync_tid = ctx->i_sync_tid;
	event.start = ctx->start;
	event.end = ctx->end;
	event.error = ctx->error;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fc_track_unlink

SEC("racepoint/ext4/fc_track_unlink")
int tp_ext4_fc_track_unlink(struct tp_ext4_fc_track_unlink_t *ctx)
{
	struct ext4_fc_track_unlink_t event = {};

	event.base.type = EXT4_FC_TRACK_UNLINK;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.t_tid = ctx->t_tid;
	event.i_ino = ctx->i_ino;
	event.i_sync_tid = ctx->i_sync_tid;
	event.error = ctx->error;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_forget

SEC("racepoint/ext4/forget")
int tp_ext4_forget(struct tp_ext4_forget_t *ctx)
{
	struct ext4_forget_t event = {};

	event.base.type = EXT4_FORGET;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.block = ctx->block;
	event.is_metadata = ctx->is_metadata;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_free_blocks

SEC("racepoint/ext4/free_blocks")
int tp_ext4_free_blocks(struct tp_ext4_free_blocks_t *ctx)
{
	struct ext4_free_blocks_t event = {};

	event.base.type = EXT4_FREE_BLOCKS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.block = ctx->block;
	event.count = ctx->count;
	event.flags = ctx->flags;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_free_inode

SEC("racepoint/ext4/free_inode")
int tp_ext4_free_inode(struct tp_ext4_free_inode_t *ctx)
{
	struct ext4_free_inode_t event = {};

	event.base.type = EXT4_FREE_INODE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.uid = ctx->uid;
	event.gid = ctx->gid;
	event.blocks = ctx->blocks;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fsmap_high_key

SEC("racepoint/ext4/fsmap_high_key")
int tp_ext4_fsmap_high_key(struct tp_ext4_fsmap_high_key_t *ctx)
{
	struct ext4_fsmap_high_key_t event = {};

	event.base.type = EXT4_FSMAP_HIGH_KEY;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.keydev = ctx->keydev;
	event.agno = ctx->agno;
	event.bno = ctx->bno;
	event.len = ctx->len;
	event.owner = ctx->owner;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fsmap_low_key

SEC("racepoint/ext4/fsmap_low_key")
int tp_ext4_fsmap_low_key(struct tp_ext4_fsmap_low_key_t *ctx)
{
	struct ext4_fsmap_low_key_t event = {};

	event.base.type = EXT4_FSMAP_LOW_KEY;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.keydev = ctx->keydev;
	event.agno = ctx->agno;
	event.bno = ctx->bno;
	event.len = ctx->len;
	event.owner = ctx->owner;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_fsmap_mapping

SEC("racepoint/ext4/fsmap_mapping")
int tp_ext4_fsmap_mapping(struct tp_ext4_fsmap_mapping_t *ctx)
{
	struct ext4_fsmap_mapping_t event = {};

	event.base.type = EXT4_FSMAP_MAPPING;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.keydev = ctx->keydev;
	event.agno = ctx->agno;
	event.bno = ctx->bno;
	event.len = ctx->len;
	event.owner = ctx->owner;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_get_implied_cluster_alloc_exit

SEC("racepoint/ext4/get_implied_cluster_alloc_exit")
int tp_ext4_get_implied_cluster_alloc_exit(
	struct tp_ext4_get_implied_cluster_alloc_exit_t *ctx
)
{
	struct ext4_get_implied_cluster_alloc_exit_t event = {};

	event.base.type = EXT4_GET_IMPLIED_CLUSTER_ALLOC_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.flags = ctx->flags;
	event.lblk = ctx->lblk;
	event.pblk = ctx->pblk;
	event.len = ctx->len;
	event.ret = ctx->ret;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_getfsmap_high_key

SEC("racepoint/ext4/getfsmap_high_key")
int tp_ext4_getfsmap_high_key(struct tp_ext4_getfsmap_high_key_t *ctx)
{
	struct ext4_getfsmap_high_key_t event = {};

	event.base.type = EXT4_GETFSMAP_HIGH_KEY;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.keydev = ctx->keydev;
	event.block = ctx->block;
	event.len = ctx->len;
	event.owner = ctx->owner;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_getfsmap_low_key

SEC("racepoint/ext4/getfsmap_low_key")
int tp_ext4_getfsmap_low_key(struct tp_ext4_getfsmap_low_key_t *ctx)
{
	struct ext4_getfsmap_low_key_t event = {};

	event.base.type = EXT4_GETFSMAP_LOW_KEY;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.keydev = ctx->keydev;
	event.block = ctx->block;
	event.len = ctx->len;
	event.owner = ctx->owner;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_getfsmap_mapping

SEC("racepoint/ext4/getfsmap_mapping")
int tp_ext4_getfsmap_mapping(struct tp_ext4_getfsmap_mapping_t *ctx)
{
	struct ext4_getfsmap_mapping_t event = {};

	event.base.type = EXT4_GETFSMAP_MAPPING;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.keydev = ctx->keydev;
	event.block = ctx->block;
	event.len = ctx->len;
	event.owner = ctx->owner;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ind_map_blocks_enter

SEC("racepoint/ext4/ind_map_blocks_enter")
int tp_ext4_ind_map_blocks_enter(struct tp_ext4_ind_map_blocks_enter_t *ctx)
{
	struct ext4_ind_map_blocks_enter_t event = {};

	event.base.type = EXT4_IND_MAP_BLOCKS_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_ind_map_blocks_exit

SEC("racepoint/ext4/ind_map_blocks_exit")
int tp_ext4_ind_map_blocks_exit(struct tp_ext4_ind_map_blocks_exit_t *ctx)
{
	struct ext4_ind_map_blocks_exit_t event = {};

	event.base.type = EXT4_IND_MAP_BLOCKS_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.flags = ctx->flags;
	event.pblk = ctx->pblk;
	event.lblk = ctx->lblk;
	event.len = ctx->len;
	event.mflags = ctx->mflags;
	event.ret = ctx->ret;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_insert_range

SEC("racepoint/ext4/insert_range")
int tp_ext4_insert_range(struct tp_ext4_insert_range_t *ctx)
{
	struct ext4_insert_range_t event = {};

	event.base.type = EXT4_INSERT_RANGE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.offset = ctx->offset;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_invalidate_folio

SEC("racepoint/ext4/invalidate_folio")
int tp_ext4_invalidate_folio(struct tp_ext4_invalidate_folio_t *ctx)
{
	struct ext4_invalidate_folio_t event = {};

	event.base.type = EXT4_INVALIDATE_FOLIO;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.index = ctx->index;
	event.offset = ctx->offset;
	event.length = ctx->length;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_journal_start_inode

SEC("racepoint/ext4/journal_start_inode")
int tp_ext4_journal_start_inode(struct tp_ext4_journal_start_inode_t *ctx)
{
	struct ext4_journal_start_inode_t event = {};

	event.base.type = EXT4_JOURNAL_START_INODE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.ino = ctx->ino;
	event.dev = ctx->dev;
	event.ip = ctx->ip;
	event.blocks = ctx->blocks;
	event.rsv_blocks = ctx->rsv_blocks;
	event.revoke_creds = ctx->revoke_creds;
	event.type = ctx->type;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_journal_start_reserved

SEC("racepoint/ext4/journal_start_reserved")
int tp_ext4_journal_start_reserved(struct tp_ext4_journal_start_reserved_t *ctx)
{
	struct ext4_journal_start_reserved_t event = {};

	event.base.type = EXT4_JOURNAL_START_RESERVED;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ip = ctx->ip;
	event.blocks = ctx->blocks;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_journal_start_sb

SEC("racepoint/ext4/journal_start_sb")
int tp_ext4_journal_start_sb(struct tp_ext4_journal_start_sb_t *ctx)
{
	struct ext4_journal_start_sb_t event = {};

	event.base.type = EXT4_JOURNAL_START_SB;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ip = ctx->ip;
	event.blocks = ctx->blocks;
	event.rsv_blocks = ctx->rsv_blocks;
	event.revoke_creds = ctx->revoke_creds;
	event.type = ctx->type;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_journalled_invalidate_folio

SEC("racepoint/ext4/journalled_invalidate_folio")
int tp_ext4_journalled_invalidate_folio(
	struct tp_ext4_journalled_invalidate_folio_t *ctx
)
{
	struct ext4_journalled_invalidate_folio_t event = {};

	event.base.type = EXT4_JOURNALLED_INVALIDATE_FOLIO;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.index = ctx->index;
	event.offset = ctx->offset;
	event.length = ctx->length;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_journalled_write_end

SEC("racepoint/ext4/journalled_write_end")
int tp_ext4_journalled_write_end(struct tp_ext4_journalled_write_end_t *ctx)
{
	struct ext4_journalled_write_end_t event = {};

	event.base.type = EXT4_JOURNALLED_WRITE_END;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pos = ctx->pos;
	event.len = ctx->len;
	event.copied = ctx->copied;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_lazy_itable_init

SEC("racepoint/ext4/lazy_itable_init")
int tp_ext4_lazy_itable_init(struct tp_ext4_lazy_itable_init_t *ctx)
{
	struct ext4_lazy_itable_init_t event = {};

	event.base.type = EXT4_LAZY_ITABLE_INIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.group = ctx->group;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_load_inode

SEC("racepoint/ext4/load_inode")
int tp_ext4_load_inode(struct tp_ext4_load_inode_t *ctx)
{
	struct ext4_load_inode_t event = {};

	event.base.type = EXT4_LOAD_INODE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_load_inode_bitmap

SEC("racepoint/ext4/load_inode_bitmap")
int tp_ext4_load_inode_bitmap(struct tp_ext4_load_inode_bitmap_t *ctx)
{
	struct ext4_load_inode_bitmap_t event = {};

	event.base.type = EXT4_LOAD_INODE_BITMAP;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.group = ctx->group;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mark_inode_dirty

SEC("racepoint/ext4/mark_inode_dirty")
int tp_ext4_mark_inode_dirty(struct tp_ext4_mark_inode_dirty_t *ctx)
{
	struct ext4_mark_inode_dirty_t event = {};

	event.base.type = EXT4_MARK_INODE_DIRTY;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.ip = ctx->ip;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mb_bitmap_load

SEC("racepoint/ext4/mb_bitmap_load")
int tp_ext4_mb_bitmap_load(struct tp_ext4_mb_bitmap_load_t *ctx)
{
	struct ext4_mb_bitmap_load_t event = {};

	event.base.type = EXT4_MB_BITMAP_LOAD;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.group = ctx->group;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mb_buddy_bitmap_load

SEC("racepoint/ext4/mb_buddy_bitmap_load")
int tp_ext4_mb_buddy_bitmap_load(struct tp_ext4_mb_buddy_bitmap_load_t *ctx)
{
	struct ext4_mb_buddy_bitmap_load_t event = {};

	event.base.type = EXT4_MB_BUDDY_BITMAP_LOAD;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.group = ctx->group;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mb_discard_preallocations

SEC("racepoint/ext4/mb_discard_preallocations")
int tp_ext4_mb_discard_preallocations(
	struct tp_ext4_mb_discard_preallocations_t *ctx
)
{
	struct ext4_mb_discard_preallocations_t event = {};

	event.base.type = EXT4_MB_DISCARD_PREALLOCATIONS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.needed = ctx->needed;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mb_new_group_pa

SEC("racepoint/ext4/mb_new_group_pa")
int tp_ext4_mb_new_group_pa(struct tp_ext4_mb_new_group_pa_t *ctx)
{
	struct ext4_mb_new_group_pa_t event = {};

	event.base.type = EXT4_MB_NEW_GROUP_PA;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pa_pstart = ctx->pa_pstart;
	event.pa_lstart = ctx->pa_lstart;
	event.pa_len = ctx->pa_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mb_new_inode_pa

SEC("racepoint/ext4/mb_new_inode_pa")
int tp_ext4_mb_new_inode_pa(struct tp_ext4_mb_new_inode_pa_t *ctx)
{
	struct ext4_mb_new_inode_pa_t event = {};

	event.base.type = EXT4_MB_NEW_INODE_PA;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pa_pstart = ctx->pa_pstart;
	event.pa_lstart = ctx->pa_lstart;
	event.pa_len = ctx->pa_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mb_release_group_pa

SEC("racepoint/ext4/mb_release_group_pa")
int tp_ext4_mb_release_group_pa(struct tp_ext4_mb_release_group_pa_t *ctx)
{
	struct ext4_mb_release_group_pa_t event = {};

	event.base.type = EXT4_MB_RELEASE_GROUP_PA;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.pa_pstart = ctx->pa_pstart;
	event.pa_len = ctx->pa_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mb_release_inode_pa

SEC("racepoint/ext4/mb_release_inode_pa")
int tp_ext4_mb_release_inode_pa(struct tp_ext4_mb_release_inode_pa_t *ctx)
{
	struct ext4_mb_release_inode_pa_t event = {};

	event.base.type = EXT4_MB_RELEASE_INODE_PA;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.block = ctx->block;
	event.count = ctx->count;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mballoc_alloc

SEC("racepoint/ext4/mballoc_alloc")
int tp_ext4_mballoc_alloc(struct tp_ext4_mballoc_alloc_t *ctx)
{
	struct ext4_mballoc_alloc_t event = {};

	event.base.type = EXT4_MBALLOC_ALLOC;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.orig_logical = ctx->orig_logical;
	event.orig_start = ctx->orig_start;
	event.orig_group = ctx->orig_group;
	event.orig_len = ctx->orig_len;
	event.goal_logical = ctx->goal_logical;
	event.goal_start = ctx->goal_start;
	event.goal_group = ctx->goal_group;
	event.goal_len = ctx->goal_len;
	event.result_logical = ctx->result_logical;
	event.result_start = ctx->result_start;
	event.result_group = ctx->result_group;
	event.result_len = ctx->result_len;
	event.found = ctx->found;
	event.groups = ctx->groups;
	event.buddy = ctx->buddy;
	event.flags = ctx->flags;
	event.tail = ctx->tail;
	event.cr = ctx->cr;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mballoc_discard

SEC("racepoint/ext4/mballoc_discard")
int tp_ext4_mballoc_discard(struct tp_ext4_mballoc_discard_t *ctx)
{
	struct ext4_mballoc_discard_t event = {};

	event.base.type = EXT4_MBALLOC_DISCARD;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.result_start = ctx->result_start;
	event.result_group = ctx->result_group;
	event.result_len = ctx->result_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mballoc_free

SEC("racepoint/ext4/mballoc_free")
int tp_ext4_mballoc_free(struct tp_ext4_mballoc_free_t *ctx)
{
	struct ext4_mballoc_free_t event = {};

	event.base.type = EXT4_MBALLOC_FREE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.result_start = ctx->result_start;
	event.result_group = ctx->result_group;
	event.result_len = ctx->result_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_mballoc_prealloc

SEC("racepoint/ext4/mballoc_prealloc")
int tp_ext4_mballoc_prealloc(struct tp_ext4_mballoc_prealloc_t *ctx)
{
	struct ext4_mballoc_prealloc_t event = {};

	event.base.type = EXT4_MBALLOC_PREALLOC;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.orig_logical = ctx->orig_logical;
	event.orig_start = ctx->orig_start;
	event.orig_group = ctx->orig_group;
	event.orig_len = ctx->orig_len;
	event.result_logical = ctx->result_logical;
	event.result_start = ctx->result_start;
	event.result_group = ctx->result_group;
	event.result_len = ctx->result_len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_nfs_commit_metadata

SEC("racepoint/ext4/nfs_commit_metadata")
int tp_ext4_nfs_commit_metadata(struct tp_ext4_nfs_commit_metadata_t *ctx)
{
	struct ext4_nfs_commit_metadata_t event = {};

	event.base.type = EXT4_NFS_COMMIT_METADATA;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_other_inode_update_time

SEC("racepoint/ext4/other_inode_update_time")
int tp_ext4_other_inode_update_time(
	struct tp_ext4_other_inode_update_time_t *ctx
)
{
	struct ext4_other_inode_update_time_t event = {};

	event.base.type = EXT4_OTHER_INODE_UPDATE_TIME;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.orig_ino = ctx->orig_ino;
	event.uid = ctx->uid;
	event.gid = ctx->gid;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_prefetch_bitmaps

SEC("racepoint/ext4/prefetch_bitmaps")
int tp_ext4_prefetch_bitmaps(struct tp_ext4_prefetch_bitmaps_t *ctx)
{
	struct ext4_prefetch_bitmaps_t event = {};

	event.base.type = EXT4_PREFETCH_BITMAPS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.group = ctx->group;
	event.next = ctx->next;
	event.ios = ctx->ios;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_punch_hole

SEC("racepoint/ext4/punch_hole")
int tp_ext4_punch_hole(struct tp_ext4_punch_hole_t *ctx)
{
	struct ext4_punch_hole_t event = {};

	event.base.type = EXT4_PUNCH_HOLE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.offset = ctx->offset;
	event.len = ctx->len;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_read_block_bitmap_load

SEC("racepoint/ext4/read_block_bitmap_load")
int tp_ext4_read_block_bitmap_load(struct tp_ext4_read_block_bitmap_load_t *ctx)
{
	struct ext4_read_block_bitmap_load_t event = {};

	event.base.type = EXT4_READ_BLOCK_BITMAP_LOAD;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.group = ctx->group;
	event.prefetch = ctx->prefetch;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_read_folio

SEC("racepoint/ext4/read_folio")
int tp_ext4_read_folio(struct tp_ext4_read_folio_t *ctx)
{
	struct ext4_read_folio_t event = {};

	event.base.type = EXT4_READ_FOLIO;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.index = ctx->index;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_release_folio

SEC("racepoint/ext4/release_folio")
int tp_ext4_release_folio(struct tp_ext4_release_folio_t *ctx)
{
	struct ext4_release_folio_t event = {};

	event.base.type = EXT4_RELEASE_FOLIO;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.index = ctx->index;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_remove_blocks

SEC("racepoint/ext4/remove_blocks")
int tp_ext4_remove_blocks(struct tp_ext4_remove_blocks_t *ctx)
{
	struct ext4_remove_blocks_t event = {};

	event.base.type = EXT4_REMOVE_BLOCKS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.from = ctx->from;
	event.to = ctx->to;
	event.ee_pblk = ctx->ee_pblk;
	event.ee_lblk = ctx->ee_lblk;
	event.ee_len = ctx->ee_len;
	event.pc_pclu = ctx->pc_pclu;
	event.pc_lblk = ctx->pc_lblk;
	event.pc_state = ctx->pc_state;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_request_blocks

SEC("racepoint/ext4/request_blocks")
int tp_ext4_request_blocks(struct tp_ext4_request_blocks_t *ctx)
{
	struct ext4_request_blocks_t event = {};

	event.base.type = EXT4_REQUEST_BLOCKS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.len = ctx->len;
	event.logical = ctx->logical;
	event.lleft = ctx->lleft;
	event.lright = ctx->lright;
	event.goal = ctx->goal;
	event.pleft = ctx->pleft;
	event.pright = ctx->pright;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_request_inode

SEC("racepoint/ext4/request_inode")
int tp_ext4_request_inode(struct tp_ext4_request_inode_t *ctx)
{
	struct ext4_request_inode_t event = {};

	event.base.type = EXT4_REQUEST_INODE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.dir = ctx->dir;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_shutdown

SEC("racepoint/ext4/shutdown")
int tp_ext4_shutdown(struct tp_ext4_shutdown_t *ctx)
{
	struct ext4_shutdown_t event = {};

	event.base.type = EXT4_SHUTDOWN;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_sync_file_enter

SEC("racepoint/ext4/sync_file_enter")
int tp_ext4_sync_file_enter(struct tp_ext4_sync_file_enter_t *ctx)
{
	struct ext4_sync_file_enter_t event = {};

	event.base.type = EXT4_SYNC_FILE_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.parent = ctx->parent;
	event.datasync = ctx->datasync;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_sync_file_exit

SEC("racepoint/ext4/sync_file_exit")
int tp_ext4_sync_file_exit(struct tp_ext4_sync_file_exit_t *ctx)
{
	struct ext4_sync_file_exit_t event = {};

	event.base.type = EXT4_SYNC_FILE_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.ret = ctx->ret;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_sync_fs

SEC("racepoint/ext4/sync_fs")
int tp_ext4_sync_fs(struct tp_ext4_sync_fs_t *ctx)
{
	struct ext4_sync_fs_t event = {};

	event.base.type = EXT4_SYNC_FS;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.wait = ctx->wait;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_trim_all_free

SEC("racepoint/ext4/trim_all_free")
int tp_ext4_trim_all_free(struct tp_ext4_trim_all_free_t *ctx)
{
	struct ext4_trim_all_free_t event = {};

	event.base.type = EXT4_TRIM_ALL_FREE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev_major = ctx->dev_major;
	event.dev_minor = ctx->dev_minor;
	event.group = ctx->group;
	event.start = ctx->start;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_trim_extent

SEC("racepoint/ext4/trim_extent")
int tp_ext4_trim_extent(struct tp_ext4_trim_extent_t *ctx)
{
	struct ext4_trim_extent_t event = {};

	event.base.type = EXT4_TRIM_EXTENT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev_major = ctx->dev_major;
	event.dev_minor = ctx->dev_minor;
	event.group = ctx->group;
	event.start = ctx->start;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_truncate_enter

SEC("racepoint/ext4/truncate_enter")
int tp_ext4_truncate_enter(struct tp_ext4_truncate_enter_t *ctx)
{
	struct ext4_truncate_enter_t event = {};

	event.base.type = EXT4_TRUNCATE_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.blocks = ctx->blocks;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_truncate_exit

SEC("racepoint/ext4/truncate_exit")
int tp_ext4_truncate_exit(struct tp_ext4_truncate_exit_t *ctx)
{
	struct ext4_truncate_exit_t event = {};

	event.base.type = EXT4_TRUNCATE_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.blocks = ctx->blocks;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_unlink_enter

SEC("racepoint/ext4/unlink_enter")
int tp_ext4_unlink_enter(struct tp_ext4_unlink_enter_t *ctx)
{
	struct ext4_unlink_enter_t event = {};

	event.base.type = EXT4_UNLINK_ENTER;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.parent = ctx->parent;
	event.size = ctx->size;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_unlink_exit

SEC("racepoint/ext4/unlink_exit")
int tp_ext4_unlink_exit(struct tp_ext4_unlink_exit_t *ctx)
{
	struct ext4_unlink_exit_t event = {};

	event.base.type = EXT4_UNLINK_EXIT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.ret = ctx->ret;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_update_sb

SEC("racepoint/ext4/update_sb")
int tp_ext4_update_sb(struct tp_ext4_update_sb_t *ctx)
{
	struct ext4_update_sb_t event = {};

	event.base.type = EXT4_UPDATE_SB;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.fsblk = ctx->fsblk;
	event.flags = ctx->flags;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_write_begin

SEC("racepoint/ext4/write_begin")
int tp_ext4_write_begin(struct tp_ext4_write_begin_t *ctx)
{
	struct ext4_write_begin_t event = {};

	event.base.type = EXT4_WRITE_BEGIN;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pos = ctx->pos;
	event.len = ctx->len;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_write_end

SEC("racepoint/ext4/write_end")
int tp_ext4_write_end(struct tp_ext4_write_end_t *ctx)
{
	struct ext4_write_end_t event = {};

	event.base.type = EXT4_WRITE_END;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.pos = ctx->pos;
	event.len = ctx->len;
	event.copied = ctx->copied;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_writepages

SEC("racepoint/ext4/writepages")
int tp_ext4_writepages(struct tp_ext4_writepages_t *ctx)
{
	struct ext4_writepages_t event = {};

	event.base.type = EXT4_WRITEPAGES;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.nr_to_write = ctx->nr_to_write;
	event.pages_skipped = ctx->pages_skipped;
	event.range_start = ctx->range_start;
	event.range_end = ctx->range_end;
	event.writeback_index = ctx->writeback_index;
	event.sync_mode = ctx->sync_mode;
	event.for_kupdate = ctx->for_kupdate;
	event.range_cyclic = ctx->range_cyclic;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_writepages_result

SEC("racepoint/ext4/writepages_result")
int tp_ext4_writepages_result(struct tp_ext4_writepages_result_t *ctx)
{
	struct ext4_writepages_result_t event = {};

	event.base.type = EXT4_WRITEPAGES_RESULT;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.ret = ctx->ret;
	event.pages_written = ctx->pages_written;
	event.pages_skipped = ctx->pages_skipped;
	event.writeback_index = ctx->writeback_index;
	event.sync_mode = ctx->sync_mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Implementation for tp_ext4_zero_range

SEC("racepoint/ext4/zero_range")
int tp_ext4_zero_range(struct tp_ext4_zero_range_t *ctx)
{
	struct ext4_zero_range_t event = {};

	event.base.type = EXT4_ZERO_RANGE;
	event.base.timestamp = bpf_ktime_get_ns();
	event.base.pid = bpf_get_current_pid_tgid() >> 32;
	event.base.tid = (pid_t)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
	event.dev = ctx->dev;
	event.ino = ctx->ino;
	event.offset = ctx->offset;
	event.len = ctx->len;
	event.mode = ctx->mode;

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
