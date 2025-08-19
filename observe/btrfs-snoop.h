#pragma once

#define TASK_COMM_LEN 16

enum btrfs_event_type
{
	BTRFS_EXTENT_WRITEPAGE = 0,
	BTRFS_ADD_DELAYED_DATA_REF,
	BTRFS_ADD_DELAYED_REF_HEAD,
	BTRFS_ADD_DELAYED_TREE_REF,
	BTRFS_ALLOC_EXTENT_STATE,
	BTRFS_ADD_BLOCK_GROUP,
	BTRFS_ADD_RECLAIM_BLOCK_GROUP,
	BTRFS_ADD_UNUSED_BLOCK_GROUP,
	BTRFS_ALL_WORK_DONE,
	BTRFS_CHUNK_ALLOC,
	BTRFS_CHUNK_FREE,
	BTRFS_CLEAR_EXTENT_BIT,
	BTRFS_CONVERT_EXTENT_BIT,
	BTRFS_COW_BLOCK,
	BTRFS_DONE_PREEMPTIVE_RECLAIM,
	BTRFS_FAIL_ALL_TICKETS,
	BTRFS_FAILED_CLUSTER_SETUP,
	BTRFS_FIND_CLUSTER,
	BTRFS_FINISH_ORDERED_EXTENT,
	BTRFS_FLUSH_SPACE,
	BTRFS_GET_EXTENT,
	BTRFS_GET_EXTENT_SHOW_FI_INLINE,
	BTRFS_GET_EXTENT_SHOW_FI_REGULAR,
	BTRFS_HANDLE_EM_EXIST,
	BTRFS_INODE_EVICT,
	BTRFS_INODE_MOD_OUTSTANDING_EXTENTS,
	BTRFS_INODE_NEW,
	BTRFS_INODE_REQUEST,
	BTRFS_ORDERED_EXTENT_ADD,
	BTRFS_ORDERED_EXTENT_DEC_TEST_PENDING,
	BTRFS_ORDERED_EXTENT_LOOKUP,
	BTRFS_ORDERED_EXTENT_LOOKUP_FIRST,
	BTRFS_ORDERED_EXTENT_LOOKUP_FIRST_RANGE,
	BTRFS_ORDERED_EXTENT_LOOKUP_FOR_LOGGING,
	BTRFS_ORDERED_EXTENT_LOOKUP_RANGE,
	BTRFS_ORDERED_EXTENT_MARK_FINISHED,
	BTRFS_ORDERED_EXTENT_PUT,
	BTRFS_ORDERED_EXTENT_REMOVE,
	BTRFS_ORDERED_EXTENT_SPLIT,
	BTRFS_ORDERED_EXTENT_START,
	BTRFS_ORDERED_SCHED,
	BTRFS_PRELIM_REF_INSERT,
	BTRFS_PRELIM_REF_MERGE,
	BTRFS_QGROUP_ACCOUNT_EXTENT,
	BTRFS_QGROUP_ACCOUNT_EXTENTS,
	BTRFS_QGROUP_RELEASE_DATA,
	BTRFS_QGROUP_RESERVE_DATA,
	BTRFS_QGROUP_TRACE_EXTENT,
	BTRFS_RECLAIM_BLOCK_GROUP,
	BTRFS_REMOVE_BLOCK_GROUP,
	BTRFS_RESERVE_EXTENT,
	BTRFS_RESERVE_EXTENT_CLUSTER,
	BTRFS_RESERVE_TICKET,
	BTRFS_RESERVED_EXTENT_ALLOC,
	BTRFS_RESERVED_EXTENT_FREE,
	BTRFS_SET_EXTENT_BIT,
	BTRFS_SET_LOCK_BLOCKING_READ,
	BTRFS_SET_LOCK_BLOCKING_WRITE,
	BTRFS_SETUP_CLUSTER,
	BTRFS_SKIP_UNUSED_BLOCK_GROUP,
	BTRFS_SPACE_RESERVATION,
	BTRFS_SYNC_FILE,
	BTRFS_SYNC_FS,
	BTRFS_TRANSACTION_COMMIT,
	BTRFS_TREE_LOCK,
	BTRFS_TREE_READ_LOCK,
	BTRFS_TREE_READ_LOCK_ATOMIC,
	BTRFS_TREE_READ_UNLOCK,
	BTRFS_TREE_READ_UNLOCK_BLOCKING,
	BTRFS_TREE_UNLOCK,
	BTRFS_TRIGGER_FLUSH,
	BTRFS_TRUNCATE_SHOW_FI_INLINE,
	BTRFS_TRUNCATE_SHOW_FI_REGULAR,
	BTRFS_TRY_TREE_READ_LOCK,
	BTRFS_TRY_TREE_WRITE_LOCK,
	BTRFS_WORK_QUEUED,
	BTRFS_WORK_SCHED,
	BTRFS_WORKQUEUE_ALLOC,
	BTRFS_WORKQUEUE_DESTROY,
	BTRFS_WRITEPAGE_END_IO_HOOK,
	BTRFS_FIND_FREE_EXTENT,
	BTRFS_FIND_FREE_EXTENT_HAVE_BLOCK_GROUP,
	BTRFS_FIND_FREE_EXTENT_SEARCH_LOOP,
	BTRFS_FREE_EXTENT_STATE,
	BTRFS_QGROUP_META_CONVERT,
	BTRFS_QGROUP_META_FREE_ALL_PERTRANS,
	BTRFS_QGROUP_META_RESERVE,
	BTRFS_QGROUP_NUM_DIRTY_EXTENTS,
	BTRFS_QGROUP_UPDATE_COUNTERS,
	BTRFS_QGROUP_UPDATE_RESERVE,
	BTRFS_RAID56_READ,
	BTRFS_RAID56_WRITE,
	BTRFS_RUN_DELAYED_DATA_REF,
	BTRFS_RUN_DELAYED_REF_HEAD,
	BTRFS_RUN_DELAYED_TREE_REF,
	BTRFS_UPDATE_BYTES_MAY_USE,
	BTRFS_UPDATE_BYTES_PINNED,
	BTRFS_UPDATE_BYTES_ZONE_UNUSABLE,
};

// 通用事件结构
struct btrfs_base_event
{
	__u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	__u64 timestamp;
};

// 具体事件结构
struct btrfs_extent_writepage_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	unsigned long index;
	long nr_to_write;
	long pages_skipped;
	loff_t range_start;
	loff_t range_end;
	char for_kupdate;
	char for_reclaim;
	char range_cyclic;
	unsigned long writeback_index;
	__u64 root_objectid;
};

struct btrfs_add_delayed_data_ref_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 num_bytes;
	int action;
	__u64 parent;
	__u64 ref_root;
	__u64 owner;
	__u64 offset;
	int type;
	__u64 seq;
};

struct btrfs_add_delayed_ref_head_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 num_bytes;
	int action;
	int is_data;
};

struct btrfs_add_delayed_tree_ref_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 num_bytes;
	int action;
	__u64 parent;
	__u64 ref_root;
	int level;
	int type;
	__u64 seq;
};

struct btrfs_alloc_extent_state_event
{
	struct btrfs_base_event base;
	__u32 state;
	unsigned long mask;
	long ip;
};

struct btrfs_add_block_group_event
{
	struct btrfs_base_event base;
	int common_pid;
	__u8 fsid[16];
	__u64 offset;
	__u64 size;
	__u64 flags;
	__u64 bytes_used;
	__u64 bytes_super;
	int create;
};

struct btrfs_add_reclaim_block_group_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 len;
	__u64 used;
	__u64 flags;
};

struct btrfs_add_unused_block_group_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 len;
	__u64 used;
	__u64 flags;
};

struct btrfs_all_work_done_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	const void *wtag;
};

struct btrfs_chunk_alloc_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	int num_stripes;
	__u64 type;
	int sub_stripes;
	__u64 offset;
	__u64 size;
	__u64 root_objectid;
};

struct btrfs_chunk_free_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	int num_stripes;
	__u64 type;
	int sub_stripes;
	__u64 offset;
	__u64 size;
	__u64 root_objectid;
};

struct btrfs_clear_extent_bit_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	unsigned owner;
	__u64 ino;
	__u64 rootid;
	__u64 start;
	__u64 len;
	unsigned clear_bits;
};

struct btrfs_convert_extent_bit_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	unsigned owner;
	__u64 ino;
	__u64 rootid;
	__u64 start;
	__u64 len;
	unsigned set_bits;
	unsigned clear_bits;
};

struct btrfs_cow_block_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_objectid;
	__u64 buf_start;
	int refs;
	__u64 cow_start;
	int buf_level;
	int cow_level;
};

struct btrfs_done_preemptive_reclaim_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 flags;
	__u64 total_bytes;
	__u64 bytes_used;
	__u64 bytes_pinned;
	__u64 bytes_reserved;
	__u64 bytes_may_use;
	__u64 bytes_readonly;
	__u64 reclaim_size;
	int clamp;
	__u64 global_reserved;
	__u64 trans_reserved;
	__u64 delayed_refs_reserved;
	__u64 delayed_reserved;
	__u64 free_chunk_space;
	__u64 delalloc_bytes;
	__u64 ordered_bytes;
};

struct btrfs_fail_all_tickets_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 flags;
	__u64 total_bytes;
	__u64 bytes_used;
	__u64 bytes_pinned;
	__u64 bytes_reserved;
	__u64 bytes_may_use;
	__u64 bytes_readonly;
	__u64 reclaim_size;
	int clamp;
	__u64 global_reserved;
	__u64 trans_reserved;
	__u64 delayed_refs_reserved;
	__u64 delayed_reserved;
	__u64 free_chunk_space;
	__u64 delalloc_bytes;
	__u64 ordered_bytes;
};

struct btrfs_failed_cluster_setup_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bg_objectid;
};

struct btrfs_find_cluster_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bg_objectid;
	__u64 flags;
	__u64 start;
	__u64 bytes;
	__u64 empty_size;
	__u64 min_bytes;
};

struct btrfs_finish_ordered_extent_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 start;
	__u64 len;
	bool uptodate;
	__u64 root_objectid;
};

struct btrfs_flush_space_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 flags;
	__u64 num_bytes;
	int state;
	int ret;
	bool for_preempt;
};

struct btrfs_get_extent_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_objectid;
	__u64 ino;
	__u64 start;
	__u64 len;
	__u64 orig_start;
	__u64 block_start;
	__u64 block_len;
	unsigned long flags;
	int refs;
	unsigned int compress_type;
};

struct btrfs_get_extent_show_fi_inline_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_obj;
	__u64 ino;
	loff_t isize;
	__u64 disk_isize;
	__u8 extent_type;
	__u8 compression;
	__u64 extent_start;
	__u64 extent_end;
};

struct btrfs_get_extent_show_fi_regular_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_obj;
	__u64 ino;
	loff_t isize;
	__u64 disk_isize;
	__u64 num_bytes;
	__u64 ram_bytes;
	__u64 disk_bytenr;
	__u64 disk_num_bytes;
	__u64 extent_offset;
	__u8 extent_type;
	__u8 compression;
	__u64 extent_start;
	__u64 extent_end;
};

struct btrfs_handle_em_exist_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 e_start;
	__u64 e_len;
	__u64 map_start;
	__u64 map_len;
	__u64 start;
	__u64 len;
};

struct btrfs_inode_evict_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 blocks;
	__u64 disk_i_size;
	__u64 generation;
	__u64 last_trans;
	__u64 logged_trans;
	__u64 root_objectid;
};

struct btrfs_inode_mod_outstanding_extents_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_objectid;
	__u64 ino;
	int mod;
	unsigned outstanding;
};

struct btrfs_inode_new_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 blocks;
	__u64 disk_i_size;
	__u64 generation;
	__u64 last_trans;
	__u64 logged_trans;
	__u64 root_objectid;
};

struct btrfs_inode_request_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 blocks;
	__u64 disk_i_size;
	__u64 generation;
	__u64 last_trans;
	__u64 logged_trans;
	__u64 root_objectid;
};

struct btrfs_ordered_extent_add_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_dec_test_pending_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_lookup_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_lookup_first_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_lookup_first_range_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_lookup_for_logging_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_lookup_range_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_mark_finished_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_put_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_remove_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_split_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_extent_start_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 file_offset;
	__u64 start;
	__u64 len;
	__u64 disk_len;
	__u64 bytes_left;
	unsigned long flags;
	int compress_type;
	int refs;
	__u64 root_objectid;
	__u64 truncated_len;
};

struct btrfs_ordered_sched_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	const void *work;
	const void *wq;
	const void *func;
	const void *ordered_func;
	const void *ordered_free;
	const void *normal_work;
};

struct btrfs_prelim_ref_insert_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_id;
	__u64 objectid;
	__u8 type;
	__u64 offset;
	int level;
	int old_count;
	__u64 parent;
	__u64 bytenr;
	int mod_count;
	__u64 tree_size;
};

struct btrfs_prelim_ref_merge_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_id;
	__u64 objectid;
	__u8 type;
	__u64 offset;
	int level;
	int old_count;
	__u64 parent;
	__u64 bytenr;
	int mod_count;
	__u64 tree_size;
};

struct btrfs_qgroup_account_extent_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 transid;
	__u64 bytenr;
	__u64 num_bytes;
	__u64 nr_old_roots;
	__u64 nr_new_roots;
};

struct btrfs_qgroup_account_extents_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 num_bytes;
};

struct btrfs_qgroup_meta_convert_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 refroot;
	__s64 diff;
};

struct btrfs_qgroup_meta_free_all_pertrans_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 refroot;
	__s64 diff;
	int type;
};

struct btrfs_qgroup_meta_reserve_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 refroot;
	__s64 diff;
	int type;
};

struct btrfs_qgroup_num_dirty_extents_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 transid;
	__u64 num_dirty_extents;
};

struct btrfs_qgroup_release_data_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 rootid;
	__u64 ino;
	__u64 start;
	__u64 len;
	__u64 reserved;
	int op;
};

struct btrfs_qgroup_reserve_data_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 rootid;
	__u64 ino;
	__u64 start;
	__u64 len;
	__u64 reserved;
	int op;
};

struct btrfs_qgroup_trace_extent_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 num_bytes;
};

struct btrfs_qgroup_update_counters_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 qgid;
	__u64 old_rfer;
	__u64 old_excl;
	__u64 cur_old_count;
	__u64 cur_new_count;
};

struct btrfs_qgroup_update_reserve_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 qgid;
	__u64 cur_reserved;
	__s64 diff;
	int type;
};

struct btrfs_raid56_read_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 full_stripe;
	__u64 physical;
	__u64 devid;
	__u32 offset;
	__u32 len;
	__u8 opf;
	__u8 total_stripes;
	__u8 real_stripes;
	__u8 nr_data;
	__u8 stripe_nr;
};

struct btrfs_raid56_write_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 full_stripe;
	__u64 physical;
	__u64 devid;
	__u32 offset;
	__u32 len;
	__u8 opf;
	__u8 total_stripes;
	__u8 real_stripes;
	__u8 nr_data;
	__u8 stripe_nr;
};

struct btrfs_reclaim_block_group_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 len;
	__u64 used;
	__u64 flags;
};

struct btrfs_remove_block_group_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 len;
	__u64 used;
	__u64 flags;
};

struct btrfs_reserve_extent_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bg_objectid;
	__u64 flags;
	int bg_size_class;
	__u64 start;
	__u64 len;
	__u64 loop;
	bool hinted;
	int size_class;
};

struct btrfs_reserve_extent_cluster_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bg_objectid;
	__u64 flags;
	int bg_size_class;
	__u64 start;
	__u64 len;
	__u64 loop;
	bool hinted;
	int size_class;
};

struct btrfs_reserve_ticket_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 flags;
	__u64 bytes;
	__u64 start_ns;
	int flush;
	int error;
};

struct btrfs_reserved_extent_alloc_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 start;
	__u64 len;
};

struct btrfs_reserved_extent_free_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 start;
	__u64 len;
};

struct btrfs_set_extent_bit_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	unsigned owner;
	__u64 ino;
	__u64 rootid;
	__u64 start;
	__u64 len;
	unsigned set_bits;
};

struct btrfs_set_lock_blocking_read_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_set_lock_blocking_write_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_setup_cluster_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bg_objectid;
	__u64 flags;
	__u64 start;
	__u64 max_size;
	__u64 size;
	int bitmap;
};

struct btrfs_skip_unused_block_group_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 len;
	__u64 used;
	__u64 flags;
};

struct btrfs_space_reservation_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	char *type;
	__u64 val;
	__u64 bytes;
	int reserve;
};

struct btrfs_sync_file_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 parent;
	int datasync;
	__u64 root_objectid;
};

struct btrfs_sync_fs_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	int wait;
};

struct btrfs_transaction_commit_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 generation;
	__u64 root_objectid;
};

struct btrfs_tree_lock_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 start_ns;
	__u64 end_ns;
	__u64 diff_ns;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_tree_read_lock_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 start_ns;
	__u64 end_ns;
	__u64 diff_ns;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_tree_read_lock_atomic_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_tree_read_unlock_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_tree_read_unlock_blocking_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_tree_unlock_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_trigger_flush_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 flags;
	__u64 bytes;
	int flush;
	char *reason;
};

struct btrfs_truncate_show_fi_inline_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_obj;
	__u64 ino;
	loff_t isize;
	__u64 disk_isize;
	__u8 extent_type;
	__u8 compression;
	__u64 extent_start;
	__u64 extent_end;
};

struct btrfs_truncate_show_fi_regular_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_obj;
	__u64 ino;
	loff_t isize;
	__u64 disk_isize;
	__u64 num_bytes;
	__u64 ram_bytes;
	__u64 disk_bytenr;
	__u64 disk_num_bytes;
	__u64 extent_offset;
	__u8 extent_type;
	__u8 compression;
	__u64 extent_start;
	__u64 extent_end;
};

struct btrfs_try_tree_read_lock_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_try_tree_write_lock_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 block;
	__u64 generation;
	__u64 owner;
	int is_log_tree;
};

struct btrfs_update_bytes_may_use_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 type;
	__u64 old;
	__s64 diff;
};

struct btrfs_update_bytes_pinned_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 type;
	__u64 old;
	__s64 diff;
};

struct btrfs_update_bytes_zone_unusable_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 type;
	__u64 old;
	__s64 diff;
};

struct btrfs_work_queued_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	const void *work;
	const void *wq;
	const void *func;
	const void *ordered_func;
	const void *ordered_free;
	const void *normal_work;
};

struct btrfs_work_sched_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	const void *work;
	const void *wq;
	const void *func;
	const void *ordered_func;
	const void *ordered_free;
	const void *normal_work;
};

struct btrfs_workqueue_alloc_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	const void *wq;
	char *name;
};

struct btrfs_workqueue_destroy_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	const void *wq;
};

struct btrfs_writepage_end_io_hook_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 ino;
	__u64 start;
	__u64 end;
	int uptodate;
	__u64 root_objectid;
};

struct btrfs_run_delayed_ref_head_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 num_bytes;
	int action;
	int is_data;
};

struct btrfs_run_delayed_data_ref_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 num_bytes;
	int action;
	__u64 parent;
	__u64 ref_root;
	__u64 owner;
	__u64 offset;
	int type;
	__u64 seq;
};

struct btrfs_run_delayed_tree_ref_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 bytenr;
	__u64 num_bytes;
	int action;
	__u64 parent;
	__u64 ref_root;
	int level;
	int type;
	__u64 seq;
};

struct btrfs_find_free_extent_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_objectid;
	__u64 num_bytes;
	__u64 empty_size;
	__u64 flags;
};

struct btrfs_find_free_extent_have_block_group_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_objectid;
	__u64 num_bytes;
	__u64 empty_size;
	__u64 flags;
	__u64 loop;
	bool hinted;
	__u64 bg_start;
	__u64 bg_flags;
};

struct btrfs_find_free_extent_search_loop_event
{
	struct btrfs_base_event base;
	__u8 fsid[16];
	__u64 root_objectid;
	__u64 num_bytes;
	__u64 empty_size;
	__u64 flags;
	__u64 loop;
};

struct btrfs_free_extent_state_event
{
	struct btrfs_base_event base;
	__u32 state;
	unsigned long ip;
};