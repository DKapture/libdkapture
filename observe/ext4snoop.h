#pragma once

enum ext4_event_type
{
	EXT4_ALLOC_DA_BLOCKS,
	EXT4_ALLOCATE_BLOCKS,
	EXT4_ALLOCATE_INODE,
	EXT4_BEGIN_ORDERED_TRUNCATE,
	EXT4_COLLAPSE_RANGE,
	EXT4_DA_RELEASE_SPACE,
	EXT4_DA_RESERVE_SPACE,
	EXT4_DA_UPDATE_RESERVE_SPACE,
	EXT4_DA_WRITE_BEGIN,
	EXT4_DA_WRITE_END,
	EXT4_DA_WRITE_PAGES,
	EXT4_DA_WRITE_PAGES_EXTENT,
	EXT4_DISCARD_BLOCKS,
	EXT4_DISCARD_PREALLOCATIONS,
	EXT4_DROP_INODE,
	EXT4_ERROR,
	EXT4_ES_CACHE_EXTENT,
	EXT4_ES_FIND_EXTENT_RANGE_ENTER,
	EXT4_ES_FIND_EXTENT_RANGE_EXIT,
	EXT4_ES_INSERT_DELAYED_BLOCK,
	EXT4_ES_INSERT_EXTENT,
	EXT4_ES_LOOKUP_EXTENT_ENTER,
	EXT4_ES_LOOKUP_EXTENT_EXIT,
	EXT4_ES_REMOVE_EXTENT,
	EXT4_ES_SHRINK,
	EXT4_ES_SHRINK_COUNT,
	EXT4_ES_SHRINK_SCAN_ENTER,
	EXT4_ES_SHRINK_SCAN_EXIT,
	EXT4_EVICT_INODE,
	EXT4_EXT_CONVERT_TO_INITIALIZED_ENTER,
	EXT4_EXT_CONVERT_TO_INITIALIZED_FASTPATH,
	EXT4_EXT_HANDLE_UNWRITTEN_EXTENTS,
	EXT4_EXT_LOAD_EXTENT,
	EXT4_EXT_MAP_BLOCKS_ENTER,
	EXT4_EXT_MAP_BLOCKS_EXIT,
	EXT4_EXT_REMOVE_SPACE,
	EXT4_EXT_REMOVE_SPACE_DONE,
	EXT4_EXT_RM_IDX,
	EXT4_EXT_RM_LEAF,
	EXT4_EXT_SHOW_EXTENT,
	EXT4_FALLOCATE_ENTER,
	EXT4_FALLOCATE_EXIT,
	EXT4_FC_CLEANUP,
	EXT4_FC_COMMIT_START,
	EXT4_FC_COMMIT_STOP,
	EXT4_FC_REPLAY,
	EXT4_FC_REPLAY_SCAN,
	EXT4_FC_STATS,
	EXT4_FC_TRACK_CREATE,
	EXT4_FC_TRACK_INODE,
	EXT4_FC_TRACK_LINK,
	EXT4_FC_TRACK_RANGE,
	EXT4_FC_TRACK_UNLINK,
	EXT4_FORGET,
	EXT4_FREE_BLOCKS,
	EXT4_FREE_INODE,
	EXT4_FSMAP_HIGH_KEY,
	EXT4_FSMAP_LOW_KEY,
	EXT4_FSMAP_MAPPING,
	EXT4_GET_IMPLIED_CLUSTER_ALLOC_EXIT,
	EXT4_GETFSMAP_HIGH_KEY,
	EXT4_GETFSMAP_LOW_KEY,
	EXT4_GETFSMAP_MAPPING,
	EXT4_IND_MAP_BLOCKS_ENTER,
	EXT4_IND_MAP_BLOCKS_EXIT,
	EXT4_INSERT_RANGE,
	EXT4_INVALIDATE_FOLIO,
	EXT4_JOURNAL_START_INODE,
	EXT4_JOURNAL_START_RESERVED,
	EXT4_JOURNAL_START_SB,
	EXT4_JOURNALLED_INVALIDATE_FOLIO,
	EXT4_JOURNALLED_WRITE_END,
	EXT4_LAZY_ITABLE_INIT,
	EXT4_LOAD_INODE,
	EXT4_LOAD_INODE_BITMAP,
	EXT4_MARK_INODE_DIRTY,
	EXT4_MB_BITMAP_LOAD,
	EXT4_MB_BUDDY_BITMAP_LOAD,
	EXT4_MB_DISCARD_PREALLOCATIONS,
	EXT4_MB_NEW_GROUP_PA,
	EXT4_MB_NEW_INODE_PA,
	EXT4_MB_RELEASE_GROUP_PA,
	EXT4_MB_RELEASE_INODE_PA,
	EXT4_MBALLOC_ALLOC,
	EXT4_MBALLOC_DISCARD,
	EXT4_MBALLOC_FREE,
	EXT4_MBALLOC_PREALLOC,
	EXT4_NFS_COMMIT_METADATA,
	EXT4_OTHER_INODE_UPDATE_TIME,
	EXT4_PREFETCH_BITMAPS,
	EXT4_PUNCH_HOLE,
	EXT4_READ_BLOCK_BITMAP_LOAD,
	EXT4_READ_FOLIO,
	EXT4_RELEASE_FOLIO,
	EXT4_REMOVE_BLOCKS,
	EXT4_REQUEST_BLOCKS,
	EXT4_REQUEST_INODE,
	EXT4_SHUTDOWN,
	EXT4_SYNC_FILE_ENTER,
	EXT4_SYNC_FILE_EXIT,
	EXT4_SYNC_FS,
	EXT4_TRIM_ALL_FREE,
	EXT4_TRIM_EXTENT,
	EXT4_TRUNCATE_ENTER,
	EXT4_TRUNCATE_EXIT,
	EXT4_UNLINK_ENTER,
	EXT4_UNLINK_EXIT,
	EXT4_UPDATE_SB,
	EXT4_WRITE_BEGIN,
	EXT4_WRITE_END,
	EXT4_WRITEPAGES,
	EXT4_WRITEPAGES_RESULT,
	EXT4_ZERO_RANGE,
};

struct ext4_event_base_t
{
	enum ext4_event_type type;
	pid_t pid;
	pid_t tid;
	char comm[16];
	__u64 timestamp;
};

struct ext4_alloc_da_blocks_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned int data_blocks;
};

struct ext4_allocate_blocks_t
{
	struct ext4_event_base_t base;
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

struct ext4_allocate_inode_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	ino_t dir;
	__u16 mode;
};

struct ext4_begin_ordered_truncate_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t new_size;
};

struct ext4_collapse_range_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
};

struct ext4_da_release_space_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 i_blocks;
	int freed_blocks;
	int reserved_data_blocks;
	__u16 mode;
};

struct ext4_da_reserve_space_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 i_blocks;
	int reserved_data_blocks;
	__u16 mode;
};

struct ext4_da_update_reserve_space_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 i_blocks;
	int used_blocks;
	int reserved_data_blocks;
	int quota_claim;
	__u16 mode;
};

struct ext4_da_write_begin_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
};

struct ext4_da_write_end_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
	unsigned int copied;
};

struct ext4_da_write_pages_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned long first_page;
	long nr_to_write;
	int sync_mode;
};

struct ext4_da_write_pages_extent_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 lblk;
	__u32 len;
	__u32 flags;
};

struct ext4_discard_blocks_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u64 blk;
	__u64 count;
};

struct ext4_discard_preallocations_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned int len;
	unsigned int needed;
};

struct ext4_drop_inode_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	int drop;
};

struct ext4_error_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	char function[64];
	unsigned line;
};

struct ext4_es_cache_extent_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
};

struct ext4_es_find_extent_range_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
};

struct ext4_es_find_extent_range_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
};

struct ext4_es_insert_delayed_block_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
	bool allocated;
};

struct ext4_es_insert_extent_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
};

struct ext4_es_lookup_extent_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
};

struct ext4_es_lookup_extent_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	__u32 len;
	__u64 pblk;
	char status;
	int found;
};

struct ext4_es_remove_extent_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t lblk;
	loff_t len;
};

struct ext4_es_shrink_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int nr_shrunk;
	unsigned long long scan_time;
	int nr_skipped;
	int retried;
};

struct ext4_es_shrink_count_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int nr_to_scan;
	int cache_cnt;
};

struct ext4_es_shrink_scan_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int nr_to_scan;
	int cache_cnt;
};

struct ext4_es_shrink_scan_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int nr_shrunk;
	int cache_cnt;
};

struct ext4_evict_inode_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	int nlink;
};

struct ext4_ext_convert_to_initialized_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 m_lblk;
	unsigned m_len;
	__u32 u_lblk;
	unsigned u_len;
	__u64 u_pblk;
};

struct ext4_ext_convert_to_initialized_fastpath_t
{
	struct ext4_event_base_t base;
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

struct ext4_ext_handle_unwritten_extents_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	int flags;
	__u32 lblk;
	__u64 pblk;
	unsigned int len;
	unsigned int allocated;
	__u64 newblk;
};

struct ext4_ext_load_extent_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 pblk;
	__u32 lblk;
};

struct ext4_ext_map_blocks_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	unsigned int len;
	unsigned int flags;
};

struct ext4_ext_map_blocks_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned int flags;
	__u64 pblk;
	__u32 lblk;
	unsigned int len;
	unsigned int mflags;
	int ret;
};

struct ext4_ext_remove_space_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 start;
	__u32 end;
	int depth;
};

struct ext4_ext_remove_space_done_t
{
	struct ext4_event_base_t base;
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

struct ext4_ext_rm_idx_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 pblk;
};

struct ext4_ext_rm_leaf_t
{
	struct ext4_event_base_t base;
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

struct ext4_ext_show_extent_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 pblk;
	__u32 lblk;
	unsigned short len;
};

struct ext4_fallocate_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
	int mode;
};

struct ext4_fallocate_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int blocks;
	int ret;
};

struct ext4_fc_cleanup_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int j_fc_off;
	int full;
	unsigned int tid;
};

struct ext4_fc_commit_start_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned int tid;
};

struct ext4_fc_commit_stop_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int nblks;
	int reason;
	int num_fc;
	int num_fc_ineligible;
	int nblks_agg;
	unsigned int tid;
};

struct ext4_fc_replay_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int tag;
	int ino;
	int priv1;
	int priv2;
};

struct ext4_fc_replay_scan_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int error;
	int off;
};

struct ext4_fc_stats_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned long fc_commits;
	unsigned long fc_ineligible_commits;
	unsigned long fc_numblks;
};

struct ext4_fc_track_create_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	int error;
};

struct ext4_fc_track_inode_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	int error;
};

struct ext4_fc_track_link_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	int error;
};

struct ext4_fc_track_range_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	long start;
	long end;
	int error;
};

struct ext4_fc_track_unlink_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned int t_tid;
	ino_t i_ino;
	unsigned int i_sync_tid;
	int error;
};

struct ext4_forget_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 block;
	int is_metadata;
	__u16 mode;
};

struct ext4_free_blocks_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 block;
	unsigned long count;
	int flags;
	__u16 mode;
};

struct ext4_free_inode_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	uid_t uid;
	gid_t gid;
	__u64 blocks;
	__u16 mode;
};

struct ext4_fsmap_high_key_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	dev_t keydev;
	__u32 agno;
	__u64 bno;
	__u64 len;
	__u64 owner;
};

struct ext4_fsmap_low_key_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	dev_t keydev;
	__u32 agno;
	__u64 bno;
	__u64 len;
	__u64 owner;
};

struct ext4_fsmap_mapping_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	dev_t keydev;
	__u32 agno;
	__u64 bno;
	__u64 len;
	__u64 owner;
};

struct ext4_get_implied_cluster_alloc_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned int flags;
	__u32 lblk;
	__u64 pblk;
	unsigned int len;
	int ret;
};

struct ext4_getfsmap_high_key_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	dev_t keydev;
	__u64 block;
	__u64 len;
	__u64 owner;
	__u64 flags;
};

struct ext4_getfsmap_low_key_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	dev_t keydev;
	__u64 block;
	__u64 len;
	__u64 owner;
	__u64 flags;
};

struct ext4_getfsmap_mapping_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	dev_t keydev;
	__u64 block;
	__u64 len;
	__u64 owner;
	__u64 flags;
};

struct ext4_ind_map_blocks_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u32 lblk;
	unsigned int len;
	unsigned int flags;
};

struct ext4_ind_map_blocks_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned int flags;
	__u64 pblk;
	__u32 lblk;
	unsigned int len;
	unsigned int mflags;
	int ret;
};

struct ext4_insert_range_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
};

struct ext4_invalidate_folio_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned long index;
	size_t offset;
	size_t length;
};

struct ext4_journal_start_inode_t
{
	struct ext4_event_base_t base;
	unsigned long ino;
	dev_t dev;
	unsigned long ip;
	int blocks;
	int rsv_blocks;
	int revoke_creds;
	int type;
};

struct ext4_journal_start_reserved_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned long ip;
	int blocks;
};

struct ext4_journal_start_sb_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned long ip;
	int blocks;
	int rsv_blocks;
	int revoke_creds;
	int type;
};

struct ext4_journalled_invalidate_folio_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned long index;
	size_t offset;
	size_t length;
};

struct ext4_journalled_write_end_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
	unsigned int copied;
};

struct ext4_lazy_itable_init_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u32 group;
};

struct ext4_load_inode_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
};

struct ext4_load_inode_bitmap_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u32 group;
};

struct ext4_mark_inode_dirty_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned long ip;
};

struct ext4_mb_bitmap_load_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u32 group;
};

struct ext4_mb_buddy_bitmap_load_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u32 group;
};

struct ext4_mb_discard_preallocations_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int needed;
};

struct ext4_mb_new_group_pa_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 pa_pstart;
	__u64 pa_lstart;
	__u32 pa_len;
};

struct ext4_mb_new_inode_pa_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 pa_pstart;
	__u64 pa_lstart;
	__u32 pa_len;
};

struct ext4_mb_release_group_pa_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u64 pa_pstart;
	__u32 pa_len;
};

struct ext4_mb_release_inode_pa_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 block;
	__u32 count;
};

struct ext4_mballoc_alloc_t
{
	struct ext4_event_base_t base;
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

struct ext4_mballoc_discard_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	int result_start;
	__u32 result_group;
	int result_len;
};

struct ext4_mballoc_free_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	int result_start;
	__u32 result_group;
	int result_len;
};

struct ext4_mballoc_prealloc_t
{
	struct ext4_event_base_t base;
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

struct ext4_nfs_commit_metadata_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
};

struct ext4_other_inode_update_time_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	ino_t orig_ino;
	uid_t uid;
	gid_t gid;
	__u16 mode;
};

struct ext4_prefetch_bitmaps_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u32 group;
	__u32 next;
	__u32 ios;
};

struct ext4_punch_hole_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
	int mode;
};

struct ext4_read_block_bitmap_load_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u32 group;
	bool prefetch;
};

struct ext4_read_folio_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned long index;
};

struct ext4_release_folio_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	unsigned long index;
};

struct ext4_remove_blocks_t
{
	struct ext4_event_base_t base;
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

struct ext4_request_blocks_t
{
	struct ext4_event_base_t base;
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

struct ext4_request_inode_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t dir;
	__u16 mode;
};

struct ext4_shutdown_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	unsigned flags;
};

struct ext4_sync_file_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	ino_t parent;
	int datasync;
};

struct ext4_sync_file_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	int ret;
};

struct ext4_sync_fs_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	int wait;
};

struct ext4_trim_all_free_t
{
	struct ext4_event_base_t base;
	int dev_major;
	int dev_minor;
	__u32 group;
	int start;
	int len;
};

struct ext4_trim_extent_t
{
	struct ext4_event_base_t base;
	int dev_major;
	int dev_minor;
	__u32 group;
	int start;
	int len;
};

struct ext4_truncate_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 blocks;
};

struct ext4_truncate_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	__u64 blocks;
};

struct ext4_unlink_enter_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	ino_t parent;
	loff_t size;
};

struct ext4_unlink_exit_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	int ret;
};

struct ext4_update_sb_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	__u64 fsblk;
	unsigned int flags;
};

struct ext4_write_begin_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
};

struct ext4_write_end_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t pos;
	unsigned int len;
	unsigned int copied;
};

struct ext4_writepages_t
{
	struct ext4_event_base_t base;
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

struct ext4_writepages_result_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	int ret;
	int pages_written;
	long pages_skipped;
	unsigned long writeback_index;
	int sync_mode;
};

struct ext4_zero_range_t
{
	struct ext4_event_base_t base;
	dev_t dev;
	ino_t ino;
	loff_t offset;
	loff_t len;
	int mode;
};