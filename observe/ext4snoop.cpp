#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>

#include "ext4snoop.skel.h"
#include "Ucom.h"
#include "ext4snoop.h"

static struct env
{
    bool verbose;
    bool timestamp;
    int target_pid;
    int target_tid;
    char *target_comm;
    char *target_dev;
    unsigned long duration;
} env = {
    .verbose = false,
    .timestamp = false,
    .target_pid = 0,
    .target_tid = 0,
    .target_comm = NULL,
    .target_dev = NULL,
    .duration = 0,
};

const char *argp_program_version = "ext4snoop 1.0";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Trace ext4 filesystem operations.\n"
    "\n"
    "USAGE: ext4snoop [-h] [-v] [-t] [-p PID] [-T TID] [-c COMM] [-d DEV] [-D DURATION]\n"
    "\n"
    "EXAMPLES:\n"
    "    ext4snoop             # trace all ext4 operations\n"
    "    ext4snoop -t          # include timestamps\n"
    "    ext4snoop -p 1234     # only trace PID 1234\n"
    "    ext4snoop -c bash     # only trace command containing 'bash'\n"
    "    ext4snoop -d sda1     # only trace device sda1\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"timestamp", 't', NULL, 0, "Include timestamp on output"},
    {"pid", 'p', "PID", 0, "Trace process with this PID only"},
    {"tid", 'T', "TID", 0, "Trace thread with this TID only"},
    {"comm", 'c', "COMM", 0, "Trace command containing this string"},
    {"device", 'd', "DEV", 0, "Trace device only"},
    {"duration", 'D', "DURATION", 0, "Total duration of trace in seconds"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {}};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case 'v':
        env.verbose = true;
        break;
    case 't':
        env.timestamp = true;
        break;
    case 'p':
        errno = 0;
        env.target_pid = strtol(arg, NULL, 10);
        if (errno)
        {
            fprintf(stderr, "invalid PID: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'T':
        errno = 0;
        env.target_tid = strtol(arg, NULL, 10);
        if (errno)
        {
            fprintf(stderr, "invalid TID: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'c':
        env.target_comm = arg;
        break;
    case 'd':
        env.target_dev = arg;
        break;
    case 'D':
        errno = 0;
        env.duration = strtoul(arg, NULL, 10);
        if (errno)
        {
            fprintf(stderr, "invalid duration: %s\n", arg);
            argp_usage(state);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_header()
{
    if (env.timestamp)
        printf("%-14s ", "TIME(s)");
    printf("%-16s %-7s %-7s %-14s %-10s %s\n",
           "COMM", "PID", "TID", "EVENT", "DEV", "DETAILS");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    ext4_event_base_t *base = (typeof(base))data;
    if (data_sz < sizeof(ext4_event_base_t))
        return 0;

    if (env.timestamp)
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("%-14.6f ", ts.tv_sec + ts.tv_nsec / 1e9);
    }
    // Print process info
    printf("%-16s %-7d %-7d ", base->comm, base->pid, base->tid);

    switch (base->type)
    {
        case EXT4_ALLOC_DA_BLOCKS:
        {
            if (data_sz < sizeof(ext4_alloc_da_blocks_t))
                return 0;
            ext4_alloc_da_blocks_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu data_blocks=%u",
                "-alloc-da-blocks",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->data_blocks);
            break;
        }
        case EXT4_ALLOCATE_BLOCKS:
        {
            if (data_sz < sizeof(ext4_allocate_blocks_t))
                return 0;
            ext4_allocate_blocks_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu block=%llu len=%u logical=%u lleft=%u lright=%u goal=%llu pleft=%llu pright=%llu flags=%u",
                "-allocate-blocks",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (unsigned long long)event->block, event->len,
                event->logical, event->lleft, event->lright, 
                (unsigned long long)event->goal, (unsigned long long)event->pleft, 
                (unsigned long long)event->pright, event->flags);
            break;
        }
        case EXT4_ALLOCATE_INODE:
        {
            if (data_sz < sizeof(ext4_allocate_inode_t))
                return 0;
            ext4_allocate_inode_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu dir=%lu mode=%o",
                "-allocate-inode",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (unsigned long)event->dir, event->mode);
            break;
        }
        case EXT4_BEGIN_ORDERED_TRUNCATE:
        {
            if (data_sz < sizeof(ext4_begin_ordered_truncate_t))
                return 0;
            ext4_begin_ordered_truncate_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu new_size=%lld",
                "-begin-ordered-truncate",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (long long)event->new_size);
            break;
        }
        case EXT4_COLLAPSE_RANGE:
        {
            if (data_sz < sizeof(ext4_collapse_range_t))
                return 0;
            ext4_collapse_range_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu offset=%lld len=%lld",
                "-collapse-range",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (long long)event->offset, (long long)event->len);
            break;
        }
        case EXT4_DA_RELEASE_SPACE:
        {
            if (data_sz < sizeof(ext4_da_release_space_t))
                return 0;
            ext4_da_release_space_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu i_blocks=%llu freed_blocks=%d reserved_data_blocks=%d mode=%o",
                "-da-release-space",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (unsigned long long)event->i_blocks,
                event->freed_blocks, event->reserved_data_blocks, event->mode);
            break;
        }
        case EXT4_DA_RESERVE_SPACE:
        {
            if (data_sz < sizeof(ext4_da_reserve_space_t))
                return 0;
            ext4_da_reserve_space_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu i_blocks=%llu reserved_data_blocks=%d mode=%o",
                "-da-reserve-space",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (unsigned long long)event->i_blocks,
                event->reserved_data_blocks, event->mode);
            break;
        }
        case EXT4_DA_UPDATE_RESERVE_SPACE:
        {
            if (data_sz < sizeof(ext4_da_update_reserve_space_t))
                return 0;
            ext4_da_update_reserve_space_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu i_blocks=%llu used_blocks=%d reserved_data_blocks=%d quota_claim=%d mode=%o",
                "-da-update-reserve-space",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (unsigned long long)event->i_blocks,
                event->used_blocks, event->reserved_data_blocks, event->quota_claim, event->mode);
            break;
        }
        case EXT4_DA_WRITE_BEGIN:
        {
            if (data_sz < sizeof(ext4_da_write_begin_t))
                return 0;
            ext4_da_write_begin_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu pos=%lld len=%u",
                "-da-write-begin",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (long long)event->pos, event->len);
            break;
        }
        case EXT4_DA_WRITE_END:
        {
            if (data_sz < sizeof(ext4_da_write_end_t))
                return 0;
            ext4_da_write_end_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu pos=%lld len=%u copied=%u",
                "-da-write-end",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (long long)event->pos, event->len, event->copied);
            break;
        }
        case EXT4_DA_WRITE_PAGES:
        {
            if (data_sz < sizeof(ext4_da_write_pages_t))
                return 0;
            ext4_da_write_pages_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu first_page=%lu nr_to_write=%ld sync_mode=%d",
                "-da-write-pages",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->first_page, event->nr_to_write, event->sync_mode);
            break;
        }
        case EXT4_DA_WRITE_PAGES_EXTENT:
        {
            if (data_sz < sizeof(ext4_da_write_pages_extent_t))
                return 0;
            ext4_da_write_pages_extent_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu lblk=%llu len=%u flags=%u",
                "-da-write-pages-extent",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->lblk, event->len, event->flags);
            break;
        }
        case EXT4_DISCARD_BLOCKS:
        {
            if (data_sz < sizeof(ext4_discard_blocks_t))
                return 0;
            ext4_discard_blocks_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u blk=%llu count=%llu",
                "-discard-blocks",
                major(event->dev), minor(event->dev), 
                (unsigned long long)event->blk, (unsigned long long)event->count);
            break;
        }
        case EXT4_DISCARD_PREALLOCATIONS:
        {
            if (data_sz < sizeof(ext4_discard_preallocations_t))
                return 0;
            ext4_discard_preallocations_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu len=%u needed=%u",
                "-discard-preallocations",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->len, event->needed);
            break;
        }
        case EXT4_DROP_INODE:
        {
            if (data_sz < sizeof(ext4_drop_inode_t))
                return 0;
            ext4_drop_inode_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu drop=%d",
                "-drop-inode",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->drop);
            break;
        }
        case EXT4_ERROR:
        {
            if (data_sz < sizeof(ext4_error_t))
                return 0;
            ext4_error_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u function=%s line=%u",
                "-error",
                major(event->dev), minor(event->dev), 
                event->function, event->line);
            break;
        }
        case EXT4_ES_CACHE_EXTENT:
        {
            if (data_sz < sizeof(ext4_es_cache_extent_t))
                return 0;
            ext4_es_cache_extent_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu lblk=%u len=%u pblk=%llu status=%c",
                "-es-cache-extent",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->lblk, event->len, 
                (unsigned long long)event->pblk, event->status);
            break;
        }
        case EXT4_ES_FIND_EXTENT_RANGE_ENTER:
        {
            if (data_sz < sizeof(ext4_es_find_extent_range_enter_t))
                return 0;
            ext4_es_find_extent_range_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-es-find-extent-range-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_ES_FIND_EXTENT_RANGE_EXIT:
        {
            if (data_sz < sizeof(ext4_es_find_extent_range_exit_t))
                return 0;
            ext4_es_find_extent_range_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-es-find-extent-range-exit",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_ES_INSERT_DELAYED_BLOCK:
        {
            if (data_sz < sizeof(ext4_es_insert_delayed_block_t))
                return 0;
            ext4_es_insert_delayed_block_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-es-insert-delayed-block",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_ES_INSERT_EXTENT:
        {
            if (data_sz < sizeof(ext4_es_insert_extent_t))
                return 0;
            ext4_es_insert_extent_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-es-insert-extent", 
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_ES_LOOKUP_EXTENT_ENTER:
        {
            if (data_sz < sizeof(ext4_es_lookup_extent_enter_t))
                return 0;
            ext4_es_lookup_extent_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-es-lookup-extent-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_ES_LOOKUP_EXTENT_EXIT:
        {
            if (data_sz < sizeof(ext4_es_lookup_extent_exit_t))
                return 0;
            ext4_es_lookup_extent_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-es-lookup-extent-exit",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_ES_REMOVE_EXTENT:
        {
            if (data_sz < sizeof(ext4_es_remove_extent_t))
                return 0;
            ext4_es_remove_extent_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-es-remove-extent",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_ES_SHRINK:
        {
            if (data_sz < sizeof(ext4_es_shrink_t))
                return 0;
            ext4_es_shrink_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u nr_shrunk=%d scan_time=%llu",
                "-es-shrink",
                major(event->dev), minor(event->dev), 
                event->nr_shrunk, event->scan_time);
            break;
        }
        case EXT4_ES_SHRINK_COUNT:
        {
            if (data_sz < sizeof(ext4_es_shrink_count_t))
                return 0;
            ext4_es_shrink_count_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u nr_to_scan=%d cache_cnt=%d",
                "-es-shrink-count",
                major(event->dev), minor(event->dev), 
                event->nr_to_scan, event->cache_cnt);
            break;
        }
        case EXT4_ES_SHRINK_SCAN_ENTER:
        {
            if (data_sz < sizeof(ext4_es_shrink_scan_enter_t))
                return 0;
            ext4_es_shrink_scan_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u nr_to_scan=%d cache_cnt=%d",
                "-es-shrink-scan-enter",
                major(event->dev), minor(event->dev), 
                event->nr_to_scan, event->cache_cnt);
            break;
        }
        case EXT4_ES_SHRINK_SCAN_EXIT:
        {
            if (data_sz < sizeof(ext4_es_shrink_scan_exit_t))
                return 0;
            ext4_es_shrink_scan_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u nr_shrunk=%d cache_cnt=%d",
                "-es-shrink-scan-exit",
                major(event->dev), minor(event->dev), 
                event->nr_shrunk, event->cache_cnt);
            break;
        }
        case EXT4_EVICT_INODE:
        {
            if (data_sz < sizeof(ext4_evict_inode_t))
                return 0;
            ext4_evict_inode_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu nlink=%d",
                "-evict-inode",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->nlink);
            break;
        }
        case EXT4_EXT_CONVERT_TO_INITIALIZED_ENTER:
        {
            if (data_sz < sizeof(ext4_ext_convert_to_initialized_enter_t))
                return 0;
            ext4_ext_convert_to_initialized_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-convert-to-initialized-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_CONVERT_TO_INITIALIZED_FASTPATH:
        {
            if (data_sz < sizeof(ext4_ext_convert_to_initialized_fastpath_t))
                return 0;
            ext4_ext_convert_to_initialized_fastpath_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-convert-to-initialized-fastpath",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_HANDLE_UNWRITTEN_EXTENTS:
        {
            if (data_sz < sizeof(ext4_ext_handle_unwritten_extents_t))
                return 0;
            ext4_ext_handle_unwritten_extents_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-handle-unwritten-extents",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_LOAD_EXTENT:
        {
            if (data_sz < sizeof(ext4_ext_load_extent_t))
                return 0;
            ext4_ext_load_extent_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-load-extent",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_MAP_BLOCKS_ENTER:
        {
            if (data_sz < sizeof(ext4_ext_map_blocks_enter_t))
                return 0;
            ext4_ext_map_blocks_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-map-blocks-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_MAP_BLOCKS_EXIT:
        {
            if (data_sz < sizeof(ext4_ext_map_blocks_exit_t))
                return 0;
            ext4_ext_map_blocks_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-map-blocks-exit",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_REMOVE_SPACE:
        {
            if (data_sz < sizeof(ext4_ext_remove_space_t))
                return 0;
            ext4_ext_remove_space_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-remove-space",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_REMOVE_SPACE_DONE:
        {
            if (data_sz < sizeof(ext4_ext_remove_space_done_t))
                return 0;
            ext4_ext_remove_space_done_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-remove-space-done",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_RM_IDX:
        {
            if (data_sz < sizeof(ext4_ext_rm_idx_t))
                return 0;
            ext4_ext_rm_idx_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-rm-idx",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_RM_LEAF:
        {
            if (data_sz < sizeof(ext4_ext_rm_leaf_t))
                return 0;
            ext4_ext_rm_leaf_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-rm-leaf",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_EXT_SHOW_EXTENT:
        {
            if (data_sz < sizeof(ext4_ext_show_extent_t))
                return 0;
            ext4_ext_show_extent_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ext-show-extent",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_FALLOCATE_ENTER:
        {
            if (data_sz < sizeof(ext4_fallocate_enter_t))
                return 0;
            ext4_fallocate_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-fallocate-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_FALLOCATE_EXIT:
        {
            if (data_sz < sizeof(ext4_fallocate_exit_t))
                return 0;
            ext4_fallocate_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-fallocate-exit",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_FC_CLEANUP:
        {
            if (data_sz < sizeof(ext4_fc_cleanup_t))
                return 0;
            ext4_fc_cleanup_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u j_fc_off=%d full=%d tid=%u",
                "-fc-cleanup",
                major(event->dev), minor(event->dev), 
                event->j_fc_off, event->full, event->tid);
            break;
        }
        case EXT4_FC_COMMIT_START:
        {
            if (data_sz < sizeof(ext4_fc_commit_start_t))
                return 0;
            ext4_fc_commit_start_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u tid=%u",
                "-fc-commit-start",
                major(event->dev), minor(event->dev), 
                event->tid);
            break;
        }
        case EXT4_FC_COMMIT_STOP:
        {
            if (data_sz < sizeof(ext4_fc_commit_stop_t))
                return 0;
            ext4_fc_commit_stop_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u nblks=%d reason=%d tid=%u",
                "-fc-commit-stop",
                major(event->dev), minor(event->dev), 
                event->nblks, event->reason, event->tid);
            break;
        }
        case EXT4_FC_REPLAY:
        {
            if (data_sz < sizeof(ext4_fc_replay_t))
                return 0;
            ext4_fc_replay_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u tag=%d ino=%d",
                "-fc-replay",
                major(event->dev), minor(event->dev), 
                event->tag, event->ino);
            break;
        }
        case EXT4_FC_REPLAY_SCAN:
        {
            if (data_sz < sizeof(ext4_fc_replay_scan_t))
                return 0;
            ext4_fc_replay_scan_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u error=%d off=%d",
                "-fc-replay-scan",
                major(event->dev), minor(event->dev), 
                event->error, event->off);
            break;
        }
        case EXT4_FC_STATS:
        {
            if (data_sz < sizeof(ext4_fc_stats_t))
                return 0;
            ext4_fc_stats_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u fc_commits=%lu fc_ineligible_commits=%lu",
                "-fc-stats",
                major(event->dev), minor(event->dev), 
                event->fc_commits, event->fc_ineligible_commits);
            break;
        }
        case EXT4_FC_TRACK_CREATE:
        {
            if (data_sz < sizeof(ext4_fc_track_create_t))
                return 0;
            ext4_fc_track_create_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu tid=%u",
                "-fc-track-create",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->i_ino, event->t_tid);
            break;
        }
        case EXT4_FC_TRACK_INODE:
        {
            if (data_sz < sizeof(ext4_fc_track_inode_t))
                return 0;
            ext4_fc_track_inode_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu tid=%u",
                "-fc-track-inode",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->i_ino, event->t_tid);
            break;
        }
        case EXT4_FC_TRACK_LINK:
        {
            if (data_sz < sizeof(ext4_fc_track_link_t))
                return 0;
            ext4_fc_track_link_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu tid=%u",
                "-fc-track-link",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->i_ino, event->t_tid);
            break;
        }
        case EXT4_FC_TRACK_RANGE:
        {
            if (data_sz < sizeof(ext4_fc_track_range_t))
                return 0;
            ext4_fc_track_range_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu tid=%u start=%ld end=%ld",
                "-fc-track-range",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->i_ino, event->t_tid, event->start, event->end);
            break;
        }
        case EXT4_FC_TRACK_UNLINK:
        {
            if (data_sz < sizeof(ext4_fc_track_unlink_t))
                return 0;
            ext4_fc_track_unlink_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu tid=%u",
                "-fc-track-unlink",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->i_ino, event->t_tid);
            break;
        }
        case EXT4_FORGET:
        {
            if (data_sz < sizeof(ext4_forget_t))
                return 0;
            ext4_forget_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-forget",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_FREE_BLOCKS:
        {
            if (data_sz < sizeof(ext4_free_blocks_t))
                return 0;
            ext4_free_blocks_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-free-blocks",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_FREE_INODE:
        {
            if (data_sz < sizeof(ext4_free_inode_t))
                return 0;
            ext4_free_inode_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-free-inode",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_FSMAP_HIGH_KEY:
        {
            if (data_sz < sizeof(ext4_fsmap_high_key_t))
                return 0;
            ext4_fsmap_high_key_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u keydev=%u:%u agno=%u bno=%llu",
                "-fsmap-high-key",
                major(event->dev), minor(event->dev), 
                major(event->keydev), minor(event->keydev), event->agno, event->bno);
            break;
        }
        case EXT4_FSMAP_LOW_KEY:
        {
            if (data_sz < sizeof(ext4_fsmap_low_key_t))
                return 0;
            ext4_fsmap_low_key_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u keydev=%u:%u agno=%u bno=%llu",
                "-fsmap-low-key",
                major(event->dev), minor(event->dev), 
                major(event->keydev), minor(event->keydev), event->agno, event->bno);
            break;
        }
        case EXT4_FSMAP_MAPPING:
        {
            if (data_sz < sizeof(ext4_fsmap_mapping_t))
                return 0;
            ext4_fsmap_mapping_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u keydev=%u:%u agno=%u bno=%llu",
                "-fsmap-mapping",
                major(event->dev), minor(event->dev), 
                major(event->keydev), minor(event->keydev), event->agno, event->bno);
            break;
        }
        case EXT4_GET_IMPLIED_CLUSTER_ALLOC_EXIT:
        {
            if (data_sz < sizeof(ext4_get_implied_cluster_alloc_exit_t))
                return 0;
            ext4_get_implied_cluster_alloc_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u flags=%u lblk=%u pblk=%llu len=%u ret=%d",
                "-get-implied-cluster-alloc-exit",
                major(event->dev), minor(event->dev), 
                event->flags, event->lblk, event->pblk, event->len, event->ret);
            break;
        }
        case EXT4_GETFSMAP_HIGH_KEY:
        {
            if (data_sz < sizeof(ext4_getfsmap_high_key_t))
                return 0;
            ext4_getfsmap_high_key_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u keydev=%u:%u block=%llu len=%llu",
                "-getfsmap-high-key",
                major(event->dev), minor(event->dev), 
                major(event->keydev), minor(event->keydev), event->block, event->len);
            break;
        }
        case EXT4_GETFSMAP_LOW_KEY:
        {
            if (data_sz < sizeof(ext4_getfsmap_low_key_t))
                return 0;
            ext4_getfsmap_low_key_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u keydev=%u:%u block=%llu len=%llu",
                "-getfsmap-low-key",
                major(event->dev), minor(event->dev), 
                major(event->keydev), minor(event->keydev), event->block, event->len);
            break;
        }
        case EXT4_GETFSMAP_MAPPING:
        {
            if (data_sz < sizeof(ext4_getfsmap_mapping_t))
                return 0;
            ext4_getfsmap_mapping_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u keydev=%u:%u block=%llu len=%llu",
                "-getfsmap-mapping",
                major(event->dev), minor(event->dev), 
                major(event->keydev), minor(event->keydev), event->block, event->len);
            break;
        }
        case EXT4_IND_MAP_BLOCKS_ENTER:
        {
            if (data_sz < sizeof(ext4_ind_map_blocks_enter_t))
                return 0;
            ext4_ind_map_blocks_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ind-map-blocks-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_IND_MAP_BLOCKS_EXIT:
        {
            if (data_sz < sizeof(ext4_ind_map_blocks_exit_t))
                return 0;
            ext4_ind_map_blocks_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-ind-map-blocks-exit",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_INSERT_RANGE:
        {
            if (data_sz < sizeof(ext4_insert_range_t))
                return 0;
            ext4_insert_range_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-insert-range",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_INVALIDATE_FOLIO:
        {
            if (data_sz < sizeof(ext4_invalidate_folio_t))
                return 0;
            ext4_invalidate_folio_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-invalidate-folio",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_JOURNAL_START_INODE:
        {
            if (data_sz < sizeof(ext4_journal_start_inode_t))
                return 0;
            ext4_journal_start_inode_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-journal-start-inode",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_JOURNAL_START_RESERVED:
        {
            if (data_sz < sizeof(ext4_journal_start_reserved_t))
                return 0;
            ext4_journal_start_reserved_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u blocks=%d ip=%lx",
                "-journal-start-reserved",
                major(event->dev), minor(event->dev), 
                event->blocks, event->ip);
            break;
        }
        case EXT4_JOURNAL_START_SB:
        {
            if (data_sz < sizeof(ext4_journal_start_sb_t))
                return 0;
            ext4_journal_start_sb_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u blocks=%d ip=%lx type=%d",
                "-journal-start-sb",
                major(event->dev), minor(event->dev), 
                event->blocks, event->ip, event->type);
            break;
        }
        case EXT4_JOURNALLED_INVALIDATE_FOLIO:
        {
            if (data_sz < sizeof(ext4_journalled_invalidate_folio_t))
                return 0;
            ext4_journalled_invalidate_folio_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-journalled-invalidate-folio",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_JOURNALLED_WRITE_END:
        {
            if (data_sz < sizeof(ext4_journalled_write_end_t))
                return 0;
            ext4_journalled_write_end_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-journalled-write-end",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_LAZY_ITABLE_INIT:
        {
            if (data_sz < sizeof(ext4_lazy_itable_init_t))
                return 0;
            ext4_lazy_itable_init_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u group=%u",
                "-lazy-itable-init",
                major(event->dev), minor(event->dev), 
                event->group);
            break;
        }
        case EXT4_LOAD_INODE:
        {
            if (data_sz < sizeof(ext4_load_inode_t))
                return 0;
            ext4_load_inode_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-load-inode",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_LOAD_INODE_BITMAP:
        {
            if (data_sz < sizeof(ext4_load_inode_bitmap_t))
                return 0;
            ext4_load_inode_bitmap_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u group=%u",
                "-load-inode-bitmap",
                major(event->dev), minor(event->dev), 
                event->group);
            break;
        }
        case EXT4_MARK_INODE_DIRTY:
        {
            if (data_sz < sizeof(ext4_mark_inode_dirty_t))
                return 0;
            ext4_mark_inode_dirty_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-mark-inode-dirty",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_MB_BITMAP_LOAD:
        {
            if (data_sz < sizeof(ext4_mb_bitmap_load_t))
                return 0;
            ext4_mb_bitmap_load_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u group=%u",
                "-mb-bitmap-load",
                major(event->dev), minor(event->dev), 
                event->group);
            break;
        }
        case EXT4_MB_BUDDY_BITMAP_LOAD:
        {
            if (data_sz < sizeof(ext4_mb_buddy_bitmap_load_t))
                return 0;
            ext4_mb_buddy_bitmap_load_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u group=%u",
                "-mb-buddy-bitmap-load",
                major(event->dev), minor(event->dev), 
                event->group);
            break;
        }
        case EXT4_MB_DISCARD_PREALLOCATIONS:
        {
            if (data_sz < sizeof(ext4_mb_discard_preallocations_t))
                return 0;
            ext4_mb_discard_preallocations_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u needed=%d",
                "-mb-discard-preallocations",
                major(event->dev), minor(event->dev), 
                event->needed);
            break;
        }
        case EXT4_MB_NEW_GROUP_PA:
        {
            if (data_sz < sizeof(ext4_mb_new_group_pa_t))
                return 0;
            ext4_mb_new_group_pa_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-mb-new-group-pa",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_MB_NEW_INODE_PA:
        {
            if (data_sz < sizeof(ext4_mb_new_inode_pa_t))
                return 0;
            ext4_mb_new_inode_pa_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-mb-new-inode-pa",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_MB_RELEASE_GROUP_PA:
        {
            if (data_sz < sizeof(ext4_mb_release_group_pa_t))
                return 0;
            ext4_mb_release_group_pa_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u pa_pstart=%llu pa_len=%u",
                "-mb-release-group-pa",
                major(event->dev), minor(event->dev), 
                event->pa_pstart, event->pa_len);
            break;
        }
        case EXT4_MB_RELEASE_INODE_PA:
        {
            if (data_sz < sizeof(ext4_mb_release_inode_pa_t))
                return 0;
            ext4_mb_release_inode_pa_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-mb-release-inode-pa",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_MBALLOC_ALLOC:
        {
            if (data_sz < sizeof(ext4_mballoc_alloc_t))
                return 0;
            ext4_mballoc_alloc_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-mballoc-alloc",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_MBALLOC_DISCARD:
        {
            if (data_sz < sizeof(ext4_mballoc_discard_t))
                return 0;
            ext4_mballoc_discard_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-mballoc-discard",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_MBALLOC_FREE:
        {
            if (data_sz < sizeof(ext4_mballoc_free_t))
                return 0;
            ext4_mballoc_free_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-mballoc-free",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_MBALLOC_PREALLOC:
        {
            if (data_sz < sizeof(ext4_mballoc_prealloc_t))
                return 0;
            ext4_mballoc_prealloc_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-mballoc-prealloc",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_NFS_COMMIT_METADATA:
        {
            if (data_sz < sizeof(ext4_nfs_commit_metadata_t))
                return 0;
            ext4_nfs_commit_metadata_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-nfs-commit-metadata",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_OTHER_INODE_UPDATE_TIME:
        {
            if (data_sz < sizeof(ext4_other_inode_update_time_t))
                return 0;
            ext4_other_inode_update_time_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-other-inode-update-time",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_PREFETCH_BITMAPS:
        {
            if (data_sz < sizeof(ext4_prefetch_bitmaps_t))
                return 0;
            ext4_prefetch_bitmaps_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u group=%u next=%u ios=%u",
                "-prefetch-bitmaps",
                major(event->dev), minor(event->dev), 
                event->group, event->next, event->ios);
            break;
        }
        case EXT4_PUNCH_HOLE:
        {
            if (data_sz < sizeof(ext4_punch_hole_t))
                return 0;
            ext4_punch_hole_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-punch-hole",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_READ_BLOCK_BITMAP_LOAD:
        {
            if (data_sz < sizeof(ext4_read_block_bitmap_load_t))
                return 0;
            ext4_read_block_bitmap_load_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u group=%u prefetch=%s",
                "-read-block-bitmap-load",
                major(event->dev), minor(event->dev), 
                event->group, event->prefetch ? "true" : "false");
            break;
        }
        case EXT4_READ_FOLIO:
        {
            if (data_sz < sizeof(ext4_read_folio_t))
                return 0;
            ext4_read_folio_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-read-folio",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_RELEASE_FOLIO:
        {
            if (data_sz < sizeof(ext4_release_folio_t))
                return 0;
            ext4_release_folio_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-release-folio",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_REMOVE_BLOCKS:
        {
            if (data_sz < sizeof(ext4_remove_blocks_t))
                return 0;
            ext4_remove_blocks_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-remove-blocks",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_REQUEST_BLOCKS:
        {
            if (data_sz < sizeof(ext4_request_blocks_t))
                return 0;
            ext4_request_blocks_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-request-blocks",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_REQUEST_INODE:
        {
            if (data_sz < sizeof(ext4_request_inode_t))
                return 0;
            ext4_request_inode_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u dir=%lu mode=%o",
                "-request-inode",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->dir, event->mode);
            break;
        }
        case EXT4_SHUTDOWN:
        {
            if (data_sz < sizeof(ext4_shutdown_t))
                return 0;
            ext4_shutdown_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u flags=%u",
                "-shutdown",
                major(event->dev), minor(event->dev), 
                event->flags);
            break;
        }
        case EXT4_SYNC_FILE_ENTER:
        {
            if (data_sz < sizeof(ext4_sync_file_enter_t))
                return 0;
            ext4_sync_file_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-sync-file-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_SYNC_FILE_EXIT:
        {
            if (data_sz < sizeof(ext4_sync_file_exit_t))
                return 0;
            ext4_sync_file_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-sync-file-exit",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_SYNC_FS:
        {
            if (data_sz < sizeof(ext4_sync_fs_t))
                return 0;
            ext4_sync_fs_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u wait=%d",
                "-sync-fs",
                major(event->dev), minor(event->dev), 
                event->wait);
            break;
        }
        case EXT4_TRIM_ALL_FREE:
        {
            if (data_sz < sizeof(ext4_trim_all_free_t))
                return 0;
            ext4_trim_all_free_t *event = (typeof(event))data;
            printf("%-14s dev=%d:%d group=%u start=%d len=%d",
                "-trim-all-free",
                event->dev_major, event->dev_minor, 
                event->group, event->start, event->len);
            break;
        }
        case EXT4_TRIM_EXTENT:
        {
            if (data_sz < sizeof(ext4_trim_extent_t))
                return 0;
            ext4_trim_extent_t *event = (typeof(event))data;
            printf("%-14s dev=%d:%d group=%u start=%d len=%d",
                "-trim-extent",
                event->dev_major, event->dev_minor, 
                event->group, event->start, event->len);
            break;
        }
        case EXT4_TRUNCATE_ENTER:
        {
            if (data_sz < sizeof(ext4_truncate_enter_t))
                return 0;
            ext4_truncate_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-truncate-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_TRUNCATE_EXIT:
        {
            if (data_sz < sizeof(ext4_truncate_exit_t))
                return 0;
            ext4_truncate_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-truncate-exit",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_UNLINK_ENTER:
        {
            if (data_sz < sizeof(ext4_unlink_enter_t))
                return 0;
            ext4_unlink_enter_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-unlink-enter",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_UNLINK_EXIT:
        {
            if (data_sz < sizeof(ext4_unlink_exit_t))
                return 0;
            ext4_unlink_exit_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu",
                "-unlink-exit",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino);
            break;
        }
        case EXT4_UPDATE_SB:
        {
            if (data_sz < sizeof(ext4_update_sb_t))
                return 0;
            ext4_update_sb_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u fsblk=%llu flags=%u",
                "-update-sb",
                major(event->dev), minor(event->dev), 
                (unsigned long long)event->fsblk, event->flags);
            break;
        }
        case EXT4_WRITE_BEGIN:
        {
            if (data_sz < sizeof(ext4_write_begin_t))
                return 0;
            ext4_write_begin_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu pos=%lld len=%u",
                "-write-begin",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (long long)event->pos, event->len);
            break;
        }
        case EXT4_WRITE_END:
        {
            if (data_sz < sizeof(ext4_write_end_t))
                return 0;
            ext4_write_end_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu pos=%lld len=%u copied=%u",
                "-write-end",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (long long)event->pos, event->len, event->copied);
            break;
        }
        case EXT4_WRITEPAGES:
        {
            if (data_sz < sizeof(ext4_writepages_t))
                return 0;
            ext4_writepages_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu nr_to_write=%ld pages_skipped=%ld range_start=%lld range_end=%lld sync_mode=%d",
                "-writepages",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->nr_to_write, event->pages_skipped, 
                (long long)event->range_start, (long long)event->range_end, event->sync_mode);
            break;
        }
        case EXT4_WRITEPAGES_RESULT:
        {
            if (data_sz < sizeof(ext4_writepages_result_t))
                return 0;
            ext4_writepages_result_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu ret=%d pages_written=%d pages_skipped=%ld sync_mode=%d",
                "-writepages-result",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, event->ret, event->pages_written, 
                event->pages_skipped, event->sync_mode);
            break;
        }
        case EXT4_ZERO_RANGE:
        {
            if (data_sz < sizeof(ext4_zero_range_t))
                return 0;
            ext4_zero_range_t *event = (typeof(event))data;
            printf("%-14s dev=%u:%u ino=%lu offset=%lld len=%lld mode=%d",
                "-zero-range",
                major(event->dev), minor(event->dev), 
                (unsigned long)event->ino, (long long)event->offset, (long long)event->len, event->mode);
            break;
        }
        default:
            printf("%-14s unknown event", "unknown");
            break;
    }

    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    time_t start_time;
    struct ring_buffer *rb = NULL;
    struct ext4snoop_bpf *skel;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf */
    libbpf_set_print(libbpf_print_fn);

    /* Open and load BPF application */
    skel = ext4snoop_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load and verify BPF application */
    err = ext4snoop_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint */
    err = ext4snoop_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Print header */
    print_header();

    /* Record start time for duration checking */
    start_time = time(NULL);

    /* Process events */
    while (!exiting)
    {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }

        if (env.duration && (time(NULL) - start_time) >= env.duration)
        {
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    ext4snoop_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
