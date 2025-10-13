// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <cstring>
#include <iomanip>
#include <sstream>

#include "btrfs-snoop.skel.h"
#include "btrfs-snoop.h"

static struct env
{
	bool verbose;
	bool timestamp;
	int target_pid;
	int target_tid;
	char *target_comm;
	unsigned long duration;
} env = {
	.verbose = false,
	.timestamp = false,
	.target_pid = 0,
	.target_tid = 0,
	.target_comm = nullptr,
	.duration = 0,
};

const char *argp_program_version = "btrfs-snoop 1.0";
const char argp_program_doc[] = "Trace Btrfs filesystem operations.\n"
								"\n"
								"USAGE: btrfs-snoop [-h] [-v] [-t] [-p PID] "
								"[-T TID] [-c COMM] [-D DURATION]\n";

static const struct argp_option opts[] = {
	{"verbose", 'v', nullptr, 0, "Verbose debug output"},
	{"timestamp", 't', nullptr, 0, "Include timestamp on output"},
	{"pid", 'p', "PID", 0, "Trace process with this PID only"},
	{"tid", 'T', "TID", 0, "Trace thread with this TID only"},
	{"comm", 'c', "COMM", 0, "Trace command containing this string"},
	{"duration", 'D', "DURATION", 0, "Total duration of trace in seconds"},
	{nullptr, 'h', nullptr, OPTION_HIDDEN, "Show the full help"},
	{}
};

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
		env.target_pid = strtol(arg, nullptr, 10);
		break;
	case 'T':
		env.target_tid = strtol(arg, nullptr, 10);
		break;
	case 'c':
		env.target_comm = arg;
		break;
	case 'D':
		env.duration = strtoul(arg, nullptr, 10);
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

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
	{
		return 0;
	}
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
	{
		printf("%-14s ", "TIME(s)");
	}
	printf(
		"%-16s %-7s %-7s %-30s %s\n",
		"COMM",
		"PID",
		"TID",
		"EVENT",
		"DETAILS"
	);
}

static void print_timestamp()
{
	if (env.timestamp)
	{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		printf("%-14.6f ", ts.tv_sec + ts.tv_nsec / 1e9);
	}
}

static bool should_filter_event(pid_t pid, pid_t tid, const char *comm)
{
	if (env.target_pid && pid != env.target_pid)
	{
		return true;
	}
	if (env.target_tid && tid != env.target_tid)
	{
		return true;
	}
	if (env.target_comm && !strstr(comm, env.target_comm))
	{
		return true;
	}
	return false;
}

static std::string format_fsid(const __u8 fsid[16])
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (int i = 0; i < 16; i++)
	{
		ss << std::setw(2) << static_cast<unsigned>(fsid[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
		{
			ss << "-";
		}
	}
	return ss.str();
}

static void
print_extent_writepage_event(const struct btrfs_extent_writepage_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s ino=%llu index=%lu nr_to_write=%ld "
		"range=[%ld-%ld] root=%llu fsid=%s\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_extent_writepage",
		e->ino,
		e->index,
		e->nr_to_write,
		e->range_start,
		e->range_end,
		e->root_objectid,
		format_fsid(e->fsid).c_str()
	);
}

static void print_add_delayed_data_ref_event(
	const struct btrfs_add_delayed_data_ref_event *e
)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s bytenr=%llu bytes=%llu action=%d "
		"parent=%llu root=%llu owner=%llu offset=%llu type=%d\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_add_delayed_data_ref",
		e->bytenr,
		e->num_bytes,
		e->action,
		e->parent,
		e->ref_root,
		e->owner,
		e->offset,
		e->type
	);
}

static void print_add_delayed_ref_head_event(
	const struct btrfs_add_delayed_ref_head_event *e
)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s bytenr=%llu bytes=%llu action=%d is_data=%d\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_add_delayed_ref_head",
		e->bytenr,
		e->num_bytes,
		e->action,
		e->is_data
	);
}

static void print_chunk_alloc_event(const struct btrfs_chunk_alloc_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s type=%llu size=%llu stripes=%d root=%llu\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_chunk_alloc",
		e->type,
		e->size,
		e->num_stripes,
		e->root_objectid
	);
}

static void print_chunk_free_event(const struct btrfs_chunk_free_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s type=%llu size=%llu stripes=%d root=%llu\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_chunk_free",
		e->type,
		e->size,
		e->num_stripes,
		e->root_objectid
	);
}

static void
print_transaction_commit_event(const struct btrfs_transaction_commit_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s generation=%llu root=%llu\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_transaction_commit",
		e->generation,
		e->root_objectid
	);
}

static void
print_space_reservation_event(const struct btrfs_space_reservation_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s bytes=%llu reserve=%d\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_space_reservation",
		e->bytes,
		e->reserve
	);
}

static void
print_ordered_extent_add_event(const struct btrfs_ordered_extent_add_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s ino=%llu start=%llu len=%llu flags=0x%lx\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_ordered_extent_add",
		e->ino,
		e->start,
		e->len,
		e->flags
	);
}

static void print_sync_file_event(const struct btrfs_sync_file_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s ino=%llu datasync=%d root=%llu\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_sync_file",
		e->ino,
		e->datasync,
		e->root_objectid
	);
}

static void print_qgroup_account_extent_event(
	const struct btrfs_qgroup_account_extent_event *e
)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s bytenr=%llu bytes=%llu old_roots=%llu "
		"new_roots=%llu\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_qgroup_account_extent",
		e->bytenr,
		e->num_bytes,
		e->nr_old_roots,
		e->nr_new_roots
	);
}

static void print_tree_lock_event(const struct btrfs_tree_lock_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s block=%llu gen=%llu diff_ns=%llu owner=%llu\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_tree_lock",
		e->block,
		e->generation,
		e->diff_ns,
		e->owner
	);
}

static void print_get_extent_event(const struct btrfs_get_extent_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s ino=%llu start=%llu len=%llu block_start=%llu\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_get_extent",
		e->ino,
		e->start,
		e->len,
		e->block_start
	);
}

static void
print_reserve_extent_event(const struct btrfs_reserve_extent_event *e)
{
	if (should_filter_event(e->base.pid, e->base.tid, e->base.comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s start=%llu len=%llu flags=%llu loop=%llu\n",
		e->base.comm,
		e->base.pid,
		e->base.tid,
		"btrfs_reserve_extent",
		e->start,
		e->len,
		e->flags,
		e->loop
	);
}

static void
print_default_event(const struct btrfs_base_event *e, const char *event_name)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-30s (generic event)\n",
		e->comm,
		e->pid,
		e->tid,
		event_name
	);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	auto *base = static_cast<struct btrfs_base_event *>(data);

	switch (base->event_type)
	{
	case BTRFS_EXTENT_WRITEPAGE:
		print_extent_writepage_event(
			static_cast<struct btrfs_extent_writepage_event *>(data)
		);
		break;
	case BTRFS_ADD_DELAYED_DATA_REF:
		print_add_delayed_data_ref_event(
			static_cast<struct btrfs_add_delayed_data_ref_event *>(data)
		);
		break;
	case BTRFS_ADD_DELAYED_REF_HEAD:
		print_add_delayed_ref_head_event(
			static_cast<struct btrfs_add_delayed_ref_head_event *>(data)
		);
		break;
	case BTRFS_CHUNK_ALLOC:
		print_chunk_alloc_event(
			static_cast<struct btrfs_chunk_alloc_event *>(data)
		);
		break;
	case BTRFS_CHUNK_FREE:
		print_chunk_free_event(static_cast<struct btrfs_chunk_free_event *>(data
		));
		break;
	case BTRFS_TRANSACTION_COMMIT:
		print_transaction_commit_event(
			static_cast<struct btrfs_transaction_commit_event *>(data)
		);
		break;
	case BTRFS_SPACE_RESERVATION:
		print_space_reservation_event(
			static_cast<struct btrfs_space_reservation_event *>(data)
		);
		break;
	case BTRFS_ORDERED_EXTENT_ADD:
		print_ordered_extent_add_event(
			static_cast<struct btrfs_ordered_extent_add_event *>(data)
		);
		break;
	case BTRFS_SYNC_FILE:
		print_sync_file_event(static_cast<struct btrfs_sync_file_event *>(data)
		);
		break;
	case BTRFS_QGROUP_ACCOUNT_EXTENT:
		print_qgroup_account_extent_event(
			static_cast<struct btrfs_qgroup_account_extent_event *>(data)
		);
		break;
	case BTRFS_TREE_LOCK:
		print_tree_lock_event(static_cast<struct btrfs_tree_lock_event *>(data)
		);
		break;
	case BTRFS_GET_EXTENT:
		print_get_extent_event(static_cast<struct btrfs_get_extent_event *>(data
		));
		break;
	case BTRFS_RESERVE_EXTENT:
		print_reserve_extent_event(
			static_cast<struct btrfs_reserve_extent_event *>(data)
		);
		break;

	// Handle remaining events with generic print function
	case BTRFS_ADD_DELAYED_TREE_REF:
		print_default_event(base, "btrfs_add_delayed_tree_ref");
		break;
	case BTRFS_ALLOC_EXTENT_STATE:
		print_default_event(base, "btrfs_alloc_extent_state");
		break;
	case BTRFS_ADD_BLOCK_GROUP:
		print_default_event(base, "btrfs_add_block_group");
		break;
	case BTRFS_COW_BLOCK:
		print_default_event(base, "btrfs_cow_block");
		break;
	case BTRFS_FLUSH_SPACE:
		print_default_event(base, "btrfs_flush_space");
		break;
	case BTRFS_INODE_NEW:
		print_default_event(base, "btrfs_inode_new");
		break;
	case BTRFS_INODE_EVICT:
		print_default_event(base, "btrfs_inode_evict");
		break;
	case BTRFS_ORDERED_EXTENT_REMOVE:
		print_default_event(base, "btrfs_ordered_extent_remove");
		break;
	case BTRFS_TREE_READ_LOCK:
		print_default_event(base, "btrfs_tree_read_lock");
		break;
	case BTRFS_TREE_UNLOCK:
		print_default_event(base, "btrfs_tree_unlock");
		break;
	case BTRFS_QGROUP_RESERVE_DATA:
		print_default_event(base, "btrfs_qgroup_reserve_data");
		break;
	case BTRFS_QGROUP_RELEASE_DATA:
		print_default_event(base, "btrfs_qgroup_release_data");
		break;
	case BTRFS_RAID56_READ:
		print_default_event(base, "btrfs_raid56_read");
		break;
	case BTRFS_RAID56_WRITE:
		print_default_event(base, "btrfs_raid56_write");
		break;
	case BTRFS_RUN_DELAYED_DATA_REF:
		print_default_event(base, "btrfs_run_delayed_data_ref");
		break;
	case BTRFS_RUN_DELAYED_REF_HEAD:
		print_default_event(base, "btrfs_run_delayed_ref_head");
		break;
	case BTRFS_WORK_QUEUED:
		print_default_event(base, "btrfs_work_queued");
		break;
	case BTRFS_WORKQUEUE_ALLOC:
		print_default_event(base, "btrfs_workqueue_alloc");
		break;
	case BTRFS_FIND_FREE_EXTENT:
		print_default_event(base, "btrfs_find_free_extent");
		break;
	case BTRFS_UPDATE_BYTES_MAY_USE:
		print_default_event(base, "btrfs_update_bytes_may_use");
		break;
	default:
		if (env.verbose)
		{
			fprintf(stderr, "Unknown event type: %d\n", base->event_type);
		}
		break;
	}

	return 0;
}

bool check_btrfs_probed()
{
	DIR *dir = opendir("/sys/kernel/debug/tracing/events/btrfs");
	if (dir)
	{
		closedir(dir);
		return true;
	}
	return false;
}

int main(int argc, char **argv)
{
	time_t start_time;
	struct ring_buffer *rb = nullptr;
	struct btrfs_snoop_bpf *skel = nullptr;
	int err;
	// 解析参数
	err = argp_parse(&argp, argc, argv, 0, nullptr, nullptr);
	if (err)
	{
		return err;
	}
	if (!check_btrfs_probed())
	{
		printf("btrfs not probed, trying execute \"sudo modprobe btrfs\".\n");
		return 0;
	}

	// 设置libbpf日志
	libbpf_set_print(libbpf_print_fn);

	// 打开并加载BPF程序
	skel = btrfs_snoop_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 加载并验证BPF程序
	err = btrfs_snoop_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	// 附加tracepoints
	err = btrfs_snoop_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 设置ring buffer
	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events),
		handle_event,
		nullptr,
		nullptr
	);
	if (!rb)
	{
		fprintf(stderr, "Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	// 设置信号处理
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 打印表头
	print_header();

	start_time = time(nullptr);

	// 事件处理循环
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}

		// 检查是否超时
		if (env.duration && time(nullptr) - start_time >= (long)env.duration)
		{
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	btrfs_snoop_bpf__destroy(skel);
	return err ? -err : 0;
}