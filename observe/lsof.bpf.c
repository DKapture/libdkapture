#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "jhash.h"
#include "Kstr-utils.h"
#include "Kmem.h"
#include "Kcom.h"
#include "fcntl-defs.h"

char _license[] SEC("license") = "GPL";

// 添加设备号转换宏定义，参考frtp
#define MAJOR(dev) (u32)((dev & 0xfff00000) >> 20)
#define MINOR(dev) (u32)(dev & 0xfffff)

union Rule
{
	char path[PAGE_SIZE];
	struct
	{
		u64 not_inode; // used for judging whether it's inode filter
		u64 inode;
		dev_t dev; // 设备号
	};
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, union Rule);
	__uint(max_entries, 1);
} filter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} logs SEC(".maps");

struct BpfData
{
	uid_t uid;
	pid_t pid;
	int fd;
	char comm[16];
};

typedef u64 pid_tgid_t;

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_tgid_t);
	__type(value, size_t);
	__uint(max_entries, 1);
} file_stat SEC(".maps");

static bool file_filter(struct file *file)
{
	long bpf_ret;
	bool ret = false;
	u32 fkey = 0;
	union Rule *rule;
	u32 pkey = __LINE__;
	char *path = NULL;

	path = malloc_page(pkey);
	if (!path)
	{
		bpf_err("fail to malloc page");
		return false;
	}

	bpf_ret = bpf_d_path(&file->f_path, path, PAGE_SIZE);
	if (bpf_ret < 0)
	{
		bpf_err("fail to parse path: %ld", bpf_ret);
		goto exit;
	}

	rule = bpf_map_lookup_elem(&filter, &fkey);
	if (!rule)
	{
		goto exit;
	}
	DEBUG(0, "%s %s", rule->path, path);
	if (rule->not_inode)
	{
		if (strncmp(path, rule->path, PAGE_SIZE))
		{
			goto exit;
		}
	}
	else
	{
		// 使用设备号进行比较
		if (rule->dev != file->f_path.mnt->mnt_sb->s_dev)
		{
			goto exit;
		}
		if (rule->inode != file->f_inode->i_ino)
		{
			goto exit;
		}
	}

	if (0) // change to 1 when DEBUG dev
	{
		bpf_info(
			"dev: major=%u, minor=%u",
			MAJOR(file->f_path.mnt->mnt_sb->s_dev),
			MINOR(file->f_path.mnt->mnt_sb->s_dev)
		);
	}
	ret = true;

exit:
	free_page(pkey);
	return ret;
}

static void send_log(struct task_struct *task, int fd)
{
	long ret;
	pid_t pid = task->pid;
	uid_t uid = task->cred->uid.val;
	struct BpfData log = {
		.uid = uid,
		.pid = pid,
		.fd = fd,
	};

	legacy_strncpy(log.comm, task->comm, 16);
	DEBUG(0, "pid: %d comm: %s", pid, log.comm);
	ret = bpf_ringbuf_output(&logs, &log, sizeof(log), 0);
	if (ret)
	{
		bpf_err("ringbuf err: %ld", ret);
	}
}

SEC("iter/task_file")
int file_iterator(struct bpf_iter__task_file *ctx)
{
	struct task_struct *task;
	struct file *file;

	task = ctx->task;
	file = ctx->file;

	if (!task || !file)
	{
		return 0;
	}

	if (task->pid != task->tgid)
	{
		return 0;
	}

	if (!file_filter(file))
	{
		return 0;
	}

	send_log(task, ctx->fd);
	return 0;
}

SEC("iter/task_vma")
int vma_iterator(struct bpf_iter__task_vma *ctx)
{
	struct task_struct *task;
	struct vm_area_struct *vma;
	struct file *file;
	task = ctx->task;
	if (!task)
	{
		return 0;
	}

	if (task->pid != task->tgid)
	{
		return 0;
	}

	vma = ctx->vma;
	if (!vma)
	{
		return 0;
	}
	file = vma->vm_file;
	if (!file)
	{
		return 0;
	}

	if (!file_filter(file))
	{
		return 0;
	}

	send_log(task, -1);
	return 0;
}