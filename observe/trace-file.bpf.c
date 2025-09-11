
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "jhash.h"
#include "Kstr-utils.h"
#include "Kmem.h"
#include "Kcom.h"
#include "fcntl-defs.h"
#include "Kerrno.h"

#define XATTR_NAME_MAX 256
#define XATTR_VALUE_MAX 1024
#define PATH_MAX 4096
char _license[] SEC("license") = "GPL";

// 添加设备号转换宏定义，参考frtp
#define MAJOR(dev) (u32)((dev & 0xfff00000) >> 20)
#define MINOR(dev) (u32)(dev & 0xfffff)

union Rule
{
	char path[PATH_MAX];
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

struct TpExitCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	int not_used;
	long ret;
};

#if defined(__loongarch__)
struct FuncArgs
{
	void *argv[6];
};

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);
	__type(value, struct FuncArgs);
	__uint(max_entries, 1000);
} funcargsMap SEC(".maps");
#endif

static struct inode *g_inode;

SEC("iter/task_file")
int find_file_inode(struct bpf_iter__task_file *ctx)
{
	long ret;
	struct task_struct *task;
	struct task_struct *current;
	struct file *file;

	u32 pkey = __LINE__;
	char *path = NULL;
	u32 fkey = 0;
	union Rule *rule;

	task = ctx->task;
	file = ctx->file;

	if (!task || !file)
	{
		return 0;
	}

	current = (typeof(current))bpf_get_current_task();
	if (task != current)
	{
		return 0;
	}

	path = malloc_page(pkey);
	if (!path)
	{
		bpf_err("fail to malloc page");
		return 0;
	}

	ret = bpf_d_path(&file->f_path, path, PATH_MAX);
	if (ret < 0)
	{
		bpf_err("fail to parse path");
		goto exit;
	}

	rule = bpf_map_lookup_elem(&filter, &fkey);
	if (!rule)
	{
		goto exit;
	}

	DEBUG(0, "Path: %s, inode: %d", path, BPF_CORE_READ(file, f_inode, i_ino));
	if (rule->not_inode)
	{
		if (strncmp(path, rule->path, PATH_MAX))
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
		if (rule->inode != BPF_CORE_READ(file, f_inode, i_ino))
		{
			goto exit;
		}
	}

	DEBUG(
		1,
		"find target: (%s), inode: [%d]",
		path[0] ? path : "null",
		BPF_CORE_READ(file, f_inode, i_ino)
	);

	if (0) // change to 1 when DEBUG dev
	{
		bpf_info(
			"dev: major=%u, minor=%u",
			MAJOR(file->f_path.mnt->mnt_sb->s_dev),
			MINOR(file->f_path.mnt->mnt_sb->s_dev)
		);
	}

	g_inode = file->f_inode;

exit:
	free_page(pkey);
	return 0;
}

enum LogType
{
	LOG_NONE,
	LOG_OPEN,
	LOG_CLOSE,
	LOG_GETXATTR,
	LOG_SETXATTR,
	LOG_LISTXATTR,
	LOG_REMOVEXATTR,
	LOG_GETACL,
	LOG_SETACL,
	LOG_CHOWN,
	LOG_CHMOD,
	LOG_STAT,
	LOG_MMAP,
	LOG_FLOCK,
	LOG_FCNTL,
	LOG_LINK,
	LOG_UNLINK,
	LOG_TRUNCATE,
	LOG_IOCTL,
	LOG_RENAME,
	LOG_FALLOCATE,
	LOG_READ,
	LOG_WRITE,
	LOG_READV,
	LOG_WRITEV,
	LOG_COPY_FILE_RANGE,
	LOG_SENDFILE,
	LOG_SPLICE,
	LOG_MKNOD,
	LOG_MKDIR,
	LOG_RMDIR,
	LOG_SYMLINK,
	LOG_LSEEK,
};

struct BpfData
{
	uid_t uid;
	pid_t pid;
	char comm[16];
	enum LogType log_type;
	char data[];
} __attribute__((__packed__));

struct OpenLog
{
	unsigned long i_ino;
	long ret;
	fmode_t f_mode;
} __attribute__((__packed__));

static u32 lkey = __LINE__;
static void *send_log(enum LogType log_type, void *sublog, size_t sz)
{
	long ret;
	struct BpfData *log;

	if (!sublog)
	{
		log = (typeof(log))malloc_page(lkey);
		if (!log)
		{
			bpf_err("out of mem");
			return NULL;
		}
		return log->data;
	}

	if (sz == 0)
	{
		free_page(lkey);
		return NULL;
	}

	log = sublog - sizeof(*log);
	log->pid = bpf_get_current_pid_tgid();
	log->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(log->comm, 16);
	log->log_type = log_type;

	ret = bpf_ringbuf_output(&logs, log, sizeof(*log) + sz, 0);
	if (ret)
	{
		bpf_err("bpf_ringbuf_output: %ld", ret);
	}

	free_page(lkey);
	return log;
}

static void *lookup_log()
{
	struct BpfData *log;
	log = (typeof(log))lookup_page(lkey);
	if (log)
	{
		return log->data;
	}
	return NULL;
}

#if defined(__loongarch__)
SEC("kprobe/do_dentry_open")
int BPF_KPROBE(
	enter_file_open,
	struct file *f,
	struct inode *inode,
	int (*open)(struct inode *, struct file *)
)
{
	pid_t pid = bpf_get_current_pid_tgid();
	struct FuncArgs args = {
		.argv =
			{
				   [0] = f,
				   [1] = inode,
				   }
	};
	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}
#endif

#if !defined(__loongarch__)
SEC("fexit/do_dentry_open")
int BPF_PROG(
	exit_file_open,
	struct file *f,
	struct inode *inode,
	int (*open)(struct inode *, struct file *),
	long ret
)
{
#else
SEC("kretprobe/do_dentry_open")
int BPF_KRETPROBE(exit_file_open, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);

	if (!args)
	{
		return 0;
	}

	struct file *f = args->argv[0];
	struct inode *inode = args->argv[1];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != inode)
	{
		return 0;
	}

	struct OpenLog *openlog;
	openlog = send_log(LOG_NONE, NULL, sizeof(struct OpenLog));
	if (!openlog)
	{
		return 0;
	}

	openlog->f_mode = BPF_CORE_READ(f, f_mode);
	openlog->i_ino = BPF_CORE_READ(inode, i_ino);
	openlog->ret = ret;

	DEBUG(
		0,
		"ino: %lu, mode: %x, ret: %lu",
		openlog->i_ino,
		openlog->f_mode,
		openlog->ret
	);

	DEBUG(0, "sizeof OpenLog: %d", sizeof(struct OpenLog));
	DEBUG(0, "sizeof Log: %d", sizeof(struct BpfData));

	send_log(LOG_OPEN, openlog, sizeof(struct OpenLog));

	return 0;
}

struct CloseLog
{
	unsigned long i_ino;
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fentry/__fput")
int BPF_PROG(fput, struct file *file)
#else
SEC("kprobe/__fput")
int BPF_KPROBE(entry_fput, struct file *file)
#endif
{
	if (!g_inode || BPF_CORE_READ(file, f_inode) != g_inode)
	{
		return 0;
	}

	struct CloseLog *closelog;
	closelog = send_log(LOG_NONE, NULL, sizeof(struct OpenLog));
	if (!closelog)
	{
		return 0;
	}

	closelog->i_ino = BPF_CORE_READ(file, f_inode, i_ino);

	send_log(LOG_CLOSE, closelog, sizeof(struct CloseLog));
	return 0;
}

struct XattrLog
{
	unsigned long i_ino;
	union
	{
		u32 name_list;
		u32 name; // the name string offset to 'action' field
	};
	u32 value; // the value's offset to 'action' field
	size_t size;
	long ret;
	char action[]; // must be less than 4096 - sizeof(Log) - sizeof(XattrLog)
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_getxattr")
int BPF_PROG(
	vfs_getxattr,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *name,
	void *value,
	size_t size,
	long ret
)
{
#else
SEC("kprobe/vfs_getxattr")
int BPF_KPROBE(
	entry_vfs_getxattr,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *name,
	void *value,
	size_t size
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dentry,
				   [2] = (void *)name,
				   [3] = value,
				   [4] = (void *)size,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_getxattr")
int BPF_KRETPROBE(exit_vfs_getxattr, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct dentry *dentry = args->argv[1];
	const char *name = args->argv[2];
	void *value = args->argv[3];
	size_t size = (size_t)args->argv[4];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(dentry, d_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_getxattr value addr: %lx", value);

	size_t st_sz = sizeof(struct XattrLog);
	struct XattrLog *xattrlog;
	xattrlog = send_log(LOG_NONE, NULL, st_sz);
	if (!xattrlog)
	{
		return 0;
	}

	long slen;
	u32 name_off;
	u32 value_off;

	xattrlog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	xattrlog->size = size;
	xattrlog->ret = ret;
	slen = legacy_strncpy(xattrlog->action, "getxattr", 16);

	name_off = slen;
	slen = bpf_read_kstr_ret(
		xattrlog->action + name_off,
		XATTR_NAME_MAX,
		name,
		NOP
	);

	DEBUG(0, "vfs_getxattr slen: %ld", slen);

	value_off = name_off + slen;

	if (value == NULL) // user space request value size
	{
		size = legacy_strncpy(xattrlog->action + value_off, "(null)", 8);
		DEBUG(0, "legacy_strncpy value: %s", xattrlog->action + value_off);
	}
	else
	{
		if (size > XATTR_VALUE_MAX)
		{
			size = XATTR_VALUE_MAX;
		}

		slen = bpf_probe_read_kernel(xattrlog->action + value_off, size, value);

		DEBUG(0, "vfs_getxattr slen: %ld", slen);
	}

	if (slen < 0)
	{
		bpf_err("read kernel mem: %ld", slen);
		size = 1;
	}

	xattrlog->name = name_off;
	xattrlog->value = value_off;

	send_log(LOG_GETXATTR, xattrlog, st_sz + value_off + size);
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_setxattr")
int BPF_PROG(
	vfs_setxattr,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *name,
	const void *_value, // TODO
	size_t size,
	int flags,
	long ret
)
{
#else
SEC("kprobe/vfs_setxattr")
int BPF_KPROBE(
	entry_vfs_setxattr,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *name,
	const void *_value, // TODO
	size_t size,
	int flags
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{[0] = idmap,
				   [1] = dentry,
				   [2] = (void *)name,
				   [3] = (void *)_value,
				   [4] = (void *)size,
				   [5] = (void *)(size_t)flags}
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_setxattr")
int BPF_KRETPROBE(exit_vfs_setxattr, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct dentry *dentry = args->argv[1];
	const char *name = args->argv[2];
	size_t size = (size_t)args->argv[4];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(dentry, d_inode))
	{
		return 0;
	}

	const void *value = NULL; // TODO
	DEBUG(0, "vfs_getxattr value addr: %lx", value);

	size_t st_sz = sizeof(struct XattrLog);
	struct XattrLog *xattrlog;
	xattrlog = send_log(LOG_NONE, NULL, st_sz);
	if (!xattrlog)
	{
		return 0;
	}

	long slen;
	u32 name_off;
	u32 value_off;

	xattrlog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	xattrlog->size = size;
	xattrlog->ret = ret;
	slen = legacy_strncpy(xattrlog->action, "setxattr", 16);

	name_off = slen;
	slen = bpf_read_kstr_ret(
		xattrlog->action + name_off,
		XATTR_NAME_MAX,
		name,
		NOP
	);

	DEBUG(0, "vfs_getxattr slen: %ld", slen);

	value_off = name_off + slen;

	if (value == NULL) // user space request value size
	{
		size = legacy_strncpy(xattrlog->action + value_off, "(null)", 8);
		DEBUG(0, "legacy_strncpy value: %s", xattrlog->action + value_off);
	}
	else
	{
		if (size > XATTR_VALUE_MAX)
		{
			size = XATTR_VALUE_MAX;
		}

		slen = bpf_probe_read_kernel(xattrlog->action + value_off, size, value);

		DEBUG(0, "vfs_getxattr slen: %ld", slen);
	}

	if (slen < 0)
	{
		bpf_err("read kernel mem: %ld", slen);
		size = 1;
	}

	xattrlog->name = name_off;
	xattrlog->value = value_off;

	send_log(LOG_SETXATTR, xattrlog, st_sz + value_off + size);
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_listxattr")
int BPF_PROG(
	vfs_listxattr,
	struct dentry *dentry,
	char *list,
	size_t size,
	long ret
)
{
#else
SEC("kprobe/vfs_listxattr")
int BPF_KPROBE(
	entry_vfs_listxattr,
	struct dentry *dentry,
	char *list,
	size_t size
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = dentry,
				   [1] = list,
				   [2] = (void *)size,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);
	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_listxattr")
int BPF_KRETPROBE(exit_vfs_listxattr, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);

	if (!args)
	{
		return 0;
	}
	struct dentry *dentry = args->argv[0];
	char *list = args->argv[1];
	size_t size = (size_t)args->argv[2];
	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(dentry, d_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_listxattr list addr: %lx", list);

	size_t st_sz = sizeof(struct XattrLog);
	struct XattrLog *xattrlog;
	xattrlog = send_log(LOG_NONE, NULL, st_sz);
	if (!xattrlog)
	{
		return 0;
	}

	long slen;
	u32 name_list_off;

	xattrlog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	xattrlog->size = size;
	xattrlog->ret = ret;
	slen = legacy_strncpy(xattrlog->action, "listxattr", 16);
	name_list_off = slen;

	if (size > XATTR_NAME_MAX + XATTR_VALUE_MAX)
	{
		size = XATTR_NAME_MAX + XATTR_VALUE_MAX;
	}

	if (!list)
	{
		size = legacy_strncpy(xattrlog->action + name_list_off, "(null)", 8);
		DEBUG(
			0,
			"legacy_strncpy namelist: %s",
			xattrlog->action + name_list_off
		);
	}
	else
	{
		slen =
			bpf_probe_read_kernel(xattrlog->action + name_list_off, size, list);

		if (slen < 0)
		{
			bpf_err("read xattr name list: %d", slen);
			size = 1;
		}
	}

	xattrlog->name_list = name_list_off;
	xattrlog->value = 0;

	send_log(LOG_LISTXATTR, xattrlog, st_sz + name_list_off + size);
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_removexattr")
int BPF_PROG(
	vfs_removexattr,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *name,
	long ret
)
{
#else

SEC("kprobe/vfs_removexattr")
int BPF_KPROBE(
	entry_vfs_removexattr,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *name
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dentry,
				   [2] = (void *)name,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}
SEC("kretprobe/vfs_removexattr")
int BPF_KRETPROBE(exit_vfs_removexattr, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);

	if (!args)
	{
		return 0;
	}

	struct dentry *dentry = args->argv[1];
	const char *name = args->argv[2];
	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(dentry, d_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_listxattr list addr: %lx", name);

	size_t st_sz = sizeof(struct XattrLog);
	struct XattrLog *xattrlog;
	xattrlog = send_log(LOG_NONE, NULL, st_sz);
	if (!xattrlog)
	{
		return 0;
	}

	long slen;
	u32 name_off;
	size_t size;

	xattrlog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	xattrlog->size = 0;
	xattrlog->ret = ret;
	slen = legacy_strncpy(xattrlog->action, "removexattr", 16);
	name_off = slen;

	slen = bpf_read_kstr_ret(
		xattrlog->action + name_off,
		XATTR_NAME_MAX,
		name,
		NOP
	);

	size = slen;
	if (size > XATTR_NAME_MAX)
	{
		size = XATTR_NAME_MAX;
	}

	xattrlog->name = name_off;
	xattrlog->value = 0;

	send_log(LOG_REMOVEXATTR, xattrlog, st_sz + name_off + size);
	return 0;
}

struct AclEntry // posix acl entry
{
	short e_tag;
	unsigned short e_perm;
	union
	{
		u32 e_uid;
		u32 e_gid;
	};
} __attribute__((__packed__));
;

struct AclLog
{
	unsigned long i_ino;
	u32 name;	   // the name string offset to 'action' field
	u32 acl_entry; // the acl entry's offset to 'action' field
	size_t count;
	long ret;
	char action[]; // must be less than 4096 - sizeof(Log) - sizeof(AclLog)
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_get_acl")
int BPF_PROG(
	vfs_get_acl,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *acl_name,
	struct posix_acl *ret
)
{
#else
SEC("kprobe/vfs_get_acl")
int BPF_KPROBE(
	entry_vfs_get_acl,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *acl_name
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dentry,
				   [2] = (void *)acl_name,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_get_acl")
int BPF_KRETPROBE(exit_vfs_get_acl, struct posix_acl *ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct dentry *dentry = args->argv[1];
	const char *acl_name = args->argv[2];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(dentry, d_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_get_acl acl_name: %s", acl_name);
	DEBUG(0, "sizeof(AclEntry): %d", sizeof(struct AclEntry));
	DEBUG(0, "sizeof(posix_acl_entry): %d", sizeof(struct posix_acl_entry));

	size_t st_sz = sizeof(struct AclLog);
	struct AclLog *acllog;
	acllog = send_log(LOG_NONE, NULL, st_sz);
	if (!acllog)
	{
		return 0;
	}

	acllog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	if (ret)
	{
		acllog->count = BPF_CORE_READ(ret, a_count);
		acllog->ret = 0;
	}
	else
	{
		acllog->count = 0;
		acllog->ret = -1;
	}

	long slen;
	u32 name_off;
	u32 acl_entry_off;
	size_t size;

	slen = legacy_strncpy(acllog->action, "get_acl", 16);
	name_off = slen;

	slen = bpf_read_kstr_ret(
		acllog->action + name_off,
		XATTR_NAME_MAX,
		acl_name,
		NOP
	);

	acl_entry_off = name_off + slen;
	size = BPF_CORE_READ(ret, a_count) * sizeof(struct AclEntry);
	if (size > XATTR_VALUE_MAX)
	{
		size = XATTR_VALUE_MAX;
	}
	slen = bpf_probe_read_kernel(
		acllog->action + acl_entry_off,
		size,
		BPF_CORE_READ(ret, a_entries)
	);

	if (slen < 0)
	{
		bpf_err("bpf read kernel: %d", slen);
		acllog->count = 0;
		size = 0;
	}

	acllog->name = name_off;
	acllog->acl_entry = acl_entry_off;

	send_log(LOG_GETACL, acllog, st_sz + acl_entry_off + size);
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_set_acl")
int BPF_PROG(
	vfs_set_acl,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *acl_name,
	struct posix_acl *kacl,
	long ret
)
{
#else

SEC("kprobe/vfs_set_acl")
int BPF_KPROBE(
	entry_vfs_set_acl,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *acl_name,
	struct posix_acl *kacl
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dentry,
				   [2] = (void *)acl_name,
				   [3] = kacl,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_set_acl")
int BPF_KRETPROBE(exit_vfs_set_acl, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct dentry *dentry = args->argv[1];
	const char *acl_name = args->argv[2];
	struct posix_acl *kacl = args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(dentry, d_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_set_acl kacl: %lx", kacl);

	size_t st_sz = sizeof(struct AclLog);
	struct AclLog *acllog;
	acllog = send_log(LOG_NONE, NULL, st_sz);
	if (!acllog)
	{
		return 0;
	}

	acllog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	acllog->count = BPF_CORE_READ(kacl, a_count);
	acllog->ret = ret;

	long slen;
	u32 name_off;
	u32 acl_entry_off;
	size_t size;

	slen = legacy_strncpy(acllog->action, "set_acl", 16);
	name_off = slen;

	slen = bpf_read_kstr_ret(
		acllog->action + name_off,
		XATTR_NAME_MAX,
		acl_name,
		NOP
	);

	acl_entry_off = name_off + slen;
	size = BPF_CORE_READ(kacl, a_count) * sizeof(struct AclEntry);
	if (size > XATTR_VALUE_MAX)
	{
		size = XATTR_VALUE_MAX;
	}
	slen = bpf_probe_read_kernel(
		acllog->action + acl_entry_off,
		size,
		BPF_CORE_READ(kacl, a_entries)
	);

	if (slen < 0)
	{
		bpf_err("bpf read kernel: %d", slen);
		acllog->count = 0;
		size = 0;
	}

	acllog->name = name_off;
	acllog->acl_entry = acl_entry_off;

	send_log(LOG_SETACL, acllog, st_sz + acl_entry_off + size);
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_remove_acl")
int BPF_PROG(
	vfs_remove_acl,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *acl_name,
	long ret
)
{
#else
SEC("kprobe/vfs_remove_acl")
int BPF_KPROBE(
	entry_vfs_remove_acl,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *acl_name
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dentry,
				   [2] = (void *)acl_name,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_remove_acl")
int BPF_KRETPROBE(exit_vfs_remove_acl, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct dentry *dentry = args->argv[1];
	const char *acl_name = args->argv[2];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(dentry, d_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_remove_acl acl_name: %lx", acl_name);

	size_t st_sz = sizeof(struct AclLog);
	struct AclLog *acllog;
	acllog = send_log(LOG_NONE, NULL, st_sz);
	if (!acllog)
	{
		return 0;
	}

	acllog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	acllog->count = 0;
	acllog->ret = ret;

	long slen;
	u32 name_off;
	size_t size;

	slen = legacy_strncpy(acllog->action, "remove_acl", 16);
	name_off = slen;

	slen = bpf_read_kstr_ret(
		acllog->action + name_off,
		XATTR_NAME_MAX,
		acl_name,
		NOP
	);

	acllog->name = name_off;
	acllog->acl_entry = 0;
	size = slen;

	send_log(LOG_SETACL, acllog, st_sz + name_off + size);
	return 0;
}

struct ChownLog
{
	unsigned long i_ino;
	u32 uid;
	u32 gid;
	long ret;
	char action[];
} __attribute__((__packed__));

// modify attributes of a filesytem object
#if !defined(__loongarch__)
SEC("fexit/chown_common")
int BPF_PROG(
	chown_common,
	const struct path *path,
	uid_t user,
	gid_t group,
	long ret
)
{
#else
SEC("kprobe/chown_common")
int BPF_KPROBE(
	entry_chown_common,
	const struct path *path,
	uid_t user,
	gid_t group
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = (void *)path,
				   [1] = (void *)(size_t)user,
				   [2] = (void *)(size_t)group,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/chown_common")
int BPF_KRETPROBE(exit_chown_common, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	const struct path *path = args->argv[0];
	uid_t user = (uid_t)(size_t)args->argv[1];
	gid_t group = (gid_t)(size_t)args->argv[2];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(path, dentry, d_inode))
	{
		return 0;
	}

	size_t st_sz = sizeof(struct ChownLog);
	struct ChownLog *chownlog;
	chownlog = send_log(LOG_NONE, NULL, st_sz);
	if (!chownlog)
	{
		return 0;
	}

	chownlog->i_ino = BPF_CORE_READ(path, dentry, d_inode, i_ino);
	chownlog->ret = ret;
	chownlog->uid = user;
	chownlog->gid = group;

	size_t size;

	size = legacy_strncpy(chownlog->action, "chown", 16);

	send_log(LOG_CHOWN, chownlog, st_sz + size);
	return 0;
}

struct ChmodLog
{
	unsigned long i_ino;
	u16 mode;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/chmod_common")
int BPF_PROG(chmod_common, const struct path *path, umode_t mode, long ret)
{
#else

SEC("kprobe/chmod_common")
int BPF_KPROBE(entry_chmod_common, const struct path *path, umode_t mode)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = (void *)path,
				   [1] = (void *)(size_t)mode,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/chmod_common")
int BPF_KRETPROBE(exit_chmod_common, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	const struct path *path = args->argv[0];
	umode_t mode = (umode_t)(size_t)args->argv[1];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(path, dentry, d_inode))
	{
		return 0;
	}

	size_t st_sz = sizeof(struct ChmodLog);
	struct ChmodLog *chmodlog;
	chmodlog = send_log(LOG_NONE, NULL, st_sz);
	if (!chmodlog)
	{
		return 0;
	}

	chmodlog->i_ino = BPF_CORE_READ(path, dentry, d_inode, i_ino);
	chmodlog->ret = ret;
	chmodlog->mode = mode;

	size_t size;

	size = legacy_strncpy(chmodlog->action, "chmod", 16);

	send_log(LOG_CHMOD, chmodlog, st_sz + size);
	return 0;
}

struct StatLog
{
	unsigned long i_ino;
	u32 request_mask;
	u32 query_flags;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("lsm/inode_getattr") // this is not for functionality, only for uos
int BPF_PROG(inode_getattr, const struct path *path, long ret)
#else
SEC("kprobe/security_inode_getattr")
int BPF_KPROBE(inode_getattr, const struct path *path)
#endif
{
	char comm[16] = {};
	if (0 == bpf_get_current_comm(comm, 16))
	{
		if (bpf_strncmp(comm, 16, "QThread") == 0)
		{
			return -2; // -ENOENT
		}
	}
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_getattr_nosec") // vfs_getattr is probably inlined in its caller
int BPF_PROG(
	vfs_getattr,
	const struct path *path,
	struct kstat *stat,
	u32 request_mask,
	unsigned int query_flags,
	long ret
)
{
#else
SEC("kprobe/vfs_getattr_nosec")
int BPF_KPROBE(
	entry_vfs_getattr,
	const struct path *path,
	struct kstat *stat,
	u32 request_mask,
	unsigned int query_flags
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = (void *)path,
				   [1] = stat,
				   [2] = (void *)(size_t)request_mask,
				   [3] = (void *)(size_t)query_flags,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_getattr_nosec")
int BPF_KRETPROBE(exit_vfs_getattr, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	const struct path *path = args->argv[0];
	struct kstat *stat = args->argv[1];
	u32 request_mask = (u32)(size_t)args->argv[2];
	unsigned int query_flags = (unsigned int)(size_t)args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(path, dentry, d_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_getattr stat: %lx", stat);
	size_t st_sz = sizeof(struct StatLog);
	struct StatLog *statlog;
	statlog = send_log(LOG_NONE, NULL, st_sz);
	if (!statlog)
	{
		return 0;
	}

	statlog->i_ino = BPF_CORE_READ(path, dentry, d_inode, i_ino);
	statlog->ret = ret;
	statlog->request_mask = request_mask;
	statlog->query_flags = query_flags;

	size_t size;
	size = legacy_strncpy(statlog->action, "getattr", 16);

	send_log(LOG_STAT, statlog, st_sz + size);
	return 0;
}

struct MmapLog
{
	unsigned long i_ino;
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flag;
	unsigned long pgoff;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vm_mmap_pgoff")
int BPF_PROG(
	vm_mmap_pgoff,
	struct file *file,
	unsigned long addr,
	unsigned long len,
	unsigned long prot,
	unsigned long flag,
	unsigned long pgoff,
	long ret
)
{
#else
SEC("kprobe/vm_mmap_pgoff")
int BPF_KPROBE(
	entry_vm_mmap_pgoff,
	struct file *file,
	unsigned long addr,
	unsigned long len,
	unsigned long prot,
	unsigned long flag,
	unsigned long pgoff
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = file,
				   [1] = (void *)addr,
				   [2] = (void *)len,
				   [3] = (void *)prot,
				   [4] = (void *)flag,
				   [5] = (void *)pgoff,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vm_mmap_pgoff")
int BPF_KRETPROBE(exit_vm_mmap_pgoff, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *file = args->argv[0];
	unsigned long addr = (unsigned long)args->argv[1];
	unsigned long len = (unsigned long)args->argv[2];
	unsigned long prot = (unsigned long)args->argv[3];
	unsigned long flag = (unsigned long)args->argv[4];
	unsigned long pgoff = (unsigned long)args->argv[5];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(file, f_inode))
	{
		return 0;
	}

	DEBUG(0, "vm_mmap_pgoff prot: %lx", prot);
	size_t st_sz = sizeof(struct MmapLog);
	struct MmapLog *mmaplog;
	mmaplog = send_log(LOG_NONE, NULL, st_sz);
	if (!mmaplog)
	{
		return 0;
	}

	mmaplog->i_ino = BPF_CORE_READ(file, f_inode, i_ino);
	mmaplog->addr = addr;
	mmaplog->len = len;
	mmaplog->prot = prot;
	mmaplog->flag = flag;
	mmaplog->pgoff = pgoff;
	mmaplog->ret = ret;

	size_t size;
	size = legacy_strncpy(mmaplog->action, "mmap", 16);

	send_log(LOG_MMAP, mmaplog, st_sz + size);
	return 0;
}

struct FlckLog
{
	unsigned long i_ino;
	long arg;
	long ret;
	char action[];
} __attribute__((__packed__));

static void flock_capture(u64 i_ino, long arg, long ret)
{
	DEBUG(0, "flock arg: %lx", arg);
	size_t st_sz = sizeof(struct FlckLog);
	struct FlckLog *flcklog;
	flcklog = send_log(LOG_NONE, NULL, st_sz);
	if (!flcklog)
	{
		return;
	}

	flcklog->i_ino = i_ino;
	flcklog->arg = arg;
	flcklog->ret = ret;

	size_t size;
	size = legacy_strncpy(flcklog->action, "flock", 16);

	send_log(LOG_FLOCK, flcklog, st_sz + size);
}

struct TpFlockEnterCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	unsigned int not_used;
	unsigned long fd;
	unsigned long cmd;
};

struct FlockParam
{
	unsigned long i_ino;
	unsigned char fl_type;
};

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);
	__type(value, struct FlockParam);
	__uint(max_entries, 1000);
} flockParamMap SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_flock")
int sys_enter_flock(struct TpFlockEnterCtx *ctx)
{
	if (!g_inode)
	{
		return 0;
	}
	long ret = 0;
	struct FlockParam param;
	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&flockParamMap, &pid, &param, BPF_ANY);

	if (ret)
	{
		bpf_err("update flock map");
	}

	return 0;
}

#if !defined(__loongarch__)
SEC("lsm/file_lock")
int BPF_PROG(file_lock, struct file *file, unsigned int cmd, long ret)
#else
SEC("kprobe/security_file_lock")
int BPF_KPROBE(file_lock, struct file *file, unsigned int cmd)
#endif
{
	pid_t pid = bpf_get_current_pid_tgid();
	struct FlockParam *param;
	param = bpf_map_lookup_elem(&flockParamMap, &pid);
	if (!param)
	{
		return 0;
	}

	if (g_inode != BPF_CORE_READ(file, f_inode))
	{
		bpf_map_delete_elem(&flockParamMap, &pid);
		return 0;
	}

	param->fl_type = cmd;
	param->i_ino = BPF_CORE_READ(file, f_inode, i_ino);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_flock")
int sys_exit_flock(struct TpExitCtx *ctx)
{
	struct FlockParam *param;
	pid_t pid = bpf_get_current_pid_tgid();
	param = bpf_map_lookup_elem(&flockParamMap, &pid);
	if (!param)
	{
		return 0;
	}

	bpf_map_delete_elem(&flockParamMap, &pid);

	if (param->i_ino == 0)
	{ // in case syscall flock returns error without entering lsm file_lock
		return 0;
	}

	flock_capture(param->i_ino, param->fl_type, ctx->ret);
	return 0;
}

struct FcntlLog
{
	unsigned long i_ino;
	unsigned int cmd;
	unsigned long arg;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/do_fcntl")
int BPF_PROG(
	do_fcntl,
	int fd,
	unsigned int cmd,
	unsigned long arg,
	struct file *filp,
	long ret
)
{
#else
SEC("kprobe/do_fcntl")
int BPF_KPROBE(
	entry_do_fcntl,
	int fd,
	unsigned int cmd,
	unsigned long arg,
	struct file *filp
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = (void *)(size_t)fd,
				   [1] = (void *)(size_t)cmd,
				   [2] = (void *)arg,
				   [3] = filp,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/do_fcntl")
int BPF_KRETPROBE(exit_do_fcntl, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	unsigned int cmd = (unsigned int)(size_t)args->argv[1];
	unsigned long arg = (unsigned long)args->argv[2];
	struct file *filp = args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(filp, f_inode))
	{
		return 0;
	}

	DEBUG(0, "do_fcntl cmd: %u, arg: %lx", cmd, arg);
	size_t st_sz = sizeof(struct FcntlLog);
	struct FcntlLog *fcntlog;
	fcntlog = send_log(LOG_NONE, NULL, st_sz);
	if (!fcntlog)
	{
		return 0;
	}

	fcntlog->i_ino = BPF_CORE_READ(filp, f_inode, i_ino);
	fcntlog->cmd = cmd;
	fcntlog->arg = arg;
	fcntlog->ret = ret;

	size_t size;
	size = legacy_strncpy(fcntlog->action, "fcntl", 16);

	send_log(LOG_FCNTL, fcntlog, st_sz + size);
	return 0;
}

struct LinkLog
{
	unsigned long i_ino;
	unsigned long i_ino_new;
	unsigned long dir_ino;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_link")
int BPF_PROG(
	vfs_link,
	struct dentry *old_dentry,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *new_dentry,
	struct inode **delegated_inode,
	long ret
)
{
#else
SEC("kprobe/vfs_link")
int BPF_KPROBE(
	entry_vfs_link,
	struct dentry *old_dentry,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *new_dentry,
	struct inode **delegated_inode
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = old_dentry,
				   [1] = idmap,
				   [2] = dir,
				   [3] = new_dentry,
				   [4] = delegated_inode,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_link")
int BPF_KRETPROBE(exit_vfs_link, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct dentry *old_dentry = args->argv[0];
	struct inode *dir = args->argv[2];
	struct dentry *new_dentry = args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode ||
		(g_inode != BPF_CORE_READ(old_dentry, d_inode) && g_inode != dir))
	{
		return 0;
	}

	DEBUG(0, "vfs_link old: %lx, new: %lx", old_dentry, new_dentry);
	size_t st_sz = sizeof(struct LinkLog);
	struct LinkLog *linklog;
	linklog = send_log(LOG_NONE, NULL, st_sz);
	if (!linklog)
	{
		return 0;
	}

	linklog->i_ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
	linklog->i_ino_new = BPF_CORE_READ(new_dentry, d_inode, i_ino);
	linklog->dir_ino = BPF_CORE_READ(dir, i_ino);
	linklog->ret = ret;

	size_t size;
	size = legacy_strncpy(linklog->action, "link", 16);

	send_log(LOG_LINK, linklog, st_sz + size);
	return 0;
}

#if !defined(__loongarch__)
SEC("fentry/vfs_unlink")
int BPF_PROG(
	vfs_unlink,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	struct inode **delegated_inode
)
#else
SEC("kprobe/vfs_unlink")
int BPF_KPROBE(
	vfs_unlink,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	struct inode **delegated_inode
)
#endif
{
	/**
	dentry->d_inode inode may be freed at the exit of vfs_unlink,
	we need to capture the inode before it is freed,
	so we use fentry plus fexit instead of only fexit
	*/
	if (!g_inode ||
		(g_inode != BPF_CORE_READ(dentry, d_inode) && g_inode != dir))
	{
		return 0;
	}

	size_t st_sz = sizeof(struct LinkLog);
	struct LinkLog *linklog;
	linklog = send_log(LOG_NONE, NULL, st_sz);
	if (!linklog)
	{
		return 0;
	}

	linklog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	linklog->i_ino_new = 0;
	linklog->dir_ino = BPF_CORE_READ(dir, i_ino);

	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_unlink")
int BPF_PROG(
	vfs_unlink_exit,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	struct inode **delegated_inode,
	long ret
)
{
#else
SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(exit_vfs_unlink, long ret)
{
#endif
	size_t st_sz = sizeof(struct LinkLog);
	struct LinkLog *linklog;
	linklog = lookup_log();
	if (!linklog)
	{
		return 0;
	}

#if !defined(__loongarch__)
	DEBUG(0, "vfs_unlink dentry: %lx", dentry);
#endif
	linklog->ret = ret;
	size_t size;
	size = legacy_strncpy(linklog->action, "unlink", 16);
	send_log(LOG_UNLINK, linklog, st_sz + size);
	return 0;
}

struct TruncateLog
{
	unsigned long i_ino;
	unsigned long length;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/do_truncate")
int BPF_PROG(
	do_truncate,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	loff_t length,
	unsigned int time_attrs,
	struct file *filp,
	long ret
)
{
#else
SEC("kprobe/do_truncate")
int BPF_KPROBE(
	entry_do_truncate,
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	loff_t length,
	unsigned int time_attrs,
	struct file *filp
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dentry,
				   [2] = (void *)length,
				   [3] = (void *)(size_t)time_attrs,
				   [4] = filp,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/do_truncate")
int BPF_KRETPROBE(exit_do_truncate, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct dentry *dentry = args->argv[1];
	loff_t length = (loff_t)args->argv[2];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(dentry, d_inode))
	{
		return 0;
	}

	DEBUG(0, "do_truncate dentry: %lx", dentry);
	size_t st_sz = sizeof(struct TruncateLog);
	struct TruncateLog *truncatelog;
	truncatelog = send_log(LOG_NONE, NULL, st_sz);
	if (!truncatelog)
	{
		return 0;
	}

	truncatelog->i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	truncatelog->length = length;
	truncatelog->ret = ret;

	size_t size;
	size = legacy_strncpy(truncatelog->action, "truncate", 16);

	send_log(LOG_TRUNCATE, truncatelog, st_sz + size);
	return 0;
}

struct IoctlLog
{
	unsigned long i_ino;
	unsigned int cmd;
	unsigned long arg;
	long ret;
	char action[];
} __attribute__((__packed__));

SEC("tracepoint/syscalls/sys_enter_ioctl")
int ioctl_entry(struct TpExitCtx *ctx)
{
	if (!g_inode)
	{
		return 0;
	}
	size_t st_sz = sizeof(struct IoctlLog);
	struct IoctlLog *ioctllog;
	ioctllog = send_log(LOG_NONE, NULL, st_sz);
	if (!ioctllog)
	{
		return 0;
	}
	return 0;
}

static int ioctl_capture(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct IoctlLog *ioctllog;
	ioctllog = lookup_log();
	if (!ioctllog)
	{
		return 0;
	}

	if (!g_inode || g_inode != BPF_CORE_READ(filp, f_inode))
	{
		send_log(LOG_NONE, ioctllog, 0); // just free
		return 0;
	}

	ioctllog->i_ino = BPF_CORE_READ(filp, f_inode, i_ino);
	ioctllog->cmd = cmd;
	ioctllog->arg = arg;
	DEBUG(0, "ioctl cmd: %lx arg: %d", cmd, arg);

	return 0;
}

#if !defined(__loongarch__)
SEC("lsm/file_ioctl")
int BPF_PROG(file_ioctl, struct file *filp, unsigned int cmd, unsigned long arg)
#else
SEC("kprobe/security_file_ioctl")
int BPF_PROG(file_ioctl, struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
	return ioctl_capture(filp, cmd, arg);
}
#if !defined(__loongarch__)
SEC("lsm/file_ioctl_compat")
int BPF_PROG(
	file_ioctl_compat,
	struct file *filp,
	unsigned int cmd,
	unsigned long arg
)
#else
SEC("kprobe/security_file_ioctl_compat")
int BPF_KPROBE(
	file_ioctl_compat,
	struct file *filp,
	unsigned int cmd,
	unsigned long arg
)
#endif
{
	return ioctl_capture(filp, cmd, arg);
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int ioctl_exit(struct TpExitCtx *ctx)
{
	struct IoctlLog *ioctllog;
	ioctllog = lookup_log();
	if (!ioctllog)
	{
		return 0;
	}
	/**
	 * SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned
	 * long, arg)
	 * {
	 *     struct fd f = fdget(fd);
	 *     int error;
	 *
	 *     if (!f.file)
	 *         return -EBADF;
	 *
	 *     error = security_file_ioctl(f.file, cmd, arg);
	 *     ...
	 * }
	 */
	// in case ioctl return for EBADF
	if (ioctllog->i_ino == 0)
	{
		send_log(LOG_NONE, ioctllog, 0); // just free
		return 0;
	}

	unsigned int cmd = ioctllog->cmd;
	int ret = ctx->ret;
	DEBUG(0, "ioctl cmd: %lx ret: %d", cmd, ret);
	ioctllog->ret = ret;

	size_t st_sz = sizeof(struct IoctlLog);
	size_t size;
	size = legacy_strncpy(ioctllog->action, "ioctl", 16);
	send_log(LOG_IOCTL, ioctllog, st_sz + size);
	return 0;
}

struct RenameLog
{
	unsigned long i_ino;
	unsigned int old_name;
	unsigned int new_name;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_rename")
int BPF_PROG(vfs_rename, struct renamedata *rd, long ret)
{
#else
SEC("kprobe/vfs_rename")
int BPF_KPROBE(entry_vfs_rename, struct renamedata *rd)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = rd,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_rename")
int BPF_KRETPROBE(exit_vfs_rename, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct renamedata *rd = args->argv[0];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
	struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);
	struct inode *source = BPF_CORE_READ(old_dentry, d_inode);

	if (!g_inode || g_inode != source)
	{
		return 0;
	}

	DEBUG(0, "rename rd: %lx", rd);
	size_t st_sz = sizeof(struct RenameLog);
	struct RenameLog *renamelog;
	renamelog = send_log(LOG_NONE, NULL, st_sz);
	if (!renamelog)
	{
		return 0;
	}

	renamelog->i_ino = BPF_CORE_READ(source, i_ino);
	renamelog->ret = ret;

	size_t size;
	size_t old_name;
	size_t new_name;
	size = legacy_strncpy(renamelog->action, "ioctl", 16);
	old_name = size;

	size = bpf_read_kstr_ret(
		renamelog->action + old_name,
		32,
		BPF_CORE_READ(old_dentry, d_iname),
		NOP
	);

	new_name = old_name + size;

	size = bpf_read_kstr_ret(
		renamelog->action + new_name,
		32,
		BPF_CORE_READ(new_dentry, d_iname),
		NOP
	);

	renamelog->old_name = old_name;
	renamelog->new_name = new_name;

	send_log(LOG_RENAME, renamelog, st_sz + new_name + size);
	return 0;
}

struct FallocateLog
{
	unsigned long i_ino;
	int mode;
	unsigned long offset;
	unsigned long len;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_fallocate")
int BPF_PROG(
	vfs_fallocate,
	struct file *file,
	int mode,
	loff_t offset,
	loff_t len,
	long ret
)
{
#else
SEC("kprobe/vfs_fallocate")
int BPF_KPROBE(
	entry_vfs_fallocate,
	struct file *file,
	int mode,
	loff_t offset,
	loff_t len
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = file,
				   [1] = (void *)(size_t)mode,
				   [2] = (void *)offset,
				   [3] = (void *)len,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_fallocate")
int BPF_KRETPROBE(exit_vfs_fallocate, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *file = args->argv[0];
	int mode = (int)(size_t)args->argv[1];
	loff_t offset = (loff_t)args->argv[2];
	loff_t len = (loff_t)args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(file, f_inode))
	{
		return 0;
	}

	DEBUG(0, "fallocate mode: %x", mode);
	size_t st_sz = sizeof(struct FallocateLog);
	struct FallocateLog *fallclog;
	fallclog = send_log(LOG_NONE, NULL, st_sz);
	if (!fallclog)
	{
		return 0;
	}

	fallclog->i_ino = BPF_CORE_READ(file, f_inode, i_ino);
	fallclog->mode = mode;
	fallclog->offset = offset;
	fallclog->len = len;
	fallclog->ret = ret;

	size_t size;
	size = legacy_strncpy(fallclog->action, "ioctl", 16);

	send_log(LOG_FALLOCATE, fallclog, st_sz + size);
	return 0;
}

struct RwLog
{
	unsigned long i_ino;
	unsigned long count; // size of kernel buf
	unsigned long pos;
	long ret;
	char action[];
} __attribute__((__packed__));

static void rw_capture(
	unsigned long i_ino,
	size_t count,
	unsigned long pos,
	long ret,
	int write
)
{
	DEBUG(0, "rw_capture %s count: %lu", write ? "write" : "read", count);
	size_t st_sz = sizeof(struct RwLog);
	struct RwLog *rwlog;
	rwlog = send_log(LOG_NONE, NULL, st_sz);
	if (!rwlog)
	{
		return;
	}

	rwlog->i_ino = i_ino;
	rwlog->count = count;
	rwlog->pos = pos;
	rwlog->ret = ret;

	size_t size;
	if (write)
	{
		size = legacy_strncpy(rwlog->action, "write", 16);
	}
	else
	{
		size = legacy_strncpy(rwlog->action, "read", 16);
	}

	if (write)
	{
		send_log(LOG_WRITE, rwlog, st_sz + size);
	}
	else
	{
		send_log(LOG_READ, rwlog, st_sz + size);
	}
}

#if !defined(__loongarch__)
SEC("fexit/vfs_read")
int BPF_PROG(
	vfs_read,
	struct file *file,
	char *buf,
	size_t count,
	loff_t *pos,
	long ret
)
{
#else
SEC("kprobe/vfs_read")
int BPF_KPROBE(
	entry_vfs_read,
	struct file *file,
	char *buf,
	size_t count,
	loff_t *pos
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = file,
				   [1] = buf,
				   [2] = (void *)count,
				   [3] = pos,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(exit_vfs_read, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *file = args->argv[0];
	size_t count = (size_t)args->argv[2];
	loff_t *pos = args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(file, f_inode))
	{
		return 0;
	}

	loff_t off = 0;
	if (pos)
	{
		bpf_read_kmem_ret(&off, pos, NOP);
	}
	else
	{
		off = (loff_t)-1;
	}
	rw_capture(BPF_CORE_READ(file, f_inode, i_ino), count, off, ret, 0);
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_write")
int BPF_PROG(
	vfs_write,
	struct file *file,
	const char *buf,
	size_t count,
	loff_t *pos,
	long ret
)
{
#else
SEC("kprobe/vfs_write")
int BPF_KPROBE(
	entry_vfs_write,
	struct file *file,
	const char *buf,
	size_t count,
	loff_t *pos
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = file,
				   [1] = (void *)buf,
				   [2] = (void *)count,
				   [3] = pos,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(exit_vfs_write, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *file = args->argv[0];
	size_t count = (size_t)args->argv[2];
	loff_t *pos = args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(file, f_inode))
	{
		return 0;
	}

	loff_t off = 0;
	if (pos)
	{
		bpf_read_kmem_ret(&off, pos, NOP);
	}
	else
	{
		off = (loff_t)-1;
	}
	rw_capture(BPF_CORE_READ(file, f_inode, i_ino), count, off, ret, 1);
	return 0;
}

struct RwvLog
{
	unsigned long i_ino;
	unsigned int sz_arr; // offset(againt 'action') of an array of reading size
	unsigned int count;	 // count of 'size' in array
	unsigned long pos;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_readv")
int BPF_PROG(
	vfs_readv,
	struct file *file,
	const struct iovec __user *vec,
	unsigned long vlen,
	loff_t *ppos,
	rwf_t flags,
	long ret
)
{
#else
SEC("kprobe/vfs_readv")
int BPF_KPROBE(
	entry_vfs_readv,
	struct file *file,
	const struct iovec __user *vec,
	unsigned long vlen,
	loff_t *ppos,
	rwf_t flags
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = file,
				   [1] = (void *)vec,
				   [2] = (void *)vlen,
				   [3] = ppos,
				   [4] = (void *)(size_t)flags,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_readv")
int BPF_KRETPROBE(exit_vfs_readv, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *file = args->argv[0];
	const struct iovec __user *vec = args->argv[1];
	unsigned long vlen = (size_t)args->argv[2];
	loff_t *ppos = args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(file, f_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_readv vlen: %lu", vlen);
	size_t st_sz = sizeof(struct RwvLog);
	struct RwvLog *rwvlog;
	rwvlog = send_log(LOG_NONE, NULL, st_sz);
	if (!rwvlog)
	{
		return 0;
	}

	loff_t pos;
	bpf_read_kmem_ret(&pos, ppos, NOP);
	rwvlog->i_ino = BPF_CORE_READ(file, f_inode, i_ino);
	rwvlog->count = vlen;
	rwvlog->pos = pos;
	rwvlog->ret = ret;

	size_t size;
	size_t sz_arr;
	size_t left;
	size_t *psz;
	size = legacy_strncpy(rwvlog->action, "readv", 16);

	sz_arr = size;
	psz = (size_t *)(rwvlog->action + sz_arr);
	left = PAGE_SIZE - sizeof(struct BpfData) - sizeof(struct RwvLog) - 16;
	if (vlen > left / sizeof(size_t))
	{
		vlen = left / sizeof(size_t);
	}

	size_t i = 0;
	while (i < vlen)
	{
		bpf_read_umem_ret(&psz[i], &vec[i].iov_len, NOP);
		DEBUG(0, "readv size: %lu", psz[i]);
		i++;
	}

	rwvlog->sz_arr = sz_arr;
	st_sz += size + i * sizeof(size_t);
	DEBUG(0, "sz_arr: %lu st_sz: %lu", sz_arr, st_sz);
	send_log(LOG_READV, rwvlog, st_sz);
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_writev")
int BPF_PROG(
	vfs_writev,
	struct file *file,
	const struct iovec __user *vec,
	unsigned long vlen,
	loff_t *ppos,
	rwf_t flags,
	long ret
)
{
#else
SEC("kprobe/vfs_writev")
int BPF_KPROBE(
	entry_vfs_writev,
	struct file *file,
	const struct iovec __user *vec,
	unsigned long vlen,
	loff_t *ppos,
	rwf_t flags
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = file,
				   [1] = (void *)vec,
				   [2] = (void *)vlen,
				   [3] = ppos,
				   [4] = (void *)(size_t)flags,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_writev")
int BPF_KRETPROBE(exit_vfs_writev, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *file = args->argv[0];
	const struct iovec __user *vec = args->argv[1];
	unsigned long vlen = (size_t)args->argv[2];
	loff_t *ppos = args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != BPF_CORE_READ(file, f_inode))
	{
		return 0;
	}

	DEBUG(0, "vfs_writev vlen: %lu", vlen);
	size_t st_sz = sizeof(struct RwvLog);
	struct RwvLog *rwvlog;
	rwvlog = send_log(LOG_NONE, NULL, st_sz);
	if (!rwvlog)
	{
		return 0;
	}

	loff_t pos;
	bpf_read_kmem_ret(&pos, ppos, NOP);
	rwvlog->i_ino = BPF_CORE_READ(file, f_inode, i_ino);
	rwvlog->count = vlen;
	rwvlog->pos = pos;
	rwvlog->ret = ret;

	size_t size;
	size_t sz_arr;
	size_t left;
	size_t *psz;
	size = legacy_strncpy(rwvlog->action, "writev", 16);

	sz_arr = size;
	psz = (size_t *)(rwvlog->action + sz_arr);
	left = PAGE_SIZE - sizeof(struct BpfData) - sizeof(struct RwvLog) - 16;
	if (vlen > left / sizeof(size_t))
	{
		vlen = left / sizeof(size_t);
	}

	size_t i = 0;
	while (i < vlen)
	{
		bpf_read_umem_ret(&psz[i], &vec[i].iov_len, NOP);
		DEBUG(0, "writev size: %lu", psz[i]);
		i++;
	}

	rwvlog->sz_arr = sz_arr;
	st_sz += size + i * sizeof(size_t);
	DEBUG(0, "sz_arr: %lu st_sz: %lu", sz_arr, st_sz);
	send_log(LOG_WRITEV, rwvlog, st_sz);
	return 0;
}

struct CopyLog
{
	unsigned long from_ino;
	unsigned long to_ino;
	unsigned long from_pos;
	unsigned long to_pos;
	unsigned long size;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_copy_file_range")
int BPF_PROG(
	vfs_copy_file_range,
	struct file *file_in,
	loff_t pos_in,
	struct file *file_out,
	loff_t pos_out,
	size_t len,
	unsigned int flags,
	long ret
)
{
#else
SEC("kprobe/vfs_copy_file_range")
int BPF_KPROBE(
	entry_vfs_copy_file_range,
	struct file *file_in,
	loff_t pos_in,
	struct file *file_out,
	loff_t pos_out,
	size_t len,
	unsigned int flags
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = file_in,
				   [1] = (void *)pos_in,
				   [2] = file_out,
				   [3] = (void *)pos_out,
				   [4] = (void *)len,
				   [5] = (void *)(size_t)flags,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_copy_file_range")
int BPF_KRETPROBE(exit_vfs_copy_file_range, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *file_in = args->argv[0];
	loff_t pos_in = (loff_t)args->argv[1];
	struct file *file_out = args->argv[2];
	loff_t pos_out = (loff_t)args->argv[3];
	size_t len = (size_t)args->argv[4];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || (g_inode != BPF_CORE_READ(file_in, f_inode) &&
					 g_inode != BPF_CORE_READ(file_out, f_inode)))
	{
		return 0;
	}

	DEBUG(0, "vfs_copy_file_range len: %lu", len);
	size_t st_sz = sizeof(struct CopyLog);
	struct CopyLog *copylog;
	copylog = send_log(LOG_NONE, NULL, st_sz);
	if (!copylog)
	{
		return 0;
	}

	copylog->from_ino = BPF_CORE_READ(file_in, f_inode, i_ino);
	copylog->to_ino = BPF_CORE_READ(file_out, f_inode, i_ino);
	copylog->from_pos = pos_in;
	copylog->to_pos = pos_out;
	copylog->size = len;
	copylog->ret = ret;

	size_t size;
	size = legacy_strncpy(copylog->action, "copy_file_range", 16);

	send_log(LOG_COPY_FILE_RANGE, copylog, st_sz + size);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);
	__type(value, struct CopyLog);
	__uint(max_entries, 1000);
} sendfileparamMap SEC(".maps");

// do_sendfile --> do_splice_direct
//             `-> splice_file_to_pipe
#if !defined(__loongarch__)
SEC("fentry/do_sendfile")
int BPF_PROG(
	do_sendfile,
	int out_fd,
	int in_fd,
	loff_t *ppos,
	size_t count,
	loff_t max
)
#else
SEC("kprobe/do_sendfile")
int BPF_KPROBE(
	do_sendfile,
	int out_fd,
	int in_fd,
	loff_t *ppos,
	size_t count,
	loff_t max
)
#endif
{
	if (!g_inode)
	{
		return 0;
	}
	long ret;
	struct CopyLog log = {};
	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&sendfileparamMap, &pid, &log, BPF_ANY);
	if (ret)
	{
		bpf_err("update map in do_sendfile: %d", ret);
	}
	return 0;
}

#if !defined(__loongarch__)
SEC("fentry/do_splice_direct")
int BPF_PROG(
	do_splice_direct,
	struct file *in,
	loff_t *ppos,
	struct file *out,
	loff_t *opos,
	size_t len,
	unsigned int flags
)
{
#else
SEC("kprobe/do_splice_direct")
int BPF_KPROBE(
	entry_do_splice_direct,
	struct file *in,
	loff_t *ppos,
	struct file *out,
	loff_t *opos,
	size_t len,
	unsigned int flags
)
{
#endif
	struct CopyLog *log;
	pid_t pid = bpf_get_current_pid_tgid();
	log = bpf_map_lookup_elem(&sendfileparamMap, &pid);
	if (!log)
	{
		return 0;
	}

	if (!g_inode || (g_inode != BPF_CORE_READ(in, f_inode) &&
					 g_inode != BPF_CORE_READ(out, f_inode)))
	{
		bpf_map_delete_elem(&sendfileparamMap, &pid);
		return 0;
	}

	DEBUG(0, "do_splice_direct len: %lu", len);
	loff_t in_pos;
	loff_t out_pos;
	bpf_read_kmem_ret(&in_pos, ppos, NOP);
	bpf_read_kmem_ret(&out_pos, opos, NOP);
	log->from_ino = BPF_CORE_READ(in, f_inode, i_ino);
	log->to_ino = BPF_CORE_READ(out, f_inode, i_ino);
	log->from_pos = in_pos;
	log->to_pos = out_pos;
	log->size = len;

	return 0;
}

#if !defined(__loongarch__)
SEC("fentry/splice_file_to_pipe")
int BPF_PROG(
	splice_file_to_pipe,
	struct file *in,
	struct pipe_inode_info *opipe,
	loff_t *offset,
	size_t len,
	unsigned int flags
)
{
#else
SEC("kprobe/splice_file_to_pipe")
int BPF_KPROBE(
	entry_splice_file_to_pipe,
	struct file *in,
	struct pipe_inode_info *opipe,
	loff_t *offset,
	size_t len,
	unsigned int flags
)
{
#endif
	struct CopyLog *log;
	pid_t pid = bpf_get_current_pid_tgid();
	log = bpf_map_lookup_elem(&sendfileparamMap, &pid);
	if (!log)
	{
		return 0;
	}

	if (!g_inode || g_inode != BPF_CORE_READ(in, f_inode))
	{
		bpf_map_delete_elem(&sendfileparamMap, &pid);
		return 0;
	}

	DEBUG(0, "splice_file_to_pipe len: %lu", len);
	loff_t in_pos;
	bpf_read_kmem_ret(&in_pos, offset, NOP);
	log->from_ino = BPF_CORE_READ(in, f_inode, i_ino);
	log->to_ino = 0;
	log->from_pos = in_pos;
	log->to_pos = 0;
	log->size = len;

	return 0;
}

// for syscall sendfile
SEC("kretprobe/do_sendfile")
int BPF_KRETPROBE(do_sendfile_exit, long ret)
{
	struct CopyLog *sendfilelog;
	pid_t pid = bpf_get_current_pid_tgid();
	sendfilelog = bpf_map_lookup_elem(&sendfileparamMap, &pid);
	if (!sendfilelog)
	{
		return 0;
	}

	size_t st_sz = sizeof(struct CopyLog);
	struct CopyLog *copylog;
	copylog = send_log(LOG_NONE, NULL, st_sz);
	if (!copylog)
	{
		goto del_exit;
	}

	*copylog = *sendfilelog;
	copylog->ret = ret;

	size_t size;
	size = legacy_strncpy(copylog->action, "splice", 16);

	send_log(LOG_SENDFILE, copylog, st_sz + size);
del_exit:
	bpf_map_delete_elem(&sendfileparamMap, &pid);
	return 0;
}

// for syscall splice
#if !defined(__loongarch__)
SEC("fexit/do_splice")
int BPF_PROG(
	do_splice,
	struct file *in,
	loff_t *off_in,
	struct file *out,
	loff_t *off_out,
	size_t len,
	unsigned int flags,
	long ret
)
{
#else
SEC("kprobe/do_splice")
int BPF_KPROBE(
	entry_do_splice,
	struct file *in,
	loff_t *off_in,
	struct file *out,
	loff_t *off_out,
	size_t len,
	unsigned int flags
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = in,
				   [1] = off_in,
				   [2] = out,
				   [3] = off_out,
				   [4] = (void *)len,
				   [5] = (void *)(size_t)flags,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/do_splice")
int BPF_KRETPROBE(exit_do_splice, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *in = args->argv[0];
	loff_t *off_in = args->argv[1];
	struct file *out = args->argv[2];
	loff_t *off_out = args->argv[3];
	size_t len = (size_t)args->argv[4];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || (g_inode != BPF_CORE_READ(in, f_inode) &&
					 g_inode != BPF_CORE_READ(out, f_inode)))
	{
		return 0;
	}

	DEBUG(0, "do_splice len: %lu", len);
	size_t st_sz = sizeof(struct CopyLog);
	struct CopyLog *copylog;
	copylog = send_log(LOG_NONE, NULL, st_sz);
	if (!copylog)
	{
		return 0;
	}

	loff_t in_pos;
	loff_t out_pos;
	bpf_read_kmem_ret(&in_pos, off_in, NOP);
	bpf_read_kmem_ret(&out_pos, off_out, NOP);
	copylog->from_ino = BPF_CORE_READ(in, f_inode, i_ino);
	copylog->to_ino = BPF_CORE_READ(out, f_inode, i_ino);
	copylog->from_pos = in_pos;
	copylog->to_pos = out_pos;
	copylog->size = len;
	copylog->ret = ret;

	size_t size;
	size = legacy_strncpy(copylog->action, "splice", 16);

	send_log(LOG_SPLICE, copylog, st_sz + size);
	return 0;
}

struct DirLog
{
	unsigned long dir_ino;
	unsigned long ino;
	umode_t mode;
	dev_t dev;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_mknod")
int BPF_PROG(
	vfs_mknod,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode,
	dev_t dev,
	int ret
)
{
#else
SEC("kprobe/vfs_mknod")
int BPF_KPROBE(
	entry_vfs_mknod,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode,
	dev_t dev
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dir,
				   [2] = dentry,
				   [3] = (void *)(size_t)mode,
				   [4] = (void *)(size_t)dev,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_mknod")
int BPF_KRETPROBE(exit_vfs_mknod, int ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct inode *dir = args->argv[1];
	struct dentry *dentry = args->argv[2];
	umode_t mode = (size_t)args->argv[3];
	dev_t dev = (size_t)args->argv[4];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != dir)
	{
		return 0;
	}

	DEBUG(
		0,
		"vfs_mknod mode: %u, dir_ino: %lu",
		mode,
		BPF_CORE_READ(dir, i_ino)
	);
	size_t st_sz = sizeof(struct DirLog);
	struct DirLog *mknodlog;
	mknodlog = send_log(LOG_NONE, NULL, st_sz);
	if (!mknodlog)
	{
		return 0;
	}

	mknodlog->dir_ino = BPF_CORE_READ(dir, i_ino);
	mknodlog->ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	mknodlog->mode = mode;
	mknodlog->dev = dev;
	mknodlog->ret = ret;
	DEBUG(0, "vfs_mknod dev: %d ret: %d", dev, ret);

	size_t size;
	size = legacy_strncpy(mknodlog->action, "mknod", 16);

	send_log(LOG_MKNOD, mknodlog, st_sz + size);
	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_mkdir")
int BPF_PROG(
	vfs_mkdir,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode,
	long ret
)
{
#else
SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(
	entry_vfs_mkdir,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dir,
				   [2] = dentry,
				   [3] = (void *)(size_t)mode,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(exit_vfs_mkdir, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct inode *dir = args->argv[1];
	struct dentry *dentry = args->argv[2];
	umode_t mode = (size_t)args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || g_inode != dir)
	{
		return 0;
	}

	DEBUG(0, "vfs_mkdir mode: %u", mode);
	size_t st_sz = sizeof(struct DirLog);
	struct DirLog *mkdirlog;
	mkdirlog = send_log(LOG_NONE, NULL, st_sz);
	if (!mkdirlog)
	{
		return 0;
	}

	mkdirlog->dir_ino = BPF_CORE_READ(dir, i_ino);
	mkdirlog->ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	mkdirlog->mode = mode;
	mkdirlog->ret = ret;

	size_t size;
	size = legacy_strncpy(mkdirlog->action, "mkdir", 16);

	send_log(LOG_MKDIR, mkdirlog, st_sz + size);
	return 0;
}

#if !defined(__loongarch__)
SEC("fentry/vfs_rmdir")
int BPF_PROG(
	vfs_rmdir,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry
)
{
#else
SEC("kprobe/vfs_rmdir")
int BPF_KPROBE(
	entry_vfs_rmdir,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry
)
{
#endif
	if (!g_inode ||
		(g_inode != dir && g_inode != BPF_CORE_READ(dentry, d_inode)))
	{
		return 0;
	}

	size_t st_sz = sizeof(struct DirLog);
	struct DirLog *rmdirlog;
	rmdirlog = send_log(LOG_NONE, NULL, st_sz);
	if (!rmdirlog)
	{
		return 0;
	}

	rmdirlog->dir_ino = BPF_CORE_READ(dir, i_ino);
	rmdirlog->ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	DEBUG(
		0,
		"vfs_rmdir dir_ino: %lu parent_ino: %lu",
		BPF_CORE_READ(dir, i_ino),
		rmdirlog->ino
	);

	return 0;
}

#if !defined(__loongarch__)
SEC("fexit/vfs_rmdir")
int BPF_PROG(
	vfs_rmdir_exit,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	long ret
)
{
#else
SEC("kretprobe/vfs_rmdir")
int BPF_KRETPROBE(exit_vfs_rmdir, long ret)
{
#endif
	struct DirLog *rmdirlog;
	rmdirlog = lookup_log();
	if (!rmdirlog)
	{
		return 0;
	}

	rmdirlog->ret = ret;
	size_t st_sz = sizeof(struct DirLog);
	size_t size;
	size = legacy_strncpy(rmdirlog->action, "rmdir", 16);
	send_log(LOG_RMDIR, rmdirlog, st_sz + size);
	return 0;
}

struct SymLinkLog
{
	unsigned long dir_ino;
	unsigned long ino; // new inode linked to old name
	unsigned int oldname;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_symlink")
int BPF_PROG(
	vfs_symlink,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	const char *oldname,
	long ret
)
{
#else
SEC("kprobe/vfs_symlink")
int BPF_KPROBE(
	entry_vfs_symlink,
	struct mnt_idmap *idmap,
	struct inode *dir,
	struct dentry *dentry,
	const char *oldname
)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = idmap,
				   [1] = dir,
				   [2] = dentry,
				   [3] = (void *)oldname,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_symlink")
int BPF_KRETPROBE(exit_vfs_symlink, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct inode *dir = args->argv[1];
	struct dentry *dentry = args->argv[2];
	const char *oldname = args->argv[3];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode ||
		(g_inode != dir && g_inode != BPF_CORE_READ(dentry, d_inode)))
	{
		return 0;
	}

	DEBUG(0, "vfs_symlink oldname: %s", oldname);
	size_t st_sz = sizeof(struct SymLinkLog);
	struct SymLinkLog *symlinklog;
	symlinklog = send_log(LOG_NONE, NULL, st_sz);
	if (!symlinklog)
	{
		return 0;
	}

	symlinklog->dir_ino = BPF_CORE_READ(dir, i_ino);
	symlinklog->ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	symlinklog->ret = ret;

	size_t size;
	u32 oldname_off;
	size = legacy_strncpy(symlinklog->action, "symlink", 16);
	oldname_off = size;

	size = bpf_read_kstr_ret(
		symlinklog->action + oldname_off,
		PAGE_SIZE - sizeof(struct BpfData) - sizeof(*symlinklog) - 16,
		oldname,
		NOP
	);

	symlinklog->oldname = oldname_off;

	send_log(LOG_SYMLINK, symlinklog, st_sz + size);
	return 0;
}

struct SeekLog
{
	unsigned long i_ino;
	loff_t offset;
	int whence;
	long ret;
	char action[];
} __attribute__((__packed__));

#if !defined(__loongarch__)
SEC("fexit/vfs_llseek")
int BPF_PROG(vfs_llseek, struct file *file, loff_t offset, int whence, long ret)
{
#else
SEC("kprobe/vfs_llseek")
int BPF_KPROBE(entry_vfs_llseek, struct file *file, loff_t offset, int whence)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs args = {
		.argv =
			{
				   [0] = file,
				   [1] = (void *)offset,
				   [2] = (void *)(size_t)whence,
				   }
	};

	int ret = bpf_map_update_elem(&funcargsMap, &pid, &args, BPF_ANY);

	if (ret)
	{
		bpf_printk("update args map failed: %d", ret);
	}

	return 0;
}

SEC("kretprobe/vfs_llseek")
int BPF_KRETPROBE(exit_vfs_llseek, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid();

	struct FuncArgs *args = bpf_map_lookup_elem(&funcargsMap, &pid);
	if (!args)
	{
		return 0;
	}

	struct file *file = args->argv[0];
	loff_t offset = (size_t)args->argv[1];
	int whence = (size_t)args->argv[2];

	bpf_map_delete_elem(&funcargsMap, &pid);
#endif
	if (!g_inode || BPF_CORE_READ(file, f_inode) != g_inode)
	{
		return 0;
	}

	DEBUG(0, "vfs_llseek offset: %s", offset);
	size_t st_sz = sizeof(struct SeekLog);
	struct SeekLog *seeklog;
	seeklog = send_log(LOG_NONE, NULL, st_sz);
	if (!seeklog)
	{
		return 0;
	}

	seeklog->i_ino = BPF_CORE_READ(file, f_inode, i_ino);
	seeklog->offset = offset;
	seeklog->whence = whence;
	seeklog->ret = ret;

	size_t size;
	size = legacy_strncpy(seeklog->action, "lseek", 16);

	send_log(LOG_LSEEK, seeklog, st_sz + size);
	return 0;
}

// TODO mount