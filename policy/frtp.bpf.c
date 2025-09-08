/**
 * @file frtp.bpf.c
 * @brief 文件系统实时保护(File Real-Time Protection) eBPF内核态程序
 *
 * 该程序实现了基于LSM(Linux Security Module)的文件系统访问控制。
 * 通过hook各种文件操作系统调用，根据预设的规则策略来控制进程对
 * 特定文件的访问权限，并记录违规访问行为。
 *
 * 主要功能：
 * - 拦截文件打开、截断、删除、创建等操作
 * - 基于进程路径或PID的细粒度访问控制
 * - 实时日志记录和事件上报
 * - 支持目录级别的递归权限控制
 *
 * @version 1.0
 * @license GPL
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "Ktask.h"
#include "Kcom.h"
#include "Kmem.h"
#include "Kstr-utils.h"
#include <errno.h>
#include "jhash.h"

/** @brief 调试输出开关，1启用调试信息，0禁用 */
#define DEBUG_OUTPUT 0

/** @brief eBPF程序许可证声明，必须为GPL兼容 */
char _license[] SEC("license") = "GPL";

/** @brief 操作类型定义，用于表示文件访问模式 */
typedef u32 Action;

/** @brief 文件读取模式标志 */
#define FMODE_READ ((fmode_t)0x1)
/** @brief 文件写入模式标志 */
#define FMODE_WRITE ((fmode_t)0x2)
/** @brief 文件执行模式标志 */
#define FMODE_EXEC ((fmode_t)0x20)

/** @brief 从设备号中提取主设备号 */
#define MAJOR(dev) (u32)((dev & 0xfff00000) >> 20)
/** @brief 从设备号中提取次设备号 */
#define MINOR(dev) (u32)(dev & 0xfffff)

/**
 * @brief 目标文件标识结构
 *
 * 用于唯一标识文件系统中的一个文件，通过设备号和inode号组合。
 */
struct Target
{
	dev_t dev; /**< 设备号 */
	ino_t ino; /**< inode号 */
};

/**
 * @brief 访问控制规则结构
 *
 * 定义了一条访问控制规则，包含进程标识、操作类型和目标文件。
 * 支持两种进程标识方式：具体PID或进程路径模式匹配。
 */
struct Rule
{
	union
	{
		struct
		{
			u32 not_pid; /**< 标志位，0表示使用PID，1表示使用进程路径 */
			pid_t pid; /**< 进程ID */
		};
		char process[4096]; /**< 进程路径字符串 */
	};
	Action act;			  /**< 禁止的操作类型 */
	struct Target target; /**< 目标文件标识 */
};

/**
 * @brief eBPF程序日志数据结构
 *
 * 用于通过ring buffer向用户空间传递违规访问的日志信息。
 */
struct BpfData
{
	Action act;		/**< 违规的操作类型 */
	pid_t pid;		/**< 违规进程的PID */
	char process[]; /**< 变长字段，包含进程路径和目标文件信息 */
};

/**
 * @brief 访问控制规则映射
 *
 * 存储从用户空间加载的访问控制规则，内核态程序使用这些规则
 * 来判断特定的文件访问是否应该被允许。
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH); /**< 哈希表类型映射 */
	__type(key, u32);				 /**< 键类型：规则ID */
	__type(value, struct Rule);		 /**< 值类型：访问控制规则 */
	__uint(max_entries, 1000);		 /**< 最大条目数 */
} filter SEC(".maps");

/**
 * @brief 进程ID到路径映射
 *
 * 缓存进程ID与其可执行文件路径的映射关系，用于基于进程路径
 * 的访问控制规则匹配。使用LRU策略自动淘汰旧条目。
 */
struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH); /**< LRU哈希表类型 */
	__type(key, pid_t);					 /**< 键类型：进程ID */
	__type(value, char[4096]); /**< 值类型：进程路径字符串 */
	__uint(max_entries, 1024); /**< 最大条目数 */
} pid2path SEC(".maps");

/**
 * @brief 日志事件环形缓冲区
 *
 * 用于向用户空间传递违规访问事件的日志信息。
 * 采用ring buffer机制实现高效的内核到用户空间数据传输。
 */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF); /**< 环形缓冲区类型 */
	__uint(max_entries, 1024 * 1024);	/**< 缓冲区大小：1MB */
} logs SEC(".maps");

/**
 * @brief 记录违规访问审计日志
 *
 * 当检测到违规的文件访问行为时，将相关信息封装成日志事件
 * 并通过ring buffer发送到用户空间。
 *
 * @param pid 违规进程的PID
 * @param process 违规进程的路径
 * @param target 被访问的目标文件信息
 * @param act 违规的操作类型
 */
static void audit_log(
	pid_t pid,
	const char *process,
	const struct Target *target,
	Action act
)
{
	long ret;
	u32 log_bsz;
	u32 log_sz;
	u32 mkey = __LINE__;
	struct BpfData *log = (typeof(log))malloc_page(mkey);
	if (!log)
	{
		bpf_printk("log buffer full");
		return;
	}

	log->pid = pid;
	log->act = act & 0XFF;
	log_bsz = 4096 - sizeof(log);
	log_sz = sizeof(log);

	ret = bpf_snprintf(log->process, log_bsz / 2, "%s", (u64 *)&process, 8);
	if (ret < 0)
	{
		bpf_printk("error: bpf_snprintf: %ld", ret);
		goto exit;
	}

	if (ret > log_bsz / 2)
	{
		ret = log_bsz / 2;
	}

	log_sz += ret;
	u64 data[] = {
		MAJOR(target->dev),
		MINOR(target->dev),
		target->ino,
	};
	ret = bpf_snprintf(
		log->process + ret,
		log_bsz / 2,
		"%u,%u %lu",
		data,
		sizeof(data)
	);
	if (ret < 0)
	{
		bpf_printk("error: bpf_snprintf: %ld", ret);
		goto exit;
	}

	if (ret > log_bsz / 2)
	{
		ret = log_bsz / 2;
	}

	log_sz += ret;

	ret = bpf_ringbuf_output(&logs, log, log_sz, 0);
	if (ret)
	{
		bpf_printk("error: bpf_perf_event_output: %ld", ret);
	}

exit:
	if (log)
	{
		free_page(mkey);
	}
}

/**
 * @brief 事件处理上下文结构
 *
 * 用于在规则匹配回调函数中传递事件相关信息。
 */
struct Event
{
	const char *proc_path;		 /**< 进程路径 */
	const struct Target *target; /**< 目标文件信息 */
	int act;					 /**< 操作类型 */
};

/**
 * @brief 规则匹配回调函数
 *
 * 对filter映射中的每条规则进行匹配检查，判断当前文件访问
 * 是否违反了任何已配置的访问控制规则。
 *
 * @param map BPF映射指针
 * @param key 映射键指针
 * @param value 映射值指针（Rule结构）
 * @param ctx 回调上下文（Event结构）
 * @return 匹配成功返回1，继续匹配返回0
 */
static long
match_callback(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	const char *proc_path;
	dev_t dev;
	ino_t ino;
	int act;

	struct Event *event = ctx;
	struct Rule *rule = value;

	proc_path = event->proc_path;
	dev = event->target->dev;
	ino = event->target->ino;
	act = event->act;

	if (rule->not_pid)
	{
		if (!proc_path)
		{
			return 0;
		}
		// Check if process path matches
		if (wildcard_match(rule->process, proc_path, 4096))
		{
			return 0;
		}
	}
	else
	{
		pid_t pid = bpf_get_current_pid_tgid();
		if (rule->pid != pid)
		{
			return 0;
		}
	}

	if (DEBUG_OUTPUT)
	{
		bpf_printk("proc fit: %s %d", proc_path, act);
	}

	// Check if file matches
	if (rule->target.ino != ino || rule->target.dev != dev)
	{
		return 0;
	}

	if (DEBUG_OUTPUT)
	{
		bpf_printk("target fit: %s %lu %lu %d", proc_path, dev, ino, act);
	}
	// Check if act is a subset of rule->act
	if (act & rule->act)
	{
		event->act = 0;
	}

	return 1;
}

/**
 * @brief 规则过滤器主函数
 *
 * 检查指定的文件访问是否被访问控制规则所禁止。
 * 遍历所有规则并进行匹配。
 *
 * @param proc_path 进程路径
 * @param target 目标文件信息
 * @param act 操作类型
 * @return true表示访问被允许，false表示访问被禁止
 */
static bool
rules_filter(const char *proc_path, const struct Target *target, int act)
{
	struct Event event = {.act = act, .proc_path = proc_path, .target = target};

	bpf_for_each_map_elem(&filter, match_callback, &event, 0);

	return !!event.act;
}

/**
 * @brief 权限检查核心实现
 *
 * 对指定目标文件的访问权限进行检查，如果违反规则则记录日志
 * 并返回拒绝访问的错误码。
 *
 * @param target 目标文件信息
 * @param mode 访问模式
 * @return 0表示允许访问，-EACCES表示拒绝访问
 */
static int _permission_check(const struct Target *target, fmode_t mode)
{
	pid_t pid;
	char *proc_path = NULL;
	long ret = 0;

	pid = bpf_get_current_pid_tgid();

	proc_path = bpf_map_lookup_elem(&pid2path, &pid);

	if (!rules_filter(proc_path, target, mode))
	{
		if (proc_path)
		{
			audit_log(pid, proc_path, target, mode);
		}
		else
		{
			char comm[16];
			ret = bpf_get_current_comm(comm, sizeof(comm));
			if (ret)
			{
				bpf_printk("fail to get current comm: %ld", ret);
			}
			else
			{
				audit_log(pid, comm, target, mode);
			}
		}

		if (DEBUG_OUTPUT)
		{
			bpf_printk(
				"permission denied: %lu %lu %d",
				target->dev,
				target->ino,
				mode
			);
		}
		ret = -EACCES;
	}

	return ret;
}

/**
 * @brief 权限检查入口函数
 *
 * 对文件及其父目录进行权限检查。这是一个二级检查机制，
 * 既检查目标文件本身，也检查其父目录的访问权限。
 *
 * @param dentry 目录项指针
 * @param mode 访问模式
 * @return 0表示允许访问，负值表示拒绝访问
 */
static int permission_check(struct dentry *dentry, fmode_t mode)
{
	struct Target target = {
		.ino = dentry->d_inode->i_ino,
		.dev = dentry->d_inode->i_sb->s_dev,
	};
	int ret = _permission_check(&target, mode);
	if (ret)
	{
		return ret;
	}
	target.ino = dentry->d_parent->d_inode->i_ino;
	target.dev = dentry->d_parent->d_inode->i_sb->s_dev;
	return _permission_check(&target, mode);
}

/**
 * @brief 文件打开LSM hook
 *
 * 拦截文件打开操作，根据访问控制规则决定是否允许打开文件。
 *
 * @param file 文件结构指针
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file, int ret)
{
	if (ret)
	{
		return ret;
	}

	return permission_check(file->f_path.dentry, file->f_mode);
}

/**
 * @brief 文件截断LSM hook
 *
 * 拦截文件截断操作，检查是否有写入权限。
 *
 * @param file 文件结构指针
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/file_truncate")
int BPF_PROG(file_truncate, struct file *file, int ret)
{
	if (ret)
	{
		return ret;
	}

	return permission_check(file->f_path.dentry, FMODE_WRITE);
}

/**
 * @brief 文件删除LSM hook
 *
 * 拦截文件删除操作，检查对父目录是否有写入权限。
 *
 * @param dir 父目录路径
 * @param dentry 要删除的文件目录项
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/path_unlink")
int BPF_PROG(
	path_unlink,
	const struct path *dir,
	struct dentry *dentry,
	int ret
)
{
	if (ret)
	{
		return ret;
	}

	return permission_check(dir->dentry, FMODE_WRITE);
}

/**
 * @brief 目录创建LSM hook
 *
 * 拦截目录创建操作，检查对父目录是否有写入权限。
 *
 * @param dir 父目录路径
 * @param dentry 要创建的目录项
 * @param mode 创建模式
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/path_mkdir")
int BPF_PROG(
	path_mkdir,
	const struct path *dir,
	struct dentry *dentry,
	umode_t mode,
	int ret
)
{
	if (ret)
	{
		return ret;
	}

	return permission_check(dir->dentry, FMODE_WRITE);
}

/**
 * @brief 目录删除LSM hook
 *
 * 拦截目录删除操作，检查对父目录是否有写入权限。
 *
 * @param dir 父目录路径
 * @param dentry 要删除的目录项
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *dentry, int ret)
{
	if (ret)
	{
		return ret;
	}

	return permission_check(dir->dentry, FMODE_WRITE);
}

/**
 * @brief 特殊文件创建LSM hook
 *
 * 拦截特殊文件（设备文件、管道等）创建操作，检查对父目录是否有写入权限。
 *
 * @param dir 父目录路径
 * @param dentry 要创建的目录项
 * @param mode 创建模式
 * @param dev 设备号（仅设备文件）
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/path_mknod")
int BPF_PROG(
	path_mknod,
	const struct path *dir,
	struct dentry *dentry,
	umode_t mode,
	unsigned int dev,
	int ret
)
{
	if (ret)
	{
		return ret;
	}

	return permission_check(dir->dentry, FMODE_WRITE);
}

/**
 * @brief PID到路径映射过滤回调
 *
 * 检查给定的文件路径是否匹配任何基于进程路径的规则，
 * 用于决定是否需要缓存该进程的路径信息。
 *
 * @param map BPF映射指针
 * @param key 映射键指针
 * @param value 映射值指针
 * @param ctx 回调上下文（文件路径指针）
 * @return 匹配成功返回1，继续匹配返回0
 */
static long
pid2path_callback(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	char *filepath = *(char **)ctx;
	struct Rule *rule = value;

	if (!rule)
	{
		filepath[4095] = 0;
		return 0;
	}

	if (!rule->not_pid)
	{
		filepath[4095] = 0;
		return 0;
	}

	if (wildcard_match(rule->process, filepath, 4096))
	{
		filepath[4095] = 0;
		return 0;
	}

	filepath[4095] = 1;
	return 1;
}

/**
 * @brief PID到路径映射过滤器
 *
 * 检查指定的文件路径是否需要被添加到PID到路径的映射中。
 * 只有匹配某些规则的进程路径才会被缓存。
 *
 * @param file_path 文件路径
 * @return true表示需要缓存，false表示不需要缓存
 */
static bool pid2path_filter(char *file_path)
{
	bpf_for_each_map_elem(&filter, pid2path_callback, &file_path, 0);

	bool ret = !!file_path[4095];
	file_path[4095] = 0; // use last byte as flag
	return ret;
}

/**
 * @brief 线程退出检查回调
 *
 * 检查是否存在任何基于进程路径的规则，用于决定是否需要
 * 在线程退出时清理PID到路径的映射。
 *
 * @param map BPF映射指针
 * @param key 映射键指针
 * @param value 映射值指针
 * @param ctx 回调上下文（布尔返回值指针）
 * @return 找到进程路径规则返回1，否则返回0
 */
static long thead_exit_callback(
	struct bpf_map *map,
	const void *key,
	void *value,
	void *ctx
)
{
	struct Rule *rule = value;
	bool *ret = ctx;

	if (!rule)
	{
		*ret = false;
		return 0;
	}

	if (!rule->not_pid)
	{
		*ret = false;
		return 0;
	}

	*ret = true;
	return 1;
}

/**
 * @brief 线程退出过滤器
 *
 * 检查是否需要在线程退出时进行清理操作。
 * 只有当存在基于进程路径的规则时才需要清理。
 *
 * @return true表示需要清理，false表示不需要清理
 */
static bool thread_exit_filter(void)
{
	bool ret = false;
	bpf_for_each_map_elem(&filter, thead_exit_callback, &ret, 0);

	return ret;
}

/**
 * @brief 程序执行追踪hook
 *
 * 在程序执行时建立PID到可执行文件路径的映射关系。
 * 这个映射用于支持基于进程路径的访问控制规则。
 *
 * @param bprm 二进制程序参数结构
 * @param fd 文件描述符
 * @param filename 文件名结构
 * @param flags 标志位
 * @return 总是返回0
 */
SEC("fexit/bprm_execve")
int BPF_PROG(
	bprm_execve,
	struct linux_binprm *bprm,
	int fd,
	struct filename *filename,
	int flags
)
{
	long ret = 0;
	pid_t pid;
	char *filepath;

	u32 mkey = __LINE__;
	filepath = malloc_page(mkey);
	if (!filepath)
	{
		bpf_printk("error: malloc_page");
		return 0;
	}

	ret = bpf_probe_read_kernel(filepath, 4096, filename->iname);
	if (ret < 0)
	{
		bpf_printk("error: bpf_probe_read_kernel_str: %ld", ret);
		goto exit;
	}

	if (!pid2path_filter(filepath))
	{
		goto exit;
	}

	pid = bpf_get_current_pid_tgid();

	if (DEBUG_OUTPUT)
	{
		bpf_printk("pid2hash: %s pid: %d", filepath, pid);
	}
	ret = bpf_map_update_elem(&pid2path, &pid, filepath, BPF_ANY);
	if (ret)
	{
		bpf_printk("error: bpf_map_update_elem: %ld", ret);
		goto exit;
	}

exit:
	if (filepath)
	{
		free_page(mkey);
	}
	return 0;
}

/**
 * @brief 线程退出追踪hook
 *
 * 在线程退出时清理PID到路径映射中的相应条目，
 * 避免映射表中的陈旧条目。
 *
 * @param tsk 任务结构指针
 * @return 总是返回0
 */
SEC("fentry/exit_thread")
int BPF_PROG(exit_thread, struct task_struct *tsk)
{
	long ret = 0;
	pid_t pid;

	if (!thread_exit_filter())
	{
		return 0;
	}

	pid = bpf_get_current_pid_tgid();
	ret = bpf_map_delete_elem(&pid2path, &pid);
	if (ret && ret != -ENOENT)
	{
		bpf_printk("error: bpf_map_delete_elem: %ld", ret);
	}

	return 0;
}
