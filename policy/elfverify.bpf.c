/**
 * @file elfverify.bpf.c
 * @brief ELF可执行文件验证eBPF内核态程序
 *
 * 该程序实现了基于LSM(Linux Security Module)的可执行文件访问控制。
 * 通过hook mmap和execve相关的系统调用，根据预设的白名单策略来控制用户
 * 对特定可执行文件的访问权限。程序支持基于文件路径和用户ID的访问控制。
 *
 * 主要功能：
 * - 拦截可执行文件的内存映射操作
 * - 拦截程序执行权限检查
 * - 基于白名单的访问控制机制
 * - 实时日志记录和事件上报
 * - 支持目录级别的递归权限继承
 *
 * @version 1.0
 * @license GPL
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "Ktask.h"
#include "Kmem.h"
#include "Kstr-utils.h"
#include <errno.h>
#include "jhash.h"

/** @brief eBPF程序许可证声明，必须为GPL兼容 */
char _license[] SEC("license") = "GPL";

/** @brief 内存映射执行权限标志 */
#define PROT_EXEC 0x4
/** @brief 私有内存映射标志 */
#define MAP_PRIVATE 0x02
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
 * 定义了一条访问控制规则，支持两种类型：基于文件目标的规则和基于用户ID的规则。
 * 使用union结构来节省内存空间，两种规则类型互斥。
 */
struct Rule
{
	union
	{
		struct Target target; /**< 文件目标标识 */
		struct
		{
			int not_uid; /**< 标志位，0表示使用用户ID规则 */
			uid_t uid;	 /**< 用户ID */
		};
	};
};

/**
 * @brief eBPF程序日志数据结构
 *
 * 用于通过ring buffer向用户空间传递违规访问的日志信息。
 */
struct BpfData
{
	uid_t uid;	   /**< 违规用户的ID */
	pid_t pid;	   /**< 违规进程的PID */
	int is_binary; /**< 标志位，1表示二进制文件，0表示脚本文件 */
	struct Target target; /**< 目标文件标识 */
};

/**
 * @brief 白名单规则映射
 *
 * 存储从用户空间加载的白名单访问控制规则，内核态程序使用这些规则
 * 来判断特定的可执行文件访问是否应该被允许。支持大量规则条目。
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH); /**< 哈希表类型映射 */
	__type(key, u32);				 /**< 键类型：规则ID */
	__type(value, struct Rule);		 /**< 值类型：访问控制规则 */
	__uint(max_entries, 400000);	 /**< 最大条目数：40万 */
} whitelist SEC(".maps");

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
 * 当检测到违规的可执行文件访问行为时，将相关信息封装成日志事件
 * 并通过ring buffer发送到用户空间。
 *
 * @param uid 违规用户的ID
 * @param pid 违规进程的PID
 * @param is_binary 文件类型标志，1表示二进制文件，0表示脚本文件
 * @param target 被访问的目标文件信息
 */
static void
audit_log(uid_t uid, pid_t pid, int is_binary, struct Target *target)
{
	struct BpfData log;
	log.uid = uid;
	log.pid = pid;
	log.is_binary = is_binary;
	log.target = *target;
	long ret = bpf_ringbuf_output(&logs, &log, sizeof(log), 0);
	if (ret)
	{
		bpf_printk("error: bpf_perf_event_output: %ld", ret);
	}
}

/**
 * @brief 事件处理上下文结构
 *
 * 用于在规则匹配回调函数中传递事件相关信息和匹配结果。
 */
struct Event
{
	bool allow;			   /**< 匹配结果，true表示允许访问 */
	uid_t uid;			   /**< 用户ID */
	struct Target *target; /**< 目标文件信息 */
};

/**
 * @brief 规则匹配回调函数
 *
 * 对whitelist映射中的每条规则进行匹配检查，判断当前可执行文件访问
 * 是否匹配任何已配置的白名单规则。支持基于用户ID和文件目标的匹配。
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
	struct Event *event = ctx;
	struct Rule *rule = value;

	if (!rule->not_uid && rule->uid == event->uid)
	{
		event->allow = true;
		return 1;
	}
	if (rule->target.dev == event->target->dev &&
		rule->target.ino == event->target->ino)
	{
		event->allow = true;
		return 1;
	}
	return 0;
}

/**
 * @brief 规则过滤器主函数
 *
 * 检查指定的可执行文件访问是否被白名单规则所允许。
 * 遍历所有白名单规则并进行匹配。
 *
 * @param target 目标文件信息
 * @param uid 用户ID
 * @return true表示访问被允许，false表示访问被拒绝
 */
static bool rules_filter(struct Target *target, uid_t uid)
{
	struct Event event = {
		.allow = false,
		.target = target,
		.uid = uid,
	};
	bpf_for_each_map_elem(&whitelist, match_callback, &event, 0);
	return event.allow;
}

/**
 * @brief 权限检查核心函数
 *
 * 对指定的可执行文件进行访问权限检查。采用二级检查机制：
 * 首先检查文件本身，然后检查其父目录。如果违反规则则记录日志并返回拒绝访问。
 *
 * @param d 目录项指针
 * @param is_binary 文件类型标志，1表示二进制文件，0表示脚本文件
 * @return 0表示允许访问，-EACCES表示拒绝访问
 */
static int check_permission(const struct dentry *d, int is_binary)
{
	struct Target target = {
		.dev = d->d_sb->s_dev,
		.ino = d->d_inode->i_ino,
	};
	struct Target parent_target = {
		.dev = d->d_parent->d_sb->s_dev,
		.ino = d->d_parent->d_inode->i_ino,
	};
	uid_t uid = bpf_get_current_uid_gid() & 0xffffffff;
	pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;

	if (rules_filter(&target, uid))
	{
		return 0;
	}
	if (rules_filter(&parent_target, uid))
	{
		return 0;
	}

	audit_log(uid, pid, is_binary, &target);
	return -EACCES;
}

/**
 * @brief 文件内存映射LSM hook
 *
 * 拦截文件内存映射操作，检查具有执行权限的私有映射。
 * 这类映射通常用于加载和执行可执行文件。
 *
 * @param file 文件结构指针
 * @param reqprot 请求的保护标志
 * @param prot 实际的保护标志
 * @param flags 映射标志
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/mmap_file")
int BPF_PROG(
	mmap_file,
	struct file *file,
	unsigned long reqprot,
	unsigned long prot,
	unsigned long flags,
	int ret
)
{
	if (ret)
	{
		return ret;
	}
	if (file && (prot & PROT_EXEC) && (flags & MAP_PRIVATE))
	{
		return check_permission(file->f_path.dentry, 1);
	}
	else
	{
		return 0;
	}
}

/**
 * @brief 程序执行凭据检查LSM hook
 *
 * 在程序执行过程中检查执行凭据时调用，用于验证可执行文件的合法性。
 *
 * @param bprm 二进制程序参数结构
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm, int ret)
{
	if (ret)
	{
		return ret;
	}
	if (bprm && bprm->file)
	{
		return check_permission(bprm->file->f_path.dentry, 0);
	}
	else
	{
		return 0;
	}
}

/**
 * @brief 程序执行安全检查LSM hook
 *
 * 在程序执行前进行安全检查，验证可执行文件是否允许执行。
 * 这是程序执行过程中的最后一道安全检查。
 *
 * @param bprm 二进制程序参数结构
 * @param ret 前一个LSM的返回值
 * @return 0表示允许，负值表示拒绝
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm, int ret)
{
	if (ret)
	{
		return ret;
	}
	if (bprm && bprm->file)
	{
		return check_permission(bprm->file->f_path.dentry, 0);
	}
	else
	{
		return 0;
	}
}
