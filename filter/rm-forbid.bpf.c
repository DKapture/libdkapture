/**
 * @file rm-forbid.bpf.c
 * @brief 文件删除保护 eBPF 程序
 * 
 * 该文件实现了基于 eBPF 的文件删除保护功能，通过监控
 * 文件系统操作来防止指定文件被删除。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <asm-generic/errno-base.h>

#include "Kcom.h"
#include "Kstr-utils.h"
#include "Kmem.h"
#include "endian.h"

char _license[] SEC("license") = "GPL";

/// 添加设备号转换宏定义，参考frtp
#define MAJOR(dev) (u32)((dev & 0xfff00000) >> 20)
#define MINOR(dev) (u32)(dev & 0xfffff)

struct Rule
{
	dev_t dev; // 设备号
	u64 inode;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, 1);
} filter SEC(".maps");

static int unlink_check(struct path *dir, struct dentry *dentry)
{
	filter_debug_proc(0, "test");

	if (dentry->d_lockref.count <= 1)
	{
		return 0;
	}

	if (0) // switch to 1 to enable debug
	{
		pid_t pid;
		char comm[16] = {0};
		pid = bpf_get_current_pid_tgid();
		bpf_get_current_comm(comm, sizeof(comm));
		bpf_info("file(path) busy: %d %s", pid, comm);
	}

	struct Rule *rule;
	u32 rkey = 0;
	rule = bpf_map_lookup_elem(&filter, &rkey);
	if (!rule)
	{ // no filter
		return -EBUSY;
	}

	/// 获取文件系统的设备号
	dev_t fs_dev = dir->mnt->mnt_sb->s_dev;

	if (0) // switch to 1 to enable debug
	{
		bpf_info("FS dev: major=%u, minor=%u", MAJOR(fs_dev), MINOR(fs_dev));
	}

	/// 检查设备号是否匹配
	if (rule->dev && rule->dev != fs_dev)
	{
		return 0;
	}

	if (rule->inode && rule->inode != dentry->d_inode->i_ino)
	{
		return 0;
	}

	return -EBUSY;
}

/**
 * @brief LSM路径删除钩子函数
 * 在文件删除时被调用，检查是否允许删除操作
 * @param dir 目录路径
 * @param dentry 目录项
 * @param ret 前一个钩子的返回值
 * @return 0允许删除，非0拒绝删除
 */
SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, struct path *dir, struct dentry *dentry, int ret)
{
	if (ret)
	{
		DEBUG(
			0,
			"rm-forbid %s early return for previous bpf-lsm programs",
			__func__
		);
		return ret;
	}

	return unlink_check(dir, dentry);
}

/**
 * @brief LSM路径删除目录钩子函数
 * 在目录删除时被调用，检查是否允许删除操作
 * @param dir 目录路径
 * @param dentry 目录项
 * @param ret 前一个钩子的返回值
 * @return 0允许删除，非0拒绝删除
 */
SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, struct path *dir, struct dentry *dentry, int ret)
{
	if (ret)
	{
		DEBUG(
			0,
			"rm-forbid %s early return for previous bpf-lsm programs",
			__func__
		);
		return ret;
	}

	return unlink_check(dir, dentry);
}