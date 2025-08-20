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

struct Rule
{
	uuid_t dev_uuid;
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

	char *uuid = (char *)&dir->mnt->mnt_sb->s_uuid;

	if (0)
	{
		__attribute__((aligned(8))) char tmp[16];
		memcpy(tmp, uuid, sizeof(tmp));
		byte_reverse(tmp, sizeof(tmp));
		DEBUG(
			1,
			"UUID: %04x-%02x-%02x-%02x-%02x%04x",
			*(u32 *)(tmp + 12),
			*(u16 *)(tmp + 10),
			*(u16 *)(tmp + 8),
			*(u16 *)(tmp + 6),
			*(u16 *)(tmp + 4),
			*(u32 *)tmp
		);
	}

	__attribute__((aligned(8))) char zero_uuid[16] = {0};
	if (memncmp(&rule->dev_uuid, zero_uuid, sizeof(uuid_t)) &&
		memncmp(&rule->dev_uuid, uuid, sizeof(uuid_t)))
	{
		return 0;
	}

	if (rule->inode && rule->inode != dentry->d_inode->i_ino)
	{
		return 0;
	}

	return -EBUSY;
}

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