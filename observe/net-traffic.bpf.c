#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "jhash.h"
#include "Kstr-utils.h"
#include "Kmem.h"
#include "Ktask.h"
#include "net.h"
#include "Kcom.h"

#define PF_INET 2
#define TRAFFIC_IN -1
#define TRAFFIC_OUT 1

char _license[] SEC("license") = "GPL";

struct BpfData
{
	pid_t pid;
	u32 traffic;
	u32 remote_ip;
	u16 remote_port;
	short dir;
	char comm[];
};

struct Rule
{
	u32 remote_ip;
	u16 remote_port;
	u16 dir;
	union
	{
		struct
		{
			u32 not_pid;
			pid_t pid;
		};
		char comm[16];
	};
};

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024); // 1 MB
} logs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, 1000);
} filter SEC(".maps");

struct CbCtx
{
	struct BpfData *log;
	int ret;
};

static long rule_filter_callback(
	struct bpf_map *map,
	const void *key,
	void *value,
	void *ctx
)
{
	struct CbCtx *cb = ctx;
	struct Rule *rule = value;
	struct BpfData *log = cb->log;
	cb->ret = 0;

	if (rule->not_pid)
	{
		if (rule->comm[0] && strncmp(rule->comm, log->comm, 16))
		{
			return 0;
		}
	}
	else
	{
		if (rule->pid != -1 && rule->pid != log->pid)
		{
			return 0;
		}
	}

	if (rule->remote_ip && rule->remote_ip != log->remote_ip)
	{
		return 0;
	}

	if (rule->remote_port && rule->remote_port != log->remote_port)
	{
		return 0;
	}

	if (rule->dir && rule->dir != log->dir)
	{
		return 0;
	}

	cb->ret = 1;
	return 1;
}

static int rule_filter(struct BpfData *log)
{
	long ret = 0;
	struct CbCtx ctx = {
		.log = log,
		.ret = 1,
	};
	ret = bpf_for_each_map_elem(&filter, rule_filter_callback, &ctx, 0);
	if (ret < 0)
	{
		bpf_printk("error: bpf_for_each_map_elem: %ld", ret);
		return 0;
	}
	return ctx.ret;
}

static int traffic_stat(struct socket *sock, int ret, int dir)
{
	struct BpfData *log;
	u32 dst_addr;
	u32 src_addr;
	char comm[16];
	u32 traffic = ret;
	if (ret < 0)
	{
		return 0;
	}

	struct sock *sk;
	bpf_read_kmem_ret(&sk, &sock->sk, return 0);
	if (!sk)
	{
		return 0;
	}

	u16 pf;
	bpf_read_kmem_ret(&pf, &sk->__sk_common.skc_family, return 0);

	if (pf != PF_INET)
	{
		return 0;
	}

	u32 skc_daddr;
	u32 skc_rcv_saddr;
	u16 skc_dport;

	bpf_read_kmem_ret(&skc_daddr, &sk->__sk_common.skc_daddr, return 0);

	bpf_read_kmem_ret(&skc_rcv_saddr, &sk->__sk_common.skc_rcv_saddr, return 0);

	bpf_read_kmem_ret(&skc_dport, &sk->__sk_common.skc_dport, return 0);

	dst_addr = bpf_ntohl(skc_daddr);
	src_addr = bpf_ntohl(skc_rcv_saddr);
	if (dst_addr == 0 || src_addr == 0)
	{
		return 0;
	}

	if (dst_addr == IP(127, 0, 0, 1) || src_addr == IP(127, 0, 0, 1))
	{
		return 0;
	}

	if (dst_addr == src_addr)
	{
		return 0;
	}

	ret = bpf_get_current_comm(comm, sizeof(comm));
	if (ret)
	{
		bpf_printk("fail to get current comm: %d", ret);
		return 0;
	}
	u32 lkey = __LINE__;
	log = (typeof(log))malloc_page(lkey);
	if (!log)
	{
		return 0;
	}

	log->traffic = traffic;
	log->remote_ip = dst_addr;
	log->remote_port = bpf_ntohs(skc_dport);
	log->pid = bpf_get_current_pid_tgid();
	log->dir = dir;

	if (!rule_filter(log))
	{
		DEBUG(0, "filtered by rule");
		goto exit;
	}

	u64 data[] = {(u64)comm};
	ret = bpf_snprintf(log->comm, 16, "%s", data, sizeof(data));
	if (ret < 0)
	{
		bpf_printk("error: bpf_snprintf: %d", ret);
		goto exit;
	}

	if (ret > 16)
	{
		DEBUG(0, "inpossible code branch reached");
		ret = 16;
	}

	ret = bpf_ringbuf_output(&logs, log, sizeof(*log) + ret, 0);
	if (ret != 0)
	{
		bpf_err("bpf_map_push_elem: %d\n", ret);
	}

exit:
	if (log)
	{
		free_page(lkey);
	}
	return 0;
}

SEC("fexit/__sock_sendmsg")
int BPF_PROG(__sock_sendmsg, struct socket *sock, struct msghdr *msg, int ret)
{
	return traffic_stat(sock, ret, TRAFFIC_OUT);
}

// Alternatives for __sock_sendmsg START
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, void *);
	__uint(max_entries, 1000); // 40 MB
} sock_cache SEC(".maps");

static void save_sock(struct socket *sock)
{
	long ret;
	pid_t pid;
	pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&sock_cache, &pid, &sock, BPF_ANY);
	if (ret)
	{
		bpf_err("map update");
	}
}

static void *get_sock(void)
{
	void *ret;
	pid_t pid;
	pid = bpf_get_current_pid_tgid();
	ret = bpf_map_lookup_elem(&sock_cache, &pid);
	if (!ret)
	{
		DEBUG(0, "map update");
	}
	return ret;
}

static void clean_sock(void)
{
	long ret;
	pid_t pid;
	pid = bpf_get_current_pid_tgid();
	ret = bpf_map_delete_elem(&sock_cache, &pid);
	if (ret)
	{
		bpf_err("map delete");
	}
}

SEC("fexit/sock_sendmsg")
int BPF_PROG(sock_sendmsg, struct socket *sock, struct msghdr *msg, int ret)
{
	return traffic_stat(sock, ret, TRAFFIC_OUT);
}

SEC("fexit/sock_write_iter")
int BPF_PROG(
	sock_write_iter,
	struct kiocb *iocb,
	struct iov_iter *from,
	int ret
)
{
	struct file *file;
	struct socket *sock;
	file = iocb->ki_filp;
	sock = file->private_data;
	if (!sock)
	{
		return 0;
	}
	return traffic_stat(sock, ret, TRAFFIC_OUT);
}

SEC("fentry/__sys_sendto")
int BPF_PROG(__sys_sendto_entry)
{
	save_sock(NULL);
	return 0;
}
SEC("lsm/socket_sendmsg")
int BPF_PROG(
	socket_sendmsg,
	struct socket *sock,
	struct msghdr *msg,
	int size,
	int ret
)
{
	struct socket **psock;
	psock = get_sock();
	if (!psock)
	{
		return 0;
	}
	*psock = sock;
	return 0;
}
SEC("fexit/__sys_sendto")
int BPF_PROG(
	__sys_sendto_exit,
	int fd,
	void __user *buff,
	size_t len,
	unsigned int flags,
	struct sockaddr __user *addr,
	int addr_len,
	int ret
)
{
	struct socket *sock;
	struct socket **psock;
	psock = get_sock();
	if (!psock)
	{
		return 0;
	}
	sock = *psock;
	clean_sock();
	return traffic_stat(sock, ret, TRAFFIC_OUT);
}
SEC("fexit/____sys_sendmsg")
int BPF_PROG(
	____sys_sendmsg,
	struct socket *sock,
	struct msghdr *msg_sys,
	unsigned int flags,
	struct used_address *used_address,
	unsigned int allowed_msghdr_flags,
	int ret
)
{
	return traffic_stat(sock, ret, TRAFFIC_OUT);
}
// Alternatives for __sock_sendmsg END

SEC("fexit/sock_recvmsg")
int BPF_PROG(
	sock_recvmsg,
	struct socket *sock,
	struct msghdr *msg,
	int flags,
	int ret
)
{
	return traffic_stat(sock, ret, TRAFFIC_IN);
}