#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "jhash.h"
#include "Kstr-utils.h"
#include "Kmem.h"
#include "Kcom.h"
#include "fcntl-defs.h"
#include "blk_types.h"
#include "Kblk.h"
#include "dkapture.h"

char _license[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAP_MAX_ENTRY 10000
#define MKDEV(ma, mi) ((ma) << 8 | (mi))

struct Rule
{
	pid_t pid;
	dev_t dev;
	char comm[TASK_COMM_LEN];
	u64 min_ns;
	u32 duration;
};

// for saving the timestamp, __data_len, and cmd_flags of each request
struct start_req_t
{
	u64 ts;
	u64 data_len;
	u64 cmd_flags;
};

// for saving process info by request
struct who_t
{
	u32 pid;
	char name[TASK_COMM_LEN];
};

// the key for the output summary
struct info_t
{
	u32 pid;
	int rwflag;
	int major;
	int minor;
	char name[TASK_COMM_LEN];
};

// the value of the output summary
struct val_t
{
	u64 bytes;
	u64 us;
	u32 io;
};

struct tp_args
{
	u64 __unused__;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	unsigned int bytes;
	char rwbs[8];
	char comm[16];
	char cmd[];
};

struct hash_key
{
	dev_t dev;
	u32 _pad;
	sector_t sector;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct hash_key);
	__type(value, struct start_req_t);
	__uint(max_entries, MAP_MAX_ENTRY);
} start SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct hash_key);
	__type(value, struct who_t);
	__uint(max_entries, MAP_MAX_ENTRY);
} whobyreq SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct info_t);
	__type(value, struct val_t);
	__uint(max_entries, MAP_MAX_ENTRY);
} counts SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, 1);
} filter SEC(".maps");

static struct Rule *get_rule(void)
{
	struct Rule *rule;
	int key = 0;
	rule = bpf_map_lookup_elem(&filter, &key); // Lookup rule
	return rule; // Return rule or NULL if not found
}

static dev_t ddevt(struct gendisk *disk)
{
	return (disk->major << 20) | disk->first_minor;
}

// cache PID and comm by-req
static int __trace_pid_start(struct hash_key key)
{
	struct who_t who;
	u32 pid;
	long ret;

	if (bpf_get_current_comm(&who.name, sizeof(who.name)) == 0)
	{
		pid = bpf_get_current_pid_tgid() >> 32;
		struct Rule *rule = get_rule();

		if (rule && rule->pid && pid != rule->pid)
		{
			return 0;
		}

		who.pid = pid;
		ret = bpf_map_update_elem(&whobyreq, &key, &who, BPF_ANY);
		if (ret)
		{
			bpf_err("failed to update whobyreq: %ld", ret);
		}
	}

	return 0;
}

// SEC("fentry/__blk_account_io_start")
// SEC("fentry/blk_account_io_start")
SEC("fentry")
int BPF_PROG(trace_pid_start, struct request *req)
{
	struct hash_key key = {.dev = ddevt(req->q->disk), .sector = req->__sector};

	return __trace_pid_start(key);
}

SEC("tracepoint/block/block_io_start")
int trace_pid_start_tp(struct tp_args *args)
{
	struct hash_key key = {.dev = args->dev, .sector = args->sector};

	return __trace_pid_start(key);
}

// time block I/O
SEC("fentry/blk_mq_start_request")
int BPF_PROG(trace_req_start, struct request *req)
{
	long ret;
	struct hash_key key = {.dev = ddevt(req->q->disk), .sector = req->__sector};
	struct start_req_t start_req = {
		.ts = bpf_ktime_get_ns(),
		.data_len = req->__data_len,
		.cmd_flags = req->cmd_flags
	};
	ret = bpf_map_update_elem(&start, &key, &start_req, BPF_ANY);
	if (ret)
	{
		bpf_err("failed to update start: %ld", ret);
	}
	return 0;
}

static int rule_filter(pid_t pid, const char *comm, dev_t dev)
{
	struct Rule *rule = get_rule();

	if (!rule)
	{
		return 1;
	}

	if (rule->pid && pid != rule->pid)
	{
		DEBUG(0, "filtered by pid %d", rule->pid);
		return 0;
	}
	if (rule->dev && dev != rule->dev)
	{
		DEBUG(0, "filtered by dev %d", rule->dev);
		return 0;
	}
	if (rule->comm[0] && comm && strncmp(rule->comm, comm, 16))
	{
		DEBUG(0, "filtered by comm %s", rule->comm);
		return 0;
	}
	return 1;
}

// output
static int __trace_req_completion(struct hash_key key)
{
	long ret;
	struct start_req_t *startp;

	// fetch timestamp and calculate delta
	startp = bpf_map_lookup_elem(&start, &key);
	if (startp == 0)
	{
		return 0; // missed tracing issue
	}

	struct who_t *whop;
	u32 pid;
	char *comm;

	whop = bpf_map_lookup_elem(&whobyreq, &key);
	pid = whop != 0 ? whop->pid : 0;
	comm = whop != 0 ? whop->name : 0;

	// setup info_t key
	struct info_t info = {};
	info.major = key.dev >> 20;
	info.minor = key.dev & ((1 << 20) - 1);
	info.rwflag = !!((startp->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);

	if (!rule_filter(pid, comm, MKDEV(info.major, info.minor)))
	{
		ret = bpf_map_delete_elem(&start, &key);
		if (ret)
		{
			bpf_err("failed to delete start: %ld", ret);
		}
		if (whop != 0)
		{
			ret = bpf_map_delete_elem(&whobyreq, &key);
			if (ret)
			{
				bpf_err("failed to delete whobyreq: %ld", ret);
			}
		}
		return 0;
	}

	struct val_t *valp, zero = {};
	u64 delta_us = (bpf_ktime_get_ns() - startp->ts) / 1000;

	if (whop == 0)
	{
		// missed pid who, save stats as pid 0
		ret = bpf_map_update_elem(&counts, &info, &zero, BPF_NOEXIST);
		if (ret)
		{
			DEBUG(0, "failed to update counts: %ld", ret);
		}
		valp = bpf_map_lookup_elem(&counts, &info);
		if (!valp)
		{
			bpf_err("failed to lookup counts");
		}
	}
	else
	{
		info.pid = whop->pid;
		__builtin_memcpy(&info.name, whop->name, sizeof(info.name));
		ret = bpf_map_update_elem(&counts, &info, &zero, BPF_NOEXIST);
		if (ret)
		{
			DEBUG(0, "failed to update counts: %ld", ret);
		}
		valp = bpf_map_lookup_elem(&counts, &info);
		if (!valp)
		{
			bpf_err("failed to lookup counts");
		}
	}

	if (valp)
	{
		// save stats
		valp->us += delta_us;
		valp->bytes += startp->data_len;
		valp->io++;
	}

	ret = bpf_map_delete_elem(&start, &key);
	if (ret)
	{
		bpf_err("failed to delete start: %ld", ret);
	}
	ret = bpf_map_delete_elem(&whobyreq, &key);
	if (ret)
	{
		DEBUG(0, "failed to delete whobyreq: %ld", ret);
	}

	return 0;
}

// SEC("fexit/__blk_account_io_done")
// SEC("fexit/blk_account_io_done")
SEC("fexit")
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
	struct hash_key key = {.dev = ddevt(req->q->disk), .sector = req->__sector};

	return __trace_req_completion(key);
}

SEC("tracepoint/block/block_io_done")
int trace_req_completion_tp(struct tp_args *args)
{
	struct hash_key key = {.dev = args->dev, .sector = args->sector};

	return __trace_req_completion(key);
}

struct event
{
	char comm[TASK_COMM_LEN];
	__u64 delta;
	__u64 qdelta;
	__u64 ts;
	__u64 sector;
	__u32 len;
	__u32 pid;
	__u32 cmd_flags;
	__u32 dev;
};

struct stage
{
	u64 insert;
	u64 issue;
	__u32 dev;
};

struct piddata
{
	char comm[TASK_COMM_LEN];
	u32 pid;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_ENTRY);
	__type(key, struct request *);
	__type(value, struct piddata);
} infobyreq SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_ENTRY);
	__type(key, struct request *);
	__type(value, struct stage);
} start2 SEC(".maps");

SEC("tp_btf/block_rq_complete")
int BPF_PROG(
	block_rq_complete,
	struct request *rq,
	int error,
	unsigned int nr_bytes
)
{
	long ret;
	u64 ts = bpf_ktime_get_ns();
	struct piddata *piddatap;
	struct event event = {};
	struct stage *stagep;
	s64 delta;

	struct Rule *rule = get_rule();
	if (!rule)
	{
		return 0;
	}

	stagep = bpf_map_lookup_elem(&start2, &rq);
	if (!stagep)
	{
		return 0;
	}
	delta = (s64)(ts - stagep->issue);
	if (delta < 0 || delta < rule->min_ns)
	{
		goto cleanup;
	}
	piddatap = bpf_map_lookup_elem(&infobyreq, &rq);
	if (!piddatap)
	{
		event.comm[0] = '?';
	}
	else
	{
		__builtin_memcpy(&event.comm, piddatap->comm, sizeof(event.comm));
		event.pid = piddatap->pid;
	}
	event.delta = delta;
	if (BPF_CORE_READ(rq, q, elevator))
	{
		if (!stagep->insert)
		{
			event.qdelta = -1; /* missed or don't insert entry */
		}
		else
		{
			event.qdelta = stagep->issue - stagep->insert;
		}
	}
	event.ts = ts;
	event.sector = BPF_CORE_READ(rq, __sector);
	event.len = BPF_CORE_READ(rq, __data_len);
	event.cmd_flags = BPF_CORE_READ(rq, cmd_flags);
	event.dev = stagep->dev;

	if (!rule_filter(event.pid, event.comm, event.dev))
	{
		goto cleanup;
	}

	ret = bpf_perf_event_output(
		ctx,
		&events,
		BPF_F_CURRENT_CPU,
		&event,
		sizeof(event)
	);

	if (ret)
	{
		bpf_err("bpf_perf_event_output: %ld", ret);
	}

	if (event.qdelta == -1)
	{
		DEBUG(
			0,
			"ts:%lu sec:%lu len:%lu cmd:%u dev%u",
			event.ts,
			event.sector,
			event.len,
			event.cmd_flags,
			event.dev
		);
	}
	DEBUG(0, "BIO data perf reached");

cleanup:
	bpf_map_delete_elem(&start2, &rq);
	bpf_map_delete_elem(&infobyreq, &rq);
	return 0;
}

static int trace_rq_start(struct request *rq, bool insert)
{
	struct gendisk *disk;
	struct stage *stagep, stage = {};
	u64 ts = bpf_ktime_get_ns();

	stagep = bpf_map_lookup_elem(&start2, &rq);
	if (!stagep)
	{
		stagep = &stage;
	}

	if (insert)
	{
		stagep->insert = ts;
	}
	else
	{
		stagep->issue = ts;
	}

	if (stagep == &stage)
	{
		disk = get_disk(rq);
		stage.dev = disk ? MKDEV(
							   BPF_CORE_READ(disk, major),
							   BPF_CORE_READ(disk, first_minor)
						   )
						 : 0;
		bpf_map_update_elem(&start2, &rq, stagep, 0);
	}

	return 0;
}

static int trace_pid(struct request *rq)
{
	u64 id = bpf_get_current_pid_tgid();
	struct piddata piddata = {};

	piddata.pid = id;
	bpf_get_current_comm(&piddata.comm, sizeof(&piddata.comm));
	bpf_map_update_elem(&infobyreq, &rq, &piddata, 0);
	return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue)
{
	return trace_rq_start((void *)ctx[0], false);
}

SEC("tp_btf/block_rq_insert")
int BPF_PROG(block_rq_insert)
{
	return trace_rq_start((void *)ctx[0], true);
}

SEC("kprobe/blk_account_io_merge_bio")
int BPF_KPROBE(blk_account_io_merge_bio, struct request *rq)
{
	return trace_pid(rq);
}

// not used
SEC("fentry/blk_account_io_start")
int BPF_PROG(blk_account_io_start, struct request *rq)
{
	return trace_pid(rq);
}

SEC("tp_btf/block_io_start")
int BPF_PROG(block_io_start, struct request *rq)
{
	return trace_pid(rq);
}