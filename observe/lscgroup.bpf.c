#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Kcom.h"
#include "Kmem.h"
#include "Kstr-utils.h"

#define ITER_PASS_STRING 0
#define _Map
#define _Unsafe

#ifdef ___bpf_nth
#undef ___bpf_nth
#define ___bpf_nth(                                                            \
	_,                                                                         \
	_1,                                                                        \
	_2,                                                                        \
	_3,                                                                        \
	_4,                                                                        \
	_5,                                                                        \
	_6,                                                                        \
	_7,                                                                        \
	_8,                                                                        \
	_9,                                                                        \
	_a,                                                                        \
	_b,                                                                        \
	_c,                                                                        \
	_d,                                                                        \
	_e,                                                                        \
	N,                                                                         \
	...                                                                        \
)                                                                              \
	N
#endif

#ifdef ___bpf_pick_printk
#undef ___bpf_pick_printk
#define ___bpf_pick_printk(...)                                                \
	___bpf_nth(                                                                \
		_,                                                                     \
		##__VA_ARGS__,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_vprintk,                                                         \
		__bpf_printk /*3*/,                                                    \
		__bpf_printk /*2*/,                                                    \
		__bpf_printk /*1*/,                                                    \
		__bpf_printk /*0*/                                                     \
	)
#endif

#ifdef ___bpf_narg
#undef ___bpf_narg
#define ___bpf_narg(...)                                                       \
	___bpf_nth(                                                                \
		_,                                                                     \
		##__VA_ARGS__,                                                         \
		14,                                                                    \
		13,                                                                    \
		12,                                                                    \
		11,                                                                    \
		10,                                                                    \
		9,                                                                     \
		8,                                                                     \
		7,                                                                     \
		6,                                                                     \
		5,                                                                     \
		4,                                                                     \
		3,                                                                     \
		2,                                                                     \
		1,                                                                     \
		0                                                                      \
	)
#endif

#define ___bpf_fill13(arr, p, x, args...)                                      \
	arr[p] = x;                                                                \
	___bpf_fill12(arr, p + 1, args)
#define ___bpf_fill14(arr, p, x, args...)                                      \
	arr[p] = x;                                                                \
	___bpf_fill13(arr, p + 1, args)

#define SET_CSS_ID(arr, x)                                                     \
	do                                                                         \
	{                                                                          \
		legacy_strncpy(                                                        \
			arr[x##_cgrp_id].name,                                             \
			#x,                                                                \
			sizeof(arr[x##_cgrp_id].name)                                      \
		);                                                                     \
	} while (0)

struct Rule
{
	// necessary kernel symbols
	void *pcgrp_dfl_root;
	void *pcgrp_dfl_implicit_ss_mask;
	void *pcgrp_dfl_threaded_ss_mask;
	void *pcgrp_dfl_inhibit_ss_mask;
	// fiter parameter
	u64 id;
	u64 parent_id;
	int level;
	// Note: clear the name buf before resigning
	char name[PAGE_SIZE];
};

struct CssId
{
	char name[12];
};

char _license[] SEC("license") = "GPL";
static int terminate_early = 0;
static u64 terminal_cgroup = 0;

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, 1);
} filter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct CssId[CGROUP_SUBSYS_COUNT]);
	__uint(max_entries, 1);
} css_ids SEC(".maps"); // cgroup sub-system ids

struct BpfData
{
	u64 id;
	u64 parent_id;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	u16 controller;
	u16 subtree_control;
	long unsigned int flags;
	char name[]; // name must be aligned to 8 byte
};

static void *cgrp_dfl_root = NULL;
static u16 cgrp_dfl_implicit_ss_mask = 0;
static u16 cgrp_dfl_threaded_ss_mask = 0;
static u16 cgrp_dfl_inhibit_ss_mask = 0;
static char mem[8192] = {};
static u64 filter_id;
static u64 filter_parent_id;
static int filter_level;
static char filter_name[PAGE_SIZE] = {};

static inline struct cgroup *_Unsafe cgroup_parent(struct cgroup *cgrp)
{
	struct cgroup_subsys_state *parent_css;
	parent_css = cgrp->self.parent;

	if (parent_css)
	{
		return container_of(parent_css, struct cgroup, self);
	}
	else
	{
		DEBUG(0, "this is a root");
	}
	return NULL;
}

static inline u64 cgroup_id(struct cgroup *cgrp)
{
	return cgrp->kn->id;
}

static inline u64 cgroup_id_unsafe(struct cgroup *_Unsafe cgrp)
{
	u64 id;
	struct kernfs_node *kn;
	if (!cgrp)
	{
		return 0;
	}
	bpf_read_kmem_ret(&kn, &cgrp->kn, return 0);
	bpf_read_kmem_ret(&id, &kn->id, return 0);
	return id;
}

static inline const char *cgroup_name(struct cgroup *_Unsafe cgrp)
{
	return cgrp->kn->name;
}

static void get_css_ids(void)
{
	static bool job_done = false;
	struct CssId *pcss_ids;
	u32 ckey = 0;
	if (job_done)
	{
		return;
	}

	job_done = true;
	pcss_ids = bpf_map_lookup_elem(&css_ids, &ckey);
	if (!pcss_ids)
	{
		bpf_err("no css ids specified");
	}
	else
	{
		SET_CSS_ID(pcss_ids, cpuset);
		SET_CSS_ID(pcss_ids, cpu);
		SET_CSS_ID(pcss_ids, cpuacct);
		SET_CSS_ID(pcss_ids, io);
		SET_CSS_ID(pcss_ids, memory);
		SET_CSS_ID(pcss_ids, devices);
		SET_CSS_ID(pcss_ids, freezer);
		SET_CSS_ID(pcss_ids, perf_event);
		SET_CSS_ID(pcss_ids, hugetlb);
		SET_CSS_ID(pcss_ids, pids);
		SET_CSS_ID(pcss_ids, rdma);
		SET_CSS_ID(pcss_ids, misc);
		SET_CSS_ID(pcss_ids, memory);
		/**
		 * be careful with these code, these code badly depends on
		 * linux kernel cgroup sub-system configuration, when these
		 * code compile in one environment, and run in another
		 * environment with different kernel cgroup sub-system
		 * configuration, these SET_CSS_ID code won't work properly as
		 * expected. the code below is used to check that.
		 */
	}
}

static void get_ksyms(void)
{
	static bool job_done = false;
	struct Rule *rule;
	u32 rkey = 0;
	if (job_done)
	{
		return;
	}

	job_done = true;

	rule = bpf_map_lookup_elem(&filter, &rkey);
	if (!rule)
	{
		bpf_err("bpf_map_lookup_elem failure");
		return;
	}

	cgrp_dfl_root = rule->pcgrp_dfl_root;
	bpf_read_kmem_ret(
		&cgrp_dfl_implicit_ss_mask,
		rule->pcgrp_dfl_implicit_ss_mask,
		NOP
	);
	bpf_read_kmem_ret(
		&cgrp_dfl_threaded_ss_mask,
		rule->pcgrp_dfl_threaded_ss_mask,
		NOP
	);
	bpf_read_kmem_ret(
		&cgrp_dfl_inhibit_ss_mask,
		rule->pcgrp_dfl_inhibit_ss_mask,
		NOP
	);
	filter_id = rule->id;
	filter_parent_id = rule->parent_id;
	filter_level = rule->level;
	bpf_read_kstr_ret(filter_name, PAGE_SIZE, rule->name, filter_name[0] = 0);
	DEBUG(0, "cgrp_dfl_root: 0x%lx", cgrp_dfl_root);
	DEBUG(0, "cgrp_dfl_implicit_ss_mask: 0x%lx", cgrp_dfl_implicit_ss_mask);
	DEBUG(0, "cgrp_dfl_threaded_ss_mask: 0x%lx", cgrp_dfl_threaded_ss_mask);
	DEBUG(0, "cgrp_dfl_inhibit_ss_mask: 0x%lx", cgrp_dfl_inhibit_ss_mask);
	DEBUG(0, "filter id: %d", filter_id);
	DEBUG(0, "filter parent id: %d", filter_id);
	DEBUG(0, "filter level: %d", filter_id);
	DEBUG(0, "filter name: %s", filter_name);
}

static int filter_check(const struct BpfData *log)
{
	if (filter_id && filter_id != log->id)
	{
		DEBUG(0, "filtered by id: %llu vs %llu", filter_id, log->id);
		return 0;
	}

	if (filter_parent_id && filter_parent_id != log->parent_id)
	{
		DEBUG(
			0,
			"filtered by parent id: %llu vs %llu",
			filter_parent_id,
			log->parent_id
		);
		return 0;
	}

	if (filter_level && filter_level != log->level)
	{
		DEBUG(0, "filtered by level: %d vs %d", filter_level, log->level);
		return 0;
	}

	if (filter_name[0] && strncmp(filter_name, log->name, PAGE_SIZE))
	{
		if (0 /* debug? */ && bpf_strncmp(log->name, 6, "debug") == 0)
		{
			DEBUG(1, "%0x vs %0x", *(long *)filter_name, *(long *)log->name);
		}
		DEBUG(0, "filtered by name: %s vs %s", filter_name, log->name);
		return 0;
	}

	return 1;
}

static bool cgroup_threaded(const struct cgroup *cgrp)
{
	return cgrp->dom_cgrp != cgrp;
}

static bool cgroup_on_dfl(const struct cgroup *cgrp)
{
	return cgrp->root == cgrp_dfl_root;
}

static u16 cgroup_control(struct cgroup *cgrp)
{
	struct cgroup *parent;
	u16 root_ss_mask;
	parent = cgroup_parent(cgrp);
	root_ss_mask = cgrp->root->subsys_mask;

	if (parent)
	{
		u16 ss_mask;
		bpf_read_kmem_ret(&ss_mask, &parent->subtree_control, NOP);

		/* threaded cgroups can only have threaded controllers */
		if (cgroup_threaded(cgrp))
		{
			ss_mask &= cgrp_dfl_threaded_ss_mask;
		}
		return ss_mask;
	}

	if (cgroup_on_dfl(cgrp))
	{
		root_ss_mask &= ~(cgrp_dfl_inhibit_ss_mask | cgrp_dfl_implicit_ss_mask);
	}
	return root_ss_mask;
}

static long fill_log(struct cgroup *cgrp, struct BpfData *_Map log)
{
	struct cgroup *parent_cgrp;
	u64 id, parent_id;
	int level;
	long unsigned int flags;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	u16 subtree_control;
	u16 controller;
	const char *name;
	long name_len;

	parent_cgrp = cgroup_parent(cgrp);
	name = cgroup_name(cgrp);

	id = cgroup_id(cgrp);
	parent_id = cgroup_id_unsafe(parent_cgrp);
	flags = cgrp->flags;
	level = cgrp->level;
	max_depth = cgrp->max_depth;
	nr_descendants = cgrp->nr_descendants;
	nr_dying_descendants = cgrp->nr_dying_descendants;
	max_descendants = cgrp->max_descendants;
	nr_populated_csets = cgrp->nr_populated_csets;
	nr_populated_domain_children = cgrp->nr_populated_domain_children;
	nr_populated_threaded_children = cgrp->nr_populated_threaded_children;
	nr_threaded_children = cgrp->nr_threaded_children;
	subtree_control = cgrp->subtree_control;
	controller = cgroup_control(cgrp);

	DEBUG(0, "------------------------------------");
	DEBUG(0, "name: %s", name);
	DEBUG(0, "id: %llu", id);
	DEBUG(0, "parent_id: %llu", parent_id);
	DEBUG(0, "flags: %lu", flags);
	DEBUG(0, "level: %d", level);
	DEBUG(0, "max_depth: %d", max_depth);
	DEBUG(0, "nr_descendants: %d", nr_descendants);
	DEBUG(0, "nr_dying_descendants: %d", nr_dying_descendants);
	DEBUG(0, "max_descendants: %d", max_descendants);
	DEBUG(0, "nr_populated_csets: %d", nr_populated_csets);
	DEBUG(0, "nr_populated_domain_children: %d", nr_populated_domain_children);
	DEBUG(
		0,
		"nr_populated_threaded_children: %d",
		nr_populated_threaded_children
	);
	DEBUG(0, "nr_threaded_children: %d", nr_threaded_children);
	DEBUG(0, "subtree_control: %u", subtree_control);
	DEBUG(0, "controller: %u", controller);

	log->id = id;
	log->parent_id = parent_id;
	log->flags = flags;
	log->level = level;
	log->max_depth = max_depth;
	log->nr_descendants = nr_descendants;
	log->nr_dying_descendants = nr_dying_descendants;
	log->max_descendants = max_descendants;
	log->nr_populated_csets = nr_populated_csets;
	log->nr_populated_domain_children = nr_populated_domain_children;
	log->nr_populated_threaded_children = nr_populated_threaded_children;
	log->nr_threaded_children = nr_threaded_children;
	log->subtree_control = subtree_control;
	log->controller = controller;
	name_len = bpf_read_kstr(log->name, 4096, cgroup_name(cgrp));
	if (name_len < 0)
	{
		bpf_err("bpf_read_kstr: %d", name_len);
		name_len = 0;
	}
	DEBUG(0, "name length: %ld", name_len);
	/**
	 * make sure 'name' has at least one tailing zero 8-byte,
	 * so that we can call util-function 'strncmp' afterwords.
	 */
	(*(long *)&log->name[name_len]) = 0;
	(*(long *)&log->name[name_len + 1]) = 0;
	return sizeof(*log) + name_len;
}

SEC("iter/cgroup")
int cgroup_iter(struct bpf_iter__cgroup *ctx)
{
	long ret;
	struct seq_file *seq;
	struct cgroup *cgrp;
	struct BpfData *log;

	seq = ctx->meta->seq;
	cgrp = ctx->cgroup;
	log = (typeof(log))mem;
	get_ksyms();
	get_css_ids();

#if ITER_PASS_STRING
	/* epilogue */
	if (cgrp == NULL)
	{
		DEBUG(1, "epilogue");
		BPF_SEQ_PRINTF(seq, "epilogue\n");
		return 0;
	}

	/* prologue */
	if (ctx->meta->seq_num == 0)
	{
		BPF_SEQ_PRINTF(seq, "prologue\n");
	}

	ret = fill_log(cgrp, log);
	if (!filter_check(log))
	{
		return 0;
	}

	ret = BPF_SEQ_PRINTF(seq, "%s: %8llu\n", log->name, log->id);

	if (0 != ret)
	{
		bpf_err("BPF_SEQ_PRINTF: %d", ret);
	}
#else
	if (cgrp == NULL)
	{
		return 0;
	}

	ret = fill_log(cgrp, log);
	if (!filter_check(log))
	{
		return 0;
	}
	ret = bpf_seq_write(seq, log, ret);

	if (0 != ret)
	{
		bpf_err("bpf_seq_write: %d", ret);
	}
#endif

	if (terminal_cgroup == cgroup_id(cgrp))
	{
		DEBUG(1, "id matched, break iterator");
		return 1;
	}

	return terminate_early ? 1 : 0;
}
