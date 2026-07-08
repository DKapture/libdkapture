// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "dkapture.h"

struct Rule
{
	unsigned long long id = 0;
	unsigned long long parent_id = 0;
	int level = 0;
	bool has_id = false;
	bool has_parent_id = false;
	bool has_level = false;
	char name[PATH_MAX] = {0};
};

struct HelpMsg
{
	const char *argparam;
	const char *msg;
};

static struct option lopts[] = {
	{"name", required_argument, 0, 'n'},
	{"id", required_argument, 0, 'i'},
	{"parent_id", required_argument, 0, 'p'},
	{"level", required_argument, 0, 'l'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static HelpMsg help_msg[] = {
	{"[cgroup name]",
	 "the directory name you use to create "
	 "a new cgroup by calling 'mkdir'.\n"},
	{"[cgroup id]",
	 "the cgroup inode number, you can check "
	 "this by call 'stat' syscall on a cgroup directory.\n"},
	{"[parent id]", "similar to id, but of parent.\n"},
	{"[cgroup level]",
	 "the cgroup rank level in the whole "
	 "cgroup hierarchy tree. the level of root cgroup is "
	 "0, and it increases while going down through the tree\n"},
	{"", "print this help message\n"},
};

static std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts;
	for (int i = 0; lopts[i].name; i++)
	{
		sopts += static_cast<char>(lopts[i].val);
		switch (lopts[i].has_arg)
		{
		case no_argument:
			break;
		case required_argument:
			sopts += ":";
			break;
		case optional_argument:
			sopts += "::";
			break;
		default:
			fprintf(stderr, "Code internal bug\n");
			abort();
		}
	}
	return sopts;
}

static void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  list cgroup hierarchy information.\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf(
			"  -%c, --%s %s\n\t%s\n",
			lopts[i].val,
			lopts[i].name,
			help_msg[i].argparam,
			help_msg[i].msg
		);
	}
}

#ifdef BUILTIN

#include <assert.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "com.h"
#include "jhash.h"
#include "kallsyms.h"
#include "lscgroup.skel.h"
#include "types.h"

struct KernelRule
{
	void *pcgrp_dfl_root;
	void *pcgrp_dfl_implicit_ss_mask;
	void *pcgrp_dfl_threaded_ss_mask;
	void *pcgrp_dfl_inhibit_ss_mask;
	u64 id;
	u64 parent_id;
	int level;
	char name[PATH_MAX];
};

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
	unsigned long flags;
	char name[];
};

struct CssId
{
	char name[12];
};

static struct KernelRule rule = {};
static lscgroup_bpf *obj;
static int filter_fd;
static int css_fd;
static int iter_fd;
static std::atomic<bool> exit_flag(false);
static struct CssId css_ids[16];

static void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	optind = 1;
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'i':
			rule.id = strtoull(optarg, nullptr, 10);
			break;
		case 'p':
			rule.parent_id = strtoull(optarg, nullptr, 10);
			break;
		case 'l':
			rule.level = strtol(optarg, nullptr, 10);
			break;
		case 'n':
			if (strlen(optarg) >= PATH_MAX)
			{
				pr_error(
					"the name string is too long, must be less than %d\n",
					PATH_MAX
				);
				exit(-1);
			}
			strncpy(rule.name, optarg, PATH_MAX);
			break;
		case 'h':
			Usage(argv[0]);
			exit(0);
			break;
		default:
			Usage(argv[0]);
			exit(-1);
			break;
		}
	}
}

static void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; };
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

static bpf_link *attach_cgroup_iter(struct bpf_program *prog)
{
	bpf_link *iter_link;
	union bpf_iter_link_info link_info = {};
	struct bpf_iter_attach_opts opts = {};
	link_info.cgroup.order = BPF_CGROUP_ITER_DESCENDANTS_PRE;
	opts.link_info = &link_info;
	opts.sz = sizeof(opts);
	opts.link_info_len = sizeof(link_info);
	bpf_program__set_autoattach(prog, false);
	iter_link = bpf_program__attach_iter(prog, &opts);
	if (!iter_link)
	{
		pr_error("fail to link iter bpf prog\n");
		return NULL;
	}
	return iter_link;
}

static void lookup_ksyms(void)
{
	void *pcgrp_dfl_root = kallsyms_lookup("cgrp_dfl_root");
	void *pcgrp_dfl_implicit_ss_mask =
		kallsyms_lookup("cgrp_dfl_implicit_ss_mask");
	void *pcgrp_dfl_threaded_ss_mask =
		kallsyms_lookup("cgrp_dfl_threaded_ss_mask");
	void *pcgrp_dfl_inhibit_ss_mask =
		kallsyms_lookup("cgrp_dfl_inhibit_ss_mask");

	if (!pcgrp_dfl_root)
	{
		pr_error("fail to lookup kernel symbols\n");
		pr_error("the output 'control' value of cgroup may be wrong\n");
		return;
	}

	rule.pcgrp_dfl_root = pcgrp_dfl_root;
	rule.pcgrp_dfl_implicit_ss_mask = pcgrp_dfl_implicit_ss_mask;
	rule.pcgrp_dfl_threaded_ss_mask = pcgrp_dfl_threaded_ss_mask;
	rule.pcgrp_dfl_inhibit_ss_mask = pcgrp_dfl_inhibit_ss_mask;
}

static void get_css_ids(void)
{
	int key = 0;
	static bool job_done = false;
	if (job_done)
	{
		return;
	}
	job_done = true;
	if (0 != bpf_map_lookup_elem(css_fd, &key, css_ids))
	{
		pr_error("bpf_map_lookup_elem");
	}
}

static int emit_subsys(DKapture::DKCallback callback, void *ctx)
{
	for (unsigned int i = 0; i < 16; i++)
	{
		if (css_ids[i].name[0] == 0)
		{
			continue;
		}

		size_t name_len = strnlen(css_ids[i].name, sizeof(css_ids[i].name));
		size_t payload_sz = sizeof(ProcCgroupSubsys) + name_len + 1;
		size_t total_sz = sizeof(DKapture::DataHdr) + payload_sz;
		auto *hdr = static_cast<DKapture::DataHdr *>(malloc(total_sz));
		if (!hdr)
		{
			return -ENOMEM;
		}

		memset(hdr, 0, total_sz);
		hdr->type = DKapture::PROC_CGROUP_SUBSYS;
		hdr->dsz = total_sz;
		auto *subsys = reinterpret_cast<ProcCgroupSubsys *>(hdr->data);
		subsys->index = i;
		memcpy(subsys->name, css_ids[i].name, name_len);
		subsys->name[name_len] = '\0';

		int ret = callback(ctx, hdr, total_sz);
		free(hdr);
		if (ret != 0)
		{
			return ret;
		}
	}
	return 0;
}

static int emit_cgroups(
	char *buf,
	size_t bsz,
	DKapture::DKCallback callback,
	void *ctx
)
{
	while (bsz >= sizeof(BpfData))
	{
		auto *log = reinterpret_cast<BpfData *>(buf);
		size_t allowed_slen = bsz - sizeof(BpfData);
		size_t slen = strnlen(log->name, allowed_slen);
		if (slen == allowed_slen)
		{
			break;
		}

		size_t log_sz = sizeof(BpfData) + slen + 1;
		size_t payload_sz = sizeof(ProcCgroup) + slen + 1;
		size_t total_sz = sizeof(DKapture::DataHdr) + payload_sz;
		auto *hdr = static_cast<DKapture::DataHdr *>(malloc(total_sz));
		if (!hdr)
		{
			return -ENOMEM;
		}

		memset(hdr, 0, total_sz);
		hdr->type = DKapture::PROC_CGROUP;
		hdr->dsz = total_sz;

		auto *cg = reinterpret_cast<ProcCgroup *>(hdr->data);
		cg->id = log->id;
		cg->parent_id = log->parent_id;
		cg->level = log->level;
		cg->max_depth = log->max_depth;
		cg->nr_descendants = log->nr_descendants;
		cg->nr_dying_descendants = log->nr_dying_descendants;
		cg->max_descendants = log->max_descendants;
		cg->nr_populated_csets = log->nr_populated_csets;
		cg->nr_populated_domain_children = log->nr_populated_domain_children;
		cg->nr_populated_threaded_children = log->nr_populated_threaded_children;
		cg->nr_threaded_children = log->nr_threaded_children;
		cg->controller = log->controller;
		cg->subtree_control = log->subtree_control;
		cg->flags = log->flags;
		memcpy(cg->name, log->name, slen);
		cg->name[slen] = '\0';

		int ret = callback(ctx, hdr, total_sz);
		free(hdr);
		if (ret != 0)
		{
			return ret;
		}

		bsz -= log_sz;
		buf += log_sz;
	}
	return 0;
}

int lscgroup_query(DKapture::DKCallback callback, void *ctx)
{
	ssize_t rd_sz = 0;
	bpf_link *iter_link = nullptr;
	size_t chunk_sz = PATH_MAX * 2;
	std::vector<char> chunk;
	std::vector<char> all_data;
	assert(sizeof(BpfData) < PATH_MAX);

	char arg0[] = "lscgroup";
	char *argv[] = {arg0, nullptr};
	parse_args(1, argv);
	register_signal();
	lookup_ksyms();

	int key = 0;
	obj = lscgroup_bpf::open_and_load();
	if (!obj)
	{
		return -1;
	}

	iter_link = attach_cgroup_iter(obj->progs.cgroup_iter);
	if (!iter_link)
	{
		goto err_out;
	}

	if (0 != lscgroup_bpf::attach(obj))
	{
		goto err_out;
	}

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
	css_fd = bpf_get_map_fd(obj->obj, "css_ids", goto err_out);

	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		pr_error("bpf_map_update_elem");
		goto err_out;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
	if (iter_fd < 0)
	{
		pr_error("creating BPF iterator\n");
		goto err_out;
	}

	chunk.resize(chunk_sz);
	all_data.clear();
	while ((rd_sz = read(iter_fd, chunk.data(), chunk.size())) > 0)
	{
		all_data.insert(all_data.end(), chunk.data(), chunk.data() + rd_sz);
	}
	if (rd_sz == -1)
	{
		if (errno != EOPNOTSUPP)
		{
			perror("cgroup iter read");
			goto err_out;
		}
	}

	get_css_ids();
	if (emit_subsys(callback, ctx) != 0)
	{
		goto err_out;
	}
	if (!all_data.empty() &&
		emit_cgroups(all_data.data(), all_data.size(), callback, ctx) != 0)
	{
		goto err_out;
	}

	close(iter_fd);
	iter_fd = -1;

	if (iter_link)
	{
		bpf_link__destroy(iter_link);
	}
	lscgroup_bpf::detach(obj);
	lscgroup_bpf::destroy(obj);
	return 0;

err_out:
	if (iter_fd >= 0)
	{
		close(iter_fd);
	}
	if (iter_link)
	{
		bpf_link__destroy(iter_link);
	}
	if (obj)
	{
		lscgroup_bpf::detach(obj);
		lscgroup_bpf::destroy(obj);
	}
	return -1;
}

#else

struct CgroupRecord
{
	unsigned long long id;
	unsigned long long parent_id;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	unsigned short controller;
	unsigned short subtree_control;
	unsigned long flags;
	std::string name;
};

struct PrintContext
{
	Rule rule;
	std::string subsys_names[16];
	std::vector<CgroupRecord> records;
};

static const char *titles[] = {
	"ID",
	"parent",
	"LVL",
	"max-depth",
	"DDT",
	"dying-DDT",
	"max-DDT",
	"CSet",
	"D-kids",
	"t-kids",
	"T-kids",
	"sub-ctl",
	"ctlr",
	"flags",
	"name",
	nullptr
};

static void parse_args(int argc, char **argv, Rule &rule)
{
	int opt, opt_idx;
	optind = 1;
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'i':
			rule.id = strtoull(optarg, nullptr, 10);
			rule.has_id = true;
			break;
		case 'p':
			rule.parent_id = strtoull(optarg, nullptr, 10);
			rule.has_parent_id = true;
			break;
		case 'l':
			rule.level = strtol(optarg, nullptr, 10);
			rule.has_level = true;
			break;
		case 'n':
			if (strlen(optarg) >= PATH_MAX)
			{
				fprintf(
					stderr,
					"the name string is too long, must be less than %d\n",
					PATH_MAX
				);
				exit(-1);
			}
			strncpy(rule.name, optarg, sizeof(rule.name));
			rule.name[sizeof(rule.name) - 1] = '\0';
			break;
		case 'h':
			Usage(argv[0]);
			exit(0);
			break;
		default:
			Usage(argv[0]);
			exit(-1);
			break;
		}
	}
}

static bool match_rule(const Rule &rule, const CgroupRecord &record)
{
	if (rule.has_id && record.id != rule.id)
	{
		return false;
	}
	if (rule.has_parent_id && record.parent_id != rule.parent_id)
	{
		return false;
	}
	if (rule.has_level && record.level != rule.level)
	{
		return false;
	}
	if (rule.name[0] != '\0' && record.name != rule.name)
	{
		return false;
	}
	return true;
}

static int handle_event(void *ctx, const void *data, size_t data_sz)
{
	if (!ctx || !data || data_sz < sizeof(DKapture::DataHdr))
	{
		return -EINVAL;
	}

	auto &pc = *static_cast<PrintContext *>(ctx);
	const auto *hdr = static_cast<const DKapture::DataHdr *>(data);

	if (hdr->type == DKapture::PROC_CGROUP_SUBSYS)
	{
		if (data_sz < sizeof(DKapture::DataHdr) + sizeof(ProcCgroupSubsys))
		{
			return -EINVAL;
		}
		const auto *subsys =
			reinterpret_cast<const ProcCgroupSubsys *>(hdr->data);
		if (subsys->index < 16)
		{
			pc.subsys_names[subsys->index] = subsys->name;
		}
		return 0;
	}

	if (hdr->type != DKapture::PROC_CGROUP)
	{
		return 0;
	}
	if (data_sz < sizeof(DKapture::DataHdr) + sizeof(ProcCgroup))
	{
		return -EINVAL;
	}

	const auto *cg = reinterpret_cast<const ProcCgroup *>(hdr->data);
	CgroupRecord record = {
		.id = cg->id,
		.parent_id = cg->parent_id,
		.level = cg->level,
		.max_depth = cg->max_depth,
		.nr_descendants = cg->nr_descendants,
		.nr_dying_descendants = cg->nr_dying_descendants,
		.max_descendants = cg->max_descendants,
		.nr_populated_csets = cg->nr_populated_csets,
		.nr_populated_domain_children = cg->nr_populated_domain_children,
		.nr_populated_threaded_children = cg->nr_populated_threaded_children,
		.nr_threaded_children = cg->nr_threaded_children,
		.controller = cg->controller,
		.subtree_control = cg->subtree_control,
		.flags = cg->flags,
		.name = cg->name,
	};

	if (match_rule(pc.rule, record))
	{
		pc.records.push_back(std::move(record));
	}
	return 0;
}

static void print_records(const PrintContext &pc)
{
	printf("ctlr-bit-meaning:\n");
	for (int i = 0; i < 16; i++)
	{
		if (pc.subsys_names[i].empty())
		{
			printf("\tbit %2d: nop\n", i);
		}
		else
		{
			printf("\tbit %2d: %s\n", i, pc.subsys_names[i].c_str());
		}
	}
	printf("\n");

	int slen = printf(
		"%6s %6s %4s %10s %6s %10s %10s %6s "
		"%6s %6s %6s %8s %4s %8s %s\n",
		titles[0],
		titles[1],
		titles[2],
		titles[3],
		titles[4],
		titles[5],
		titles[6],
		titles[7],
		titles[8],
		titles[9],
		titles[10],
		titles[11],
		titles[12],
		titles[13],
		titles[14]
	);
	while (slen--)
	{
		putc('-', stdout);
	}
	putc('\n', stdout);

	for (const auto &record : pc.records)
	{
		printf(
			"%6llu %6llu %4d %10d %6d %10d %10d %6d "
			"%6d %6d %6d     %04x %04x %8lx %s\n",
			record.id,
			record.parent_id,
			record.level,
			record.max_depth,
			record.nr_descendants,
			record.nr_dying_descendants,
			record.max_descendants,
			record.nr_populated_csets,
			record.nr_populated_domain_children,
			record.nr_populated_threaded_children,
			record.nr_threaded_children,
			record.subtree_control,
			record.controller,
			record.flags,
			record.name.c_str()
		);
	}
}

int main(int argc, char **argv)
{
	PrintContext ctx = {};
	parse_args(argc, argv, ctx.rule);

	std::unique_ptr<DKapture> dk(DKapture::new_instance());
	if (!dk)
	{
		fprintf(stderr, "failed to create DKapture instance\n");
		return 1;
	}
	if (dk->open(stderr, DKapture::ERROR) < 0)
	{
		fprintf(stderr, "failed to open DKapture\n");
		return 1;
	}

	if (dk->read(DKapture::PROC_CGROUP, handle_event, &ctx) < 0)
	{
		fprintf(stderr, "failed to read cgroup data from DKapture\n");
		return 1;
	}

	print_records(ctx);
	return 0;
}

#endif
