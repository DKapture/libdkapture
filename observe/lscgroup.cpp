#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <getopt.h>
#include <string>
#include <signal.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <algorithm>
#include <pthread.h>
#include <map>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <limits.h>

#include "types.h"
#include "lscgroup.skel.h"
#include "com.h"
#include "jhash.h"
#include "kallsyms.h"

#define ITER_PASS_STRING 0

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
	long unsigned int flags;
	char name[];
};

struct CssId
{
	char name[12];
};

static struct Rule rule = {};
static lscgroup_bpf *obj;
static int filter_fd;
static int css_fd;
static int iter_fd;
static std::atomic<bool> exit_flag(false);
static struct CssId css_ids[16];

const char *titles[] = {
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

static struct option lopts[] = {
	{"name",		 required_argument, 0, 'n'},
	{"id",		   required_argument, 0, 'i'},
	{"parent_id", required_argument, 0, 'p'},
	{"level",	  required_argument, 0, 'l'},
	{"help",		 no_argument,		  0, 'h'},
	{0,		   0,				 0, 0  }
};

struct HelpMsg
{
	const char *argparam;
	const char *msg;
};

static HelpMsg help_msg[] = {
	{"[cgroup name]",
	 "the directory name you use to create "
	 "a new cgroup by calling 'mkdir'.\n"					 },
	{"[cgroup id]",
	 "the cgroup inode number, you can check "
	 "this by call 'stat' syscall on a cgroup directory.\n"   },
	{"[parent id]",	"similar to id, but of parent.\n"		 },
	{"[cgroup level]",
	 "the cgroup rank level in the whole "
	 "cgroup hierarchy tree. the level of root cgroup is "
	 "0, and it increases while going down through the tree\n"},
	{"",			   "print this help message\n"			},
};

void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  To query who are occupying the specified file.\n\n");
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

std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts = "";
	for (int i = 0; lopts[i].name; i++)
	{
		sopts += lopts[i].val;
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
			DIE("Code internal bug!!!\n");
			abort();
		}
	}
	return sopts;
}

void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	optind = 1;
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'i':
			rule.id = strtol(optarg, NULL, 10);
			break;
		case 'p':
			rule.parent_id = strtol(optarg, NULL, 10);
			break;
		case 'l':
			rule.level = strtol(optarg, NULL, 10);
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

void register_signal()
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
	void *pcgrp_dfl_root;
	void *pcgrp_dfl_implicit_ss_mask;
	void *pcgrp_dfl_threaded_ss_mask;
	void *pcgrp_dfl_inhibit_ss_mask;
	pcgrp_dfl_root = kallsyms_lookup("cgrp_dfl_root");
	pcgrp_dfl_implicit_ss_mask = kallsyms_lookup("cgrp_dfl_implicit_ss_mask");
	pcgrp_dfl_threaded_ss_mask = kallsyms_lookup("cgrp_dfl_threaded_ss_mask");
	pcgrp_dfl_inhibit_ss_mask = kallsyms_lookup("cgrp_dfl_inhibit_ss_mask");
	DEBUG(0, "cgrp_dfl_root: 0x%lx\n", (long)pcgrp_dfl_root);
	DEBUG(
		0,
		"cgrp_dfl_implicit_ss_mask: 0x%lx\n",
		(long)pcgrp_dfl_implicit_ss_mask
	);
	DEBUG(
		0,
		"cgrp_dfl_threaded_ss_mask: 0x%lx\n",
		(long)pcgrp_dfl_threaded_ss_mask
	);
	DEBUG(
		0,
		"cgrp_dfl_inhibit_ss_mask: 0x%lx\n",
		(long)pcgrp_dfl_inhibit_ss_mask
	);

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

static void process_log(char *buf, size_t bsz)
{
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

	struct BpfData *log;
	size_t slen;
	size_t log_sz;
	size_t allowed_slen;

	printf("ctlr-bit-meaning:\n");

	for (int i = 0; i < 16; i++)
	{
		if (css_ids[i].name[0] == 0)
		{
			printf("\tbit %2d: nop\n", i);
		}
		else
		{
			printf("\tbit %2d: %s\n", i, css_ids[i].name);
		}
	}
	printf("\n");

	slen = printf(
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

	while (bsz >= sizeof(struct BpfData))
	{
		log = (typeof(log))buf;
		id = log->id;
		parent_id = log->parent_id;
		level = log->level;
		max_depth = log->max_depth;
		nr_descendants = log->nr_descendants;
		nr_dying_descendants = log->nr_dying_descendants;
		max_descendants = log->max_descendants;
		nr_populated_csets = log->nr_populated_csets;
		nr_populated_domain_children = log->nr_populated_domain_children;
		nr_populated_threaded_children = log->nr_populated_threaded_children;
		nr_threaded_children = log->nr_threaded_children;
		subtree_control = log->subtree_control;
		controller = log->controller;
		flags = log->flags;
		name = log->name;

		allowed_slen = bsz - sizeof(struct BpfData);
		slen = strnlen(name, allowed_slen);
		if (slen == allowed_slen)
		{
			break; // not null terminated
		}

		log_sz = sizeof(struct BpfData) + slen + 1;
		bsz -= log_sz;
		buf += log_sz;

		printf(
			"%6llu %6llu %4d %10d %6d %10d %10d %6d "
			"%6d %6d %6d     %04x %04x %8lx %s\n",
			id,
			parent_id,
			level,
			max_depth,
			nr_descendants,
			nr_dying_descendants,
			max_descendants,
			nr_populated_csets,
			nr_populated_domain_children,
			nr_populated_threaded_children,
			nr_threaded_children,
			subtree_control,
			controller,
			flags,
			name
		);
	}
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
		pr_error("bpf_map_update_elem");
	}
}

int main(int argc, char *args[])
{
	ssize_t rd_sz = 0;
	bpf_link *iter_link;
	char *buf;
	size_t bsz = PATH_MAX * 2;
	assert(sizeof(BpfData) < PATH_MAX);

	parse_args(argc, args);
	register_signal();
	lookup_ksyms();

	int key = 0;
	obj = lscgroup_bpf::open_and_load();
	if (!obj)
	{
		exit(-1);
	}

	iter_link = attach_cgroup_iter(obj->progs.cgroup_iter);
	if (!iter_link)
	{
		pr_error("fail to link iter bpf prog\n");
		return -1;
	}

	if (0 != lscgroup_bpf::attach(obj))
	{
		exit(-1);
	}

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
	css_fd = bpf_get_map_fd(obj->obj, "css_ids", goto err_out);

	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		pr_error("bpf_map_update_elem");
		goto err_out;
	}

repeat:
	iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
	if (iter_fd < 0)
	{
		pr_error("creating BPF iterator\n");
		goto err_out;
	}

	buf = new char[bsz];
	rd_sz = read(iter_fd, buf, bsz);
	if ((size_t)rd_sz == bsz)
	{
		bsz *= 2;
		delete[] buf;
		close(iter_fd);
		goto repeat;
	}

	if (rd_sz == -1)
	{
		perror("cgroup iter read");
	}
	else
	{
		get_css_ids();
		DEBUG(0, "===== rd_sz: %ld\n", rd_sz);
#if ITER_PASS_STRING
		write(fileno(stdout), buf, rd_sz);
#else
		process_log(buf, rd_sz);
#endif
	}

	delete[] buf;
	close(iter_fd);
	iter_fd = -1;

	follow_trace_pipe();

err_out:
	if (iter_link)
	{
		bpf_link__destroy(iter_link);
	}
	lscgroup_bpf::detach(obj);
	lscgroup_bpf::destroy(obj);
	return 0;
}