// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "net-limit.skel.h"

using namespace std;

#define NET_LIMIT_SCOPE_CGROUP 2
#define NET_LIMIT_EGRESS 1
#define NET_LIMIT_INGRESS 2

static const char *PIN_DIR = "/sys/fs/bpf/dkapture/net-limit";
static const char *PIN_CGROUP_RULES = "/sys/fs/bpf/dkapture/net-limit/"
									  "cgroup_rules";
static const char *PIN_BUCKETS = "/sys/fs/bpf/dkapture/net-limit/buckets";
static const char *PIN_STATS = "/sys/fs/bpf/dkapture/net-limit/stats";
static const char *PIN_SHAPE_RULES = "/sys/fs/bpf/dkapture/net-limit/"
									 "shape_rules";

static volatile bool running = true;
static string g_last_tgid_cgroup_path;

struct limit_rule
{
	uint64_t rate_bps;
	uint64_t burst_bytes;
	uint32_t direction;
	uint32_t pad;
};

struct bucket_key
{
	uint32_t scope;
	uint32_t direction;
	uint64_t id;
};

struct limit_stats
{
	uint64_t pass_bytes;
	uint64_t drop_bytes;
	uint64_t pass_packets;
	uint64_t drop_packets;
};

struct shape_rule
{
	uint32_t classid;
	uint32_t direction;
};

static void sig_handler(int)
{
	running = false;
}

static void cleanup_tgid_cgroup()
{
	if (!g_last_tgid_cgroup_path.empty())
	{
		rmdir(g_last_tgid_cgroup_path.c_str());
	}
}

static int usage(FILE *out, int rc)
{
	fprintf(out, "Usage:\n");
	fprintf(
		out,
		"  net-limit load (--egress --dev <ifname> | --ingress [--attach-root "
		"auto|<cgroup-path>]) [--pin]\n"
	);
	fprintf(
		out,
		"                 [--rate <rate>] [--burst <bytes>] [--tgid "
		"<tgid>|--pid <pid>|--cgroup-path <path>|--cgroup-id <id>]\n"
	);
	fprintf(
		out,
		"  net-limit add (--tgid <tgid>|--pid <pid>|--cgroup-path "
		"<path>|--cgroup-id <id>) --rate <rate> (--egress --dev "
		"<ifname>|--ingress) [--burst <bytes>]\n"
	);
	fprintf(
		out,
		"  net-limit del (--tgid <tgid>|--pid <pid>|--cgroup-path "
		"<path>|--cgroup-id <id>) (--egress [--dev <ifname>]|--ingress)\n"
	);
	fprintf(out, "  net-limit list (--egress|--ingress)\n");
	fprintf(out, "  net-limit stats (--egress [--dev <ifname>]|--ingress)\n");
	fprintf(out, "  net-limit help\n");
	fprintf(out, "\nNote:\n");
	fprintf(
		out,
		"  Run 'net-limit load ... --pin' before add/del/list/stats.\n"
	);
	fprintf(
		out,
		"  The load command pins maps under /sys/fs/bpf and must keep "
		"running.\n"
	);
	fprintf(
		out,
		"\nRate units: B/s by default, K/M/G for bytes, or "
		"kbit/mbit/gbit/mbit/s.\n"
	);
	fprintf(
		out,
		"shape only supports egress; police mode only supports ingress.\n"
	);
	fprintf(
		out,
		"cgroup-path may be absolute under /sys/fs/cgroup, absolute inside "
		"cgroup v2, or relative.\n"
	);
	return rc;
}

static string trim(const string &s)
{
	size_t begin = 0;
	size_t end = s.size();
	while (begin < end && isspace((unsigned char)s[begin]))
	{
		begin++;
	}
	while (end > begin && isspace((unsigned char)s[end - 1]))
	{
		end--;
	}
	return s.substr(begin, end - begin);
}

static string decode_mountinfo_path(const string &path)
{
	string out;
	for (size_t i = 0; i < path.size(); i++)
	{
		if (path[i] == '\\' && i + 3 < path.size() && isdigit(path[i + 1]) &&
			isdigit(path[i + 2]) && isdigit(path[i + 3]))
		{
			int value = (path[i + 1] - '0') * 64 + (path[i + 2] - '0') * 8 +
						(path[i + 3] - '0');
			out.push_back((char)value);
			i += 3;
		}
		else
		{
			out.push_back(path[i]);
		}
	}
	return out;
}

static bool get_cgroup2_mount(string *mount)
{
	ifstream in("/proc/self/mountinfo");
	if (!in)
	{
		fprintf(stderr, "mountinfo挂载文件无法打开");
	}
	string line;
	while (getline(in, line))
	{
		size_t sep = line.find(" - ");
		if (sep == string::npos)
		{
			continue;
		}

		string pre = line.substr(0, sep);
		string post = line.substr(sep + 3);
		istringstream post_ss(post);
		string fstype;
		post_ss >> fstype;
		if (fstype != "cgroup2")
		{
			continue;
		}

		istringstream pre_ss(pre);
		string field;
		for (int i = 0; i < 5; i++)
		{
			if (!(pre_ss >> field))
			{
				return false;
			}
		}
		*mount = decode_mountinfo_path(field);
		return true;
	}
	return false;
}

static string join_path(const string &base, const string &sub)
{
	if (sub.empty() || sub == "/")
	{
		return base;
	}
	if (base.empty() || base == "/")
	{
		return "/" + sub;
	}
	if (base.back() == '/')
	{
		return base + (sub.front() == '/' ? sub.substr(1) : sub);
	}
	return base + "/" + (sub.front() == '/' ? sub.substr(1) : sub);
}

static bool resolve_cgroup_path(const string &input, string *resolved)
{
	string mount;
	struct stat st;

	if (!get_cgroup2_mount(&mount))
	{
		fprintf(stderr, "no cgroup2 mount found\n");
		return false;
	}

	if (input.empty() || input == "auto")
	{
		*resolved = mount;
	}
	else if (input.compare(0, mount.size(), mount) == 0 &&
			 (input.size() == mount.size() || input[mount.size()] == '/'))
	{
		*resolved = input;
	}
	else
	{
		*resolved = join_path(mount, input);
	}

	if (stat(resolved->c_str(), &st) != 0)
	{
		fprintf(
			stderr,
			"stat cgroup path %s failed: %s\n",
			resolved->c_str(),
			strerror(errno)
		);
		return false;
	}
	if (!S_ISDIR(st.st_mode))
	{
		fprintf(stderr, "%s is not a cgroup directory\n", resolved->c_str());
		return false;
	}
	return true;
}

static bool cgroup_id_from_path(const string &input, uint64_t *id)
{
	string resolved;
	struct stat st;

	if (!resolve_cgroup_path(input, &resolved))
	{
		return false;
	}
	if (stat(resolved.c_str(), &st) != 0)
	{
		fprintf(
			stderr,
			"stat cgroup path %s failed: %s\n",
			resolved.c_str(),
			strerror(errno)
		);
		return false;
	}
	*id = (uint64_t)st.st_ino;
	return true;
}

static bool ensure_dir(const string &path)
{
	struct stat st;
	if (stat(path.c_str(), &st) == 0)
	{
		return S_ISDIR(st.st_mode);
	}
	if (mkdir(path.c_str(), 0755) != 0)
	{
		fprintf(stderr, "mkdir %s failed: %s\n", path.c_str(), strerror(errno));
		return false;
	}
	return true;
}

static bool move_pid_to_cgroup(uint32_t pid, const string &cgroup_path)
{
	string procs = join_path(cgroup_path, "cgroup.procs");
	int fd = open(procs.c_str(), O_WRONLY | O_CLOEXEC);
	char buf[32];
	int len;
	ssize_t written;

	if (fd < 0)
	{
		fprintf(stderr, "open %s failed: %s\n", procs.c_str(), strerror(errno));
		return false;
	}
	len = snprintf(buf, sizeof(buf), "%u", pid);
	written = write(fd, buf, len);
	close(fd);
	if (written != len)
	{
		fprintf(
			stderr,
			"move pid %u to %s failed: %s\n",
			pid,
			cgroup_path.c_str(),
			strerror(errno)
		);
		return false;
	}
	return true;
}

static bool tgid_cgroup_path(uint32_t pid, string *path)
{
	string mount;
	string parent;

	if (!get_cgroup2_mount(&mount))
	{
		fprintf(stderr, "no cgroup2 mount found\n");
		return false;
	}
	parent = join_path(mount, "dkapture-net-limit");
	*path = join_path(parent, "tgid-" + to_string(pid));
	return true;
}

static bool
prepare_tgid_cgroup(uint32_t pid, uint64_t *cgid, string *resolved_path)
{
	string mount;
	string parent;
	string path;
	struct stat st;

	if (!get_cgroup2_mount(&mount))
	{
		fprintf(stderr, "no cgroup2 mount found\n");
		return false;
	}
	parent = join_path(mount, "dkapture-net-limit");
	path = join_path(parent, "tgid-" + to_string(pid));
	if (!ensure_dir(parent) || !ensure_dir(path))
	{
		return false;
	}
	if (!move_pid_to_cgroup(pid, path))
	{
		return false;
	}
	if (stat(path.c_str(), &st) != 0)
	{
		fprintf(stderr, "stat %s failed: %s\n", path.c_str(), strerror(errno));
		return false;
	}
	*cgid = (uint64_t)st.st_ino;
	*resolved_path = path;
	g_last_tgid_cgroup_path = path;
	return true;
}

static bool tgid_cgroup_id(uint32_t pid, uint64_t *cgid)
{
	string path;
	struct stat st;

	if (!tgid_cgroup_path(pid, &path))
	{
		return false;
	}
	if (stat(path.c_str(), &st) != 0)
	{
		fprintf(stderr, "stat %s failed: %s\n", path.c_str(), strerror(errno));
		return false;
	}
	*cgid = (uint64_t)st.st_ino;
	return true;
}

static bool cgroup_path_from_pid(uint32_t pid, string *path)
{
	char proc_path[64];
	snprintf(proc_path, sizeof(proc_path), "/proc/%u/cgroup", pid);
	ifstream in(proc_path);
	string line;

	while (getline(in, line))
	{
		size_t first = line.find(':');
		if (first == string::npos)
		{
			continue;
		}
		size_t second = line.find(':', first + 1);
		if (second == string::npos)
		{
			continue;
		}

		string controllers = line.substr(first + 1, second - first - 1);
		if (!controllers.empty())
		{
			continue;
		}

		*path = line.substr(second + 1);
		return true;
	}

	fprintf(stderr, "failed to read cgroup v2 path from %s\n", proc_path);
	return false;
}

static bool parse_u32(const char *s, uint32_t *value)
{
	char *end = nullptr;
	errno = 0;
	unsigned long v = strtoul(s, &end, 10);
	if (errno || end == s || *end || v > UINT32_MAX)
	{
		return false;
	}
	*value = (uint32_t)v;
	return true;
}

static bool parse_u64(const char *s, uint64_t *value)
{
	char *end = nullptr;
	errno = 0;
	unsigned long long v = strtoull(s, &end, 10);
	if (errno || end == s || *end)
	{
		return false;
	}
	*value = (uint64_t)v;
	return true;
}

static bool parse_size(const string &text, uint64_t *value)
{
	string s = trim(text);
	char *end = nullptr;
	double number;
	string unit;

	if (s.empty())
	{
		return false;
	}
	errno = 0;
	number = strtod(s.c_str(), &end);
	if (errno || end == s || number < 0)
	{
		return false;
	}
	unit = trim(end);
	transform(
		unit.begin(),
		unit.end(),
		unit.begin(),
		[](unsigned char c) { return (char)tolower(c); }
	);

	if (unit.empty() || unit == "b" || unit == "byte" || unit == "bytes")
	{
		*value = (uint64_t)number;
	}
	else if (unit == "k" || unit == "kb")
	{
		*value = (uint64_t)(number * 1024.0);
	}
	else if (unit == "m" || unit == "mb")
	{
		*value = (uint64_t)(number * 1024.0 * 1024.0);
	}
	else if (unit == "g" || unit == "gb")
	{
		*value = (uint64_t)(number * 1024.0 * 1024.0 * 1024.0);
	}
	else if (unit == "kbit" || unit == "kbits" || unit == "kbit/s" ||
			 unit == "kbps")
	{
		*value = (uint64_t)(number * 1000.0 / 8.0);
	}
	else if (unit == "mbit" || unit == "mbits" || unit == "mbit/s" ||
			 unit == "mbps")
	{
		*value = (uint64_t)(number * 1000.0 * 1000.0 / 8.0);
	}
	else if (unit == "gbit" || unit == "gbits" || unit == "gbit/s" ||
			 unit == "gbps")
	{
		*value = (uint64_t)(number * 1000.0 * 1000.0 * 1000.0 / 8.0);
	}
	else
	{
		return false;
	}

	return *value > 0;
}

static int ensure_pin_dir()
{
	mkdir("/sys/fs/bpf/dkapture", 0755);
	if (mkdir(PIN_DIR, 0755) != 0 && errno != EEXIST)
	{
		fprintf(stderr, "mkdir %s failed: %s\n", PIN_DIR, strerror(errno));
		return -1;
	}
	return 0;
}

static int open_pinned_map(const char *path)
{
	int fd = bpf_obj_get(path);
	if (fd < 0)
	{
		fprintf(
			stderr,
			"open pinned map %s failed: %s\n",
			path,
			strerror(errno)
		);
	}
	return fd;
}

static int reuse_pinned_map(struct bpf_map *map, const char *path)
{
	int fd = bpf_obj_get(path);
	int err;

	if (fd < 0)
	{
		if (errno == ENOENT)
		{
			return 0;
		}
		fprintf(
			stderr,
			"open pinned map %s failed: %s\n",
			path,
			strerror(errno)
		);
		return -1;
	}

	err = bpf_map__reuse_fd(map, fd);
	close(fd);
	if (err)
	{
		fprintf(stderr, "reuse pinned map %s failed: %d\n", path, err);
	}
	return err;
}

static int pin_map_if_missing(struct bpf_map *map, const char *path)
{
	int err;

	if (access(path, F_OK) == 0)
	{
		return 0;
	}
	err = bpf_map__pin(map, path);
	if (err)
	{
		fprintf(stderr, "pin map %s failed: %d\n", path, err);
	}
	return err;
}

static int prepare_pinned_maps(struct net_limit_bpf *skel)
{
	if (ensure_pin_dir() != 0)
	{
		return -1;
	}
	if (reuse_pinned_map(skel->maps.cgroup_rules, PIN_CGROUP_RULES) != 0)
	{
		return -1;
	}
	if (reuse_pinned_map(skel->maps.buckets, PIN_BUCKETS) != 0)
	{
		return -1;
	}
	if (reuse_pinned_map(skel->maps.stats, PIN_STATS) != 0)
	{
		return -1;
	}
	if (reuse_pinned_map(skel->maps.shape_rules, PIN_SHAPE_RULES) != 0)
	{
		return -1;
	}
	return 0;
}

static int pin_loaded_maps(struct net_limit_bpf *skel)
{
	if (pin_map_if_missing(skel->maps.cgroup_rules, PIN_CGROUP_RULES) != 0)
	{
		return -1;
	}
	if (pin_map_if_missing(skel->maps.buckets, PIN_BUCKETS) != 0)
	{
		return -1;
	}
	if (pin_map_if_missing(skel->maps.stats, PIN_STATS) != 0)
	{
		return -1;
	}
	if (pin_map_if_missing(skel->maps.shape_rules, PIN_SHAPE_RULES) != 0)
	{
		return -1;
	}
	return 0;
}

static const char *direction_name(uint32_t direction)
{
	if (direction == NET_LIMIT_EGRESS)
	{
		return "egress";
	}
	if (direction == NET_LIMIT_INGRESS)
	{
		return "ingress";
	}
	if (direction == (NET_LIMIT_EGRESS | NET_LIMIT_INGRESS))
	{
		return "both";
	}
	return "unknown";
}

static int update_cgroup_rule_map(
	uint64_t cgid,
	const struct limit_rule *rule,
	struct net_limit_bpf *skel
)
{
	int fd;

	if (skel)
	{
		fd = bpf_map__fd(skel->maps.cgroup_rules);
	}
	else
	{
		fd = open_pinned_map(PIN_CGROUP_RULES);
	}
	if (fd < 0)
	{
		return -1;
	}

	if (bpf_map_update_elem(fd, &cgid, rule, BPF_ANY) != 0)
	{
		perror("bpf_map_update_elem cgroup_rules");
		if (!skel)
		{
			close(fd);
		}
		return -1;
	}
	printf(
		"cgroup %llu limited: rate=%lluB/s burst=%lluB direction=%s\n",
		(unsigned long long)cgid,
		(unsigned long long)rule->rate_bps,
		(unsigned long long)rule->burst_bytes,
		direction_name(rule->direction)
	);

	if (!skel)
	{
		close(fd);
	}
	return 0;
}

static uint32_t shape_classid(uint32_t minor)
{
	return (1 << 16) | minor;
}

static string shape_classid_text(uint32_t classid)
{
	char buf[16];

	/* tc classid 的 major:minor 按十六进制解析，十进制 minor
	 * 可能被误认为超范围。 */
	snprintf(buf, sizeof(buf), "%x:%x", classid >> 16, classid & 0xffff);
	return buf;
}

static bool run_cmd(const string &cmd)
{
	int rc = system(cmd.c_str());

	if (rc == -1 || !WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
	{
		fprintf(stderr, "command failed: %s\n", cmd.c_str());
		return false;
	}
	return true;
}

static string shell_quote(const string &s)
{
	string out = "'";

	for (char c : s)
	{
		if (c == '\'')
		{
			out += "'\\''";
		}
		else
		{
			out.push_back(c);
		}
	}
	out += "'";
	return out;
}

static int shape_update_rule(uint64_t cgid, const struct shape_rule *rule)
{
	struct bucket_key key = {};
	int fd = open_pinned_map(PIN_SHAPE_RULES);

	if (fd < 0)
	{
		return -1;
	}
	key.scope = NET_LIMIT_SCOPE_CGROUP;
	key.direction = rule->direction;
	key.id = cgid;
	if (bpf_map_update_elem(fd, &key, rule, BPF_ANY) != 0)
	{
		perror("bpf_map_update_elem shape_rules");
		close(fd);
		return -1;
	}
	printf(
		"cgroup %llu shaped: classid=%s direction=%s\n",
		(unsigned long long)cgid,
		shape_classid_text(rule->classid).c_str(),
		direction_name(rule->direction)
	);
	close(fd);
	return 0;
}

static int shape_delete_rule(uint64_t cgid, uint32_t direction)
{
	struct bucket_key key = {};
	int fd = open_pinned_map(PIN_SHAPE_RULES);

	if (fd < 0)
	{
		return -1;
	}
	key.scope = NET_LIMIT_SCOPE_CGROUP;
	key.direction = direction;
	key.id = cgid;
	bpf_map_delete_elem(fd, &key);
	close(fd);
	return 0;
}

static bool shape_setup_htb(const string &dev)
{
	if (!run_cmd(
			"tc qdisc replace dev " + shell_quote(dev) +
			" root handle 1: htb default ffff"
		))
	{
		return false;
	}
	return run_cmd(
		"tc class replace dev " + shell_quote(dev) +
		" parent 1: classid 1:ffff htb rate 100gbit ceil 100gbit"
	);
}

static bool
shape_add_class(const string &dev, uint32_t classid, const string &rate)
{
	string classid_text = shape_classid_text(classid);
	string parent = to_string(classid >> 16) + ":";
	string tc_rate = trim(rate);
	string tc_rate_unit;
	char *end = nullptr;

	strtod(tc_rate.c_str(), &end);
	tc_rate_unit = trim(end ? end : "");
	transform(
		tc_rate_unit.begin(),
		tc_rate_unit.end(),
		tc_rate_unit.begin(),
		[](unsigned char c) { return (char)tolower(c); }
	);
	/* tc htb 不接受 10mbit/s 这种 /s 后缀，这里转换成 tc 支持的 10mbit。 */
	if (tc_rate_unit == "kbit/s" || tc_rate_unit == "mbit/s" ||
		tc_rate_unit == "gbit/s")
	{
		tc_rate.erase(tc_rate.size() - 2);
	}

	/* 每条规则对应一个 HTB class，BPF 只把 skb 分到这个 class。 */
	return run_cmd(
		"tc class replace dev " + shell_quote(dev) + " parent " + parent +
		" classid " + classid_text + " htb rate " + shell_quote(tc_rate) +
		" ceil " + shell_quote(tc_rate)
	);
}

static bool shape_del_class(const string &dev, uint32_t classid)
{
	return run_cmd(
		"tc class del dev " + shell_quote(dev) + " classid " +
		shape_classid_text(classid)
	);
}

static bool shape_show_classes(const string &dev)
{
	return run_cmd("tc -s class show dev " + shell_quote(dev));
}

static bool top_has_flag(int argc, char **argv, const char *flag)
{
	for (int i = 2; i < argc; i++)
	{
		if (strcmp(argv[i], flag) == 0)
		{
			return true;
		}
	}
	return false;
}

static char **shape_argv(int argc, char **argv, int *out_argc)
{
	char **out = (char **)calloc(argc + 2, sizeof(char *));

	if (!out)
	{
		return nullptr;
	}
	/* 顶层 egress 命令复用原 shape 内部实现：插入隐藏子命令名 shape。 */
	out[0] = argv[0];
	out[1] = (char *)"shape";
	out[2] = argv[1];
	for (int i = 2; i < argc; i++)
	{
		out[i + 1] = argv[i];
	}
	*out_argc = argc + 1;
	return out;
}

static int do_shape_load(int argc, char **argv)
{
	string dev = "lo";
	uint32_t direction = NET_LIMIT_EGRESS;
	net_limit_bpf *skel = nullptr;
	int ifindex;
	int err = 1;
	bool egress_attached = false;
	DECLARE_LIBBPF_OPTS(
		bpf_tc_hook,
		hook_egress,
		.ifindex = 0,
		.attach_point = BPF_TC_EGRESS
	);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_egress, .handle = 10, .priority = 1);

	static option opts[] = {
		{"dev",	required_argument, 0, 'd'},
		{"egress", no_argument,		0, 'e'},
		{"help",	 no_argument,		  0, 'h'},
		{0,		0,				 0, 0  },
	};

	optind = 3;
	while (true)
	{
		int opt = getopt_long(argc, argv, "d:eh", opts, nullptr);
		if (opt < 0)
		{
			break;
		}
		switch (opt)
		{
		case 'd':
			dev = optarg;
			break;
		case 'e':
			direction = NET_LIMIT_EGRESS;
			break;
		case 'h':
			usage(stdout, 0);
		default:
			return usage(stderr, 1);
		}
	}

	if (getuid() != 0)
	{
		fprintf(stderr, "must be root\n");
		return 1;
	}
	ifindex = if_nametoindex(dev.c_str());
	if (!ifindex)
	{
		fprintf(stderr, "invalid dev %s: %s\n", dev.c_str(), strerror(errno));
		return 1;
	}
	hook_egress.ifindex = ifindex;
	/* shape 只保留 egress；ingress 使用 cgroup_skb police，避免不可用的
	 * IFB/cgroup 组合。 */
	if (direction != NET_LIMIT_EGRESS)
	{
		return usage(stderr, 1);
	}
	if (!shape_setup_htb(dev))
	{
		return 1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	skel = net_limit_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "failed to open bpf object\n");
		return 1;
	}
	if (prepare_pinned_maps(skel) != 0)
	{
		goto out;
	}
	if (net_limit_bpf__load(skel) != 0)
	{
		fprintf(stderr, "failed to load bpf object\n");
		goto out;
	}
	if (pin_loaded_maps(skel) != 0)
	{
		goto out;
	}

	{
		int rc = bpf_tc_hook_create(&hook_egress);
		if (rc && rc != -EEXIST)
		{
			fprintf(
				stderr,
				"create egress tc hook failed: %s\n",
				strerror(-rc)
			);
			goto out;
		}
		/* 挂 tc/egress hook；BPF 设置 skb->priority，HTB 根据 classid 限速。 */
		opts_egress.prog_fd = bpf_program__fd(skel->progs.net_shape_egress);
		rc = bpf_tc_attach(&hook_egress, &opts_egress);
		if (rc && rc != -EEXIST)
		{
			fprintf(
				stderr,
				"attach egress tc program failed: %s\n",
				strerror(-rc)
			);
			goto out;
		}
		egress_attached = true;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	printf(
		"net-limit egress shape loaded on %s (%s), maps pinned\n",
		dev.c_str(),
		direction_name(direction)
	);
	printf("keep this process running; use add/del/list/stats --egress in "
		   "another shell\n");
	while (running)
	{
		sleep(1);
	}
	err = 0;

out:
	if (egress_attached)
	{
		opts_egress.flags = opts_egress.prog_fd = opts_egress.prog_id = 0;
		bpf_tc_detach(&hook_egress, &opts_egress);
	}
	if (skel)
	{
		net_limit_bpf__destroy(skel);
	}
	return err;
}

static int do_load(int argc, char **argv)
{
	if (top_has_flag(argc, argv, "--egress"))
	{
		int shape_argc;
		char **args = shape_argv(argc, argv, &shape_argc);
		int rc;

		if (!args)
		{
			return 1;
		}
		rc = do_shape_load(shape_argc, args);
		free(args);
		return rc;
	}

	string attach_root = "auto";
	string attach_path;
	string target_cgpath;
	uint32_t attach_direction = NET_LIMIT_INGRESS;
	uint32_t rule_direction = NET_LIMIT_INGRESS;
	uint32_t target_pid = 0;
	uint64_t target_cgid = 0;
	limit_rule initial_rule = {};
	bool has_target_pid = false;
	bool has_target_cgpath = false;
	bool has_target_cgid = false;
	bool has_rate = false;
	bool pin = false;
	int cgroup_fd = -1;
	bpf_link *ingress_link = nullptr;
	net_limit_bpf *skel = nullptr;
	int err = 1;

	static option opts[] = {
		{"attach-root", required_argument, 0, 'a'},
		{"tgid",		 required_argument, 0, 't'},
		{"pid",			required_argument, 0, 'P'},
		{"cgroup-path", required_argument, 0, 'c'},
		{"cgroup-id",	  required_argument, 0, 'C'},
		{"rate",		 required_argument, 0, 'r'},
		{"burst",		  required_argument, 0, 'B'},
		{"ingress",		no_argument,		 0, 'i'},
		{"pin",			no_argument,		 0, 'p'},
		{"help",		 no_argument,		  0, 'h'},
		{0,			 0,				 0, 0  },
	};

	optind = 2;
	while (true)
	{
		int opt = getopt_long(argc, argv, "a:t:P:c:C:r:B:iph", opts, nullptr);
		if (opt < 0)
		{
			break;
		}
		switch (opt)
		{
		case 'a':
			attach_root = optarg;
			break;
		case 't':
		case 'P':
			if (!parse_u32(optarg, &target_pid) || target_pid == 0)
			{
				fprintf(stderr, "invalid tgid/pid: %s\n", optarg);
				return usage(stderr, 1);
			}
			has_target_pid = true;
			break;
		case 'c':
			target_cgpath = optarg;
			has_target_cgpath = true;
			break;
		case 'C':
			if (!parse_u64(optarg, &target_cgid) || target_cgid == 0)
			{
				fprintf(stderr, "invalid cgroup id: %s\n", optarg);
				return usage(stderr, 1);
			}
			has_target_cgid = true;
			break;
		case 'r':
			if (!parse_size(optarg, &initial_rule.rate_bps))
			{
				fprintf(stderr, "invalid rate: %s\n", optarg);
				return usage(stderr, 1);
			}
			has_rate = true;
			break;
		case 'B':
			if (!parse_size(optarg, &initial_rule.burst_bytes))
			{
				fprintf(stderr, "invalid burst: %s\n", optarg);
				return usage(stderr, 1);
			}
			break;
		case 'i':
			attach_direction = NET_LIMIT_INGRESS;
			rule_direction = NET_LIMIT_INGRESS;
			break;
		case 'p':
			pin = true;
			break;
		case 'h':
			return usage(stdout, 0);
		default:
			return usage(stderr, 1);
		}
	}
	if ((int)has_target_pid + (int)has_target_cgpath + (int)has_target_cgid > 1)
	{
		fprintf(
			stderr,
			"specify at most one initial target: --tgid/--pid, --cgroup-path, "
			"or --cgroup-id\n"
		);
		return usage(stderr, 1);
	}
	if (has_rate != (has_target_pid || has_target_cgpath || has_target_cgid))
	{
		fprintf(
			stderr,
			"load initial rule requires both --rate and one target\n"
		);
		return usage(stderr, 1);
	}
	if (has_target_cgpath && !cgroup_id_from_path(target_cgpath, &target_cgid))
	{
		return 1;
	}
	initial_rule.direction = rule_direction;
	if (initial_rule.burst_bytes == 0 && initial_rule.rate_bps > 0)
	{
		initial_rule.burst_bytes = initial_rule.rate_bps;
	}

	if (getuid() != 0)
	{
		fprintf(stderr, "must be root\n");
		return 1;
	}
	if (has_target_pid)
	{
		string resolved;
		if (!prepare_tgid_cgroup(target_pid, &target_cgid, &resolved))
		{
			return 1;
		}
		printf("tgid %u moved to %s\n", target_pid, resolved.c_str());
	}
	if (!resolve_cgroup_path(attach_root, &attach_path))
	{
		return 1;
	}

	cgroup_fd = open(attach_path.c_str(), O_RDONLY | O_DIRECTORY);
	if (cgroup_fd < 0)
	{
		fprintf(
			stderr,
			"open cgroup %s failed: %s\n",
			attach_path.c_str(),
			strerror(errno)
		);
		return 1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	skel = net_limit_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "failed to open bpf object\n");
		goto out;
	}
	if (pin && prepare_pinned_maps(skel) != 0)
	{
		goto out;
	}
	if (net_limit_bpf__load(skel) != 0)
	{
		fprintf(stderr, "failed to load bpf object\n");
		goto out;
	}

	if (pin)
	{
		if (pin_loaded_maps(skel) != 0)
		{
			goto out;
		}
	}

	/* police 模式精简为 ingress-only，egress 平滑限速由 shape 模式处理。 */
	ingress_link =
		bpf_program__attach_cgroup(skel->progs.net_limit_ingress, cgroup_fd);
	if (!ingress_link)
	{
		fprintf(
			stderr,
			"attach ingress to %s failed: %s\n",
			attach_path.c_str(),
			strerror(errno)
		);
		goto out;
	}
	if (has_rate)
	{
		if (update_cgroup_rule_map(target_cgid, &initial_rule, skel) != 0)
		{
			goto out;
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	printf(
		"net-limit loaded on %s (%s)%s\n",
		attach_path.c_str(),
		direction_name(attach_direction),
		pin ? ", maps pinned" : ""
	);
	printf("keep this process running; use add/del/list/stats in another "
		   "shell\n");
	while (running)
	{
		sleep(1);
	}
	err = 0;

out:
	cleanup_tgid_cgroup();
	if (ingress_link)
	{
		bpf_link__destroy(ingress_link);
	}
	if (skel)
	{
		net_limit_bpf__destroy(skel);
	}
	if (cgroup_fd >= 0)
	{
		close(cgroup_fd);
	}
	return err;
}

static int parse_target_options(
	int argc,
	char **argv,
	uint64_t *cgid,
	bool move_tgid,
	bool need_rule,
	struct limit_rule *rule
)
{
	string cgpath;
	uint32_t pid = 0;
	bool has_tgid = false;
	bool has_cgid = false;
	bool has_cgpath = false;
	bool has_rate = false;
	uint32_t direction = NET_LIMIT_INGRESS;

	static option opts[] = {
		{"tgid",		 required_argument, 0, 't'},
		{"pid",			required_argument, 0, 'p'},
		{"cgroup-path", required_argument, 0, 'c'},
		{"cgroup-id",	  required_argument, 0, 'C'},
		{"rate",		 required_argument, 0, 'r'},
		{"burst",		  required_argument, 0, 'B'},
		{"ingress",		no_argument,		 0, 'i'},
		{"help",		 no_argument,		  0, 'h'},
		{0,			 0,				 0, 0  },
	};

	*cgid = 0;
	if (rule)
	{
		memset(rule, 0, sizeof(*rule));
	}

	optind = 2;
	while (true)
	{
		int opt = getopt_long(argc, argv, "t:p:c:C:r:B:ih", opts, nullptr);
		if (opt < 0)
		{
			break;
		}
		switch (opt)
		{
		case 't':
		case 'p':
			if (!parse_u32(optarg, &pid) || pid == 0)
			{
				fprintf(stderr, "invalid pid: %s\n", optarg);
				return -1;
			}
			has_tgid = true;
			break;
		case 'c':
			cgpath = optarg;
			has_cgpath = true;
			break;
		case 'C':
			if (!parse_u64(optarg, cgid) || *cgid == 0)
			{
				fprintf(stderr, "invalid cgroup id: %s\n", optarg);
				return -1;
			}
			has_cgid = true;
			break;
		case 'r':
			if (!need_rule || !parse_size(optarg, &rule->rate_bps))
			{
				fprintf(stderr, "invalid rate: %s\n", optarg);
				return -1;
			}
			has_rate = true;
			break;
		case 'B':
			if (!need_rule || !parse_size(optarg, &rule->burst_bytes))
			{
				fprintf(stderr, "invalid burst: %s\n", optarg);
				return -1;
			}
			break;
		case 'i':
			direction = NET_LIMIT_INGRESS;
			break;
		case 'h':
			return usage(stdout, 0);
		default:
			return -1;
		}
	}

	if ((int)has_tgid + (int)has_cgpath + (int)has_cgid != 1)
	{
		fprintf(
			stderr,
			"specify exactly one target: --pid, --cgroup-path, or --cgroup-id\n"
		);
		return -1;
	}
	if (need_rule && !has_rate)
	{
		fprintf(stderr, "--rate is required\n");
		return -1;
	}

	if (has_tgid && move_tgid)
	{
		string resolved;
		struct stat st;
		char proc_path[64];
		snprintf(proc_path, sizeof(proc_path), "/proc/%u", pid);
		if (stat(proc_path, &st) != 0)
		{
			fprintf(
				stderr,
				"target pid %u does not exist: %s\n",
				pid,
				strerror(errno)
			);
			return -1;
		}
		if (getuid() != 0)
		{
			fprintf(stderr, "must be root to move tgid %u into cgroup\n", pid);
			return -1;
		}
		if (!prepare_tgid_cgroup(pid, cgid, &resolved))
		{
			return -1;
		}
		printf("tgid %u moved to %s\n", pid, resolved.c_str());
	}
	else if (has_tgid)
	{
		if (!tgid_cgroup_id(pid, cgid))
		{
			return -1;
		}
	}
	if (has_cgpath && !cgroup_id_from_path(cgpath, cgid))
	{
		return -1;
	}
	if (rule)
	{
		rule->direction = direction;
		if (rule->burst_bytes == 0 && rule->rate_bps > 0)
		{
			rule->burst_bytes = rule->rate_bps;
		}
	}
	return NET_LIMIT_SCOPE_CGROUP;
}

static int parse_shape_target_options(
	int argc,
	char **argv,
	uint64_t *cgid,
	uint32_t *direction,
	string *dev,
	string *rate,
	bool move_tgid,
	bool need_rate
)
{
	string cgpath;
	uint32_t pid = 0;
	bool has_tgid = false;
	bool has_cgid = false;
	bool has_cgpath = false;
	bool has_rate = false;
	struct stat st;

	static option opts[] = {
		{"tgid",		 required_argument, 0, 't'},
		{"pid",			required_argument, 0, 'p'},
		{"cgroup-path", required_argument, 0, 'c'},
		{"cgroup-id",	  required_argument, 0, 'C'},
		{"rate",		 required_argument, 0, 'r'},
		{"dev",			required_argument, 0, 'd'},
		{"egress",	   no_argument,		0, 'e'},
		{"help",		 no_argument,		  0, 'h'},
		{0,			 0,				 0, 0  },
	};

	*cgid = 0;
	*direction = NET_LIMIT_EGRESS;
	*dev = "lo";
	rate->clear();
	optind = 3;
	while (true)
	{
		int opt = getopt_long(argc, argv, "t:p:c:C:r:d:eh", opts, nullptr);
		if (opt < 0)
		{
			break;
		}
		switch (opt)
		{
		case 't':
		case 'p':
			if (!parse_u32(optarg, &pid) || pid == 0)
			{
				fprintf(stderr, "invalid pid: %s\n", optarg);
				return -1;
			}
			has_tgid = true;
			break;
		case 'c':
			cgpath = optarg;
			has_cgpath = true;
			break;
		case 'C':
			if (!parse_u64(optarg, cgid) || *cgid == 0)
			{
				fprintf(stderr, "invalid cgroup id: %s\n", optarg);
				return -1;
			}
			has_cgid = true;
			break;
		case 'r':
			*rate = optarg;
			has_rate = true;
			break;
		case 'd':
			*dev = optarg;
			break;
		case 'e':
			*direction = NET_LIMIT_EGRESS;
			break;
		case 'h':
			return usage(stdout, 0);
		default:
			return -1;
		}
	}

	if ((int)has_tgid + (int)has_cgpath + (int)has_cgid != 1)
	{
		fprintf(
			stderr,
			"specify exactly one target: --pid, --cgroup-path, or --cgroup-id\n"
		);
		return -1;
	}
	if (need_rate && !has_rate)
	{
		fprintf(stderr, "--rate is required\n");
		return -1;
	}
	if (has_tgid && move_tgid)
	{
		string resolved;
		char proc_path[64];
		snprintf(proc_path, sizeof(proc_path), "/proc/%u", pid);
		if (stat(proc_path, &st) != 0)
		{
			fprintf(
				stderr,
				"target pid %u does not exist: %s\n",
				pid,
				strerror(errno)
			);
			return -1;
		}
		if (getuid() != 0)
		{
			fprintf(stderr, "must be root to move tgid %u into cgroup\n", pid);
			return -1;
		}
		if (!prepare_tgid_cgroup(pid, cgid, &resolved))
		{
			return -1;
		}
		printf("tgid %u moved to %s\n", pid, resolved.c_str());
	}
	else if (has_tgid)
	{
		if (!tgid_cgroup_id(pid, cgid))
		{
			return -1;
		}
	}
	if (has_cgpath && !cgroup_id_from_path(cgpath, cgid))
	{
		return -1;
	}
	return NET_LIMIT_SCOPE_CGROUP;
}

static int do_shape_add(int argc, char **argv)
{
	uint64_t cgid;
	uint32_t direction;
	string dev;
	string rate;
	shape_rule rule = {};
	int scope = parse_shape_target_options(
		argc,
		argv,
		&cgid,
		&direction,
		&dev,
		&rate,
		true,
		true
	);

	if (scope < 0)
	{
		return usage(stderr, 1);
	}
	rule.direction = direction;
	/* cgroup id 低 16 位作为 class minor，保证同一 cgroup 得到稳定 classid。 */
	rule.classid = shape_classid((uint32_t)(cgid & 0xffff));
	if ((rule.classid & 0xffff) == 0 || (rule.classid & 0xffff) == 0xffff)
	{
		rule.classid = shape_classid(10);
	}
	if (!shape_add_class(dev, rule.classid, rate))
	{
		return 1;
	}
	return shape_update_rule(cgid, &rule) == 0 ? 0 : 1;
}

static int do_shape_del(int argc, char **argv)
{
	uint64_t cgid;
	uint32_t direction;
	string dev;
	string rate;
	uint32_t classid;
	int scope = parse_shape_target_options(
		argc,
		argv,
		&cgid,
		&direction,
		&dev,
		&rate,
		false,
		false
	);

	if (scope < 0)
	{
		return usage(stderr, 1);
	}
	classid = shape_classid((uint32_t)(cgid & 0xffff));
	if ((classid & 0xffff) == 0 || (classid & 0xffff) == 0xffff)
	{
		classid = shape_classid(10);
	}
	shape_delete_rule(cgid, direction);
	if (!shape_del_class(dev, classid))
	{
		fprintf(
			stderr,
			"tc class %s was absent or could not be deleted\n",
			shape_classid_text(classid).c_str()
		);
	}
	printf("cgroup %llu shape rule deleted\n", (unsigned long long)cgid);
	return 0;
}

static int do_shape_list()
{
	int fd = open_pinned_map(PIN_SHAPE_RULES);
	struct bucket_key key, next;
	struct shape_rule rule;

	if (fd < 0)
	{
		return 1;
	}
	printf("Shape rules:\n");
	int rc = bpf_map_get_next_key(fd, nullptr, &key);
	while (rc == 0)
	{
		if (bpf_map_lookup_elem(fd, &key, &rule) == 0)
		{
			printf(
				"cgroup %-10llu classid=%s direction=%s\n",
				(unsigned long long)key.id,
				shape_classid_text(rule.classid).c_str(),
				direction_name(rule.direction)
			);
		}
		rc = bpf_map_get_next_key(fd, &key, &next);
		if (rc == 0)
		{
			key = next;
		}
	}
	close(fd);
	return 0;
}

static int do_shape_stats(int argc, char **argv)
{
	string dev = "lo";
	static option opts[] = {
		{"dev",	required_argument, 0, 'd'},
		{"egress", no_argument,		0, 'e'},
		{"help",	 no_argument,		  0, 'h'},
		{0,		0,				 0, 0  },
	};

	optind = 3;
	while (true)
	{
		int opt = getopt_long(argc, argv, "d:eh", opts, nullptr);
		if (opt < 0)
		{
			break;
		}
		switch (opt)
		{
		case 'd':
			dev = optarg;
			break;
		case 'e':
			break;
		case 'h':
			return usage(stdout, 0);
		default:
			return usage(stderr, 1);
		}
	}
	return shape_show_classes(dev) ? 0 : 1;
}

static int do_add(int argc, char **argv)
{
	if (top_has_flag(argc, argv, "--egress"))
	{
		int shape_argc;
		char **args = shape_argv(argc, argv, &shape_argc);
		int rc;

		if (!args)
		{
			return 1;
		}
		rc = do_shape_add(shape_argc, args);
		free(args);
		return rc;
	}

	uint64_t cgid;
	limit_rule rule;
	int scope = parse_target_options(argc, argv, &cgid, true, true, &rule);

	if (scope < 0)
	{
		usage(stderr, 1);
	}
	if (update_cgroup_rule_map(cgid, &rule, nullptr) != 0)
	{
		return 1;
	}
	return 0;
}

static int delete_stats_for_target(uint32_t scope, uint64_t id)
{
	int fd = open_pinned_map(PIN_STATS);
	bucket_key key, next;
	if (fd < 0)
	{
		return 0;
	}

	int rc = bpf_map_get_next_key(fd, nullptr, &key);
	while (rc == 0)
	{
		bool match = key.scope == scope && key.id == id;
		rc = bpf_map_get_next_key(fd, &key, &next);
		if (match)
		{
			bpf_map_delete_elem(fd, &key);
		}
		if (rc == 0)
		{
			key = next;
		}
	}
	close(fd);
	return 0;
}

static int delete_buckets_for_target(uint32_t scope, uint64_t id)
{
	int fd = open_pinned_map(PIN_BUCKETS);
	bucket_key key, next;
	if (fd < 0)
	{
		return 0;
	}

	int rc = bpf_map_get_next_key(fd, nullptr, &key);
	while (rc == 0)
	{
		bool match = key.scope == scope && key.id == id;
		rc = bpf_map_get_next_key(fd, &key, &next);
		if (match)
		{
			bpf_map_delete_elem(fd, &key);
		}
		if (rc == 0)
		{
			key = next;
		}
	}
	close(fd);
	return 0;
}

static int do_del(int argc, char **argv)
{
	if (top_has_flag(argc, argv, "--egress"))
	{
		int shape_argc;
		char **args = shape_argv(argc, argv, &shape_argc);
		int rc;

		if (!args)
		{
			return 1;
		}
		rc = do_shape_del(shape_argc, args);
		free(args);
		return rc;
	}

	uint64_t cgid;
	int scope = parse_target_options(argc, argv, &cgid, false, false, nullptr);
	int fd;
	int rc;

	if (scope < 0)
	{
		return usage(stderr, 1);
	}
	fd = open_pinned_map(PIN_CGROUP_RULES);
	if (fd < 0)
	{
		return 1;
	}

	rc = bpf_map_delete_elem(fd, &cgid);
	delete_buckets_for_target(NET_LIMIT_SCOPE_CGROUP, cgid);
	delete_stats_for_target(NET_LIMIT_SCOPE_CGROUP, cgid);
	printf(
		"cgroup %llu rule deleted%s\n",
		(unsigned long long)cgid,
		rc ? " (rule was absent)" : ""
	);
	close(fd);
	return 0;
}

static void list_rule_map(int fd, uint32_t scope)
{
	limit_rule rule;
	uint64_t key, next;
	int rc = bpf_map_get_next_key(fd, nullptr, &key);
	(void)scope;
	while (rc == 0)
	{
		if (bpf_map_lookup_elem(fd, &key, &rule) == 0)
		{
			printf(
				"cgroup %-10llu rate=%lluB/s burst=%lluB direction=%s\n",
				(unsigned long long)key,
				(unsigned long long)rule.rate_bps,
				(unsigned long long)rule.burst_bytes,
				direction_name(rule.direction)
			);
		}
		rc = bpf_map_get_next_key(fd, &key, &next);
		if (rc == 0)
		{
			key = next;
		}
	}
}

static int do_list(int argc, char **argv)
{
	if (top_has_flag(argc, argv, "--egress"))
	{
		return do_shape_list();
	}

	int cg_fd = open_pinned_map(PIN_CGROUP_RULES);
	if (cg_fd < 0)
	{
		return 1;
	}

	printf("Cgroup rules:\n");
	list_rule_map(cg_fd, NET_LIMIT_SCOPE_CGROUP);
	close(cg_fd);
	return 0;
}

static int do_stats(int argc, char **argv)
{
	if (top_has_flag(argc, argv, "--egress"))
	{
		int shape_argc;
		char **args = shape_argv(argc, argv, &shape_argc);
		int rc;

		if (!args)
		{
			return 1;
		}
		rc = do_shape_stats(shape_argc, args);
		free(args);
		return rc;
	}

	int fd = open_pinned_map(PIN_STATS);
	bucket_key key, next;
	limit_stats s;

	if (fd < 0)
	{
		return 1;
	}

	printf(
		"%-8s %-12s %-8s %-14s %-14s %-14s %-14s\n",
		"scope",
		"id",
		"dir",
		"pass_bytes",
		"drop_bytes",
		"pass_pkts",
		"drop_pkts"
	);
	int rc = bpf_map_get_next_key(fd, nullptr, &key);
	while (rc == 0)
	{
		if (bpf_map_lookup_elem(fd, &key, &s) == 0)
		{
			printf(
				"%-8s %-12llu %-8s %-14llu %-14llu %-14llu %-14llu\n",
				"cgroup",
				(unsigned long long)key.id,
				direction_name(key.direction),
				(unsigned long long)s.pass_bytes,
				(unsigned long long)s.drop_bytes,
				(unsigned long long)s.pass_packets,
				(unsigned long long)s.drop_packets
			);
		}
		rc = bpf_map_get_next_key(fd, &key, &next);
		if (rc == 0)
		{
			key = next;
		}
	}
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		return usage(stderr, 1);
	}

	string cmd = argv[1];
	if (cmd == "load")
	{
		return do_load(argc, argv);
	}
	if (cmd == "add")
	{
		return do_add(argc, argv);
	}
	if (cmd == "del")
	{
		return do_del(argc, argv);
	}
	if (cmd == "list")
	{
		return do_list(argc, argv);
	}
	if (cmd == "stats")
	{
		return do_stats(argc, argv);
	}
	if (cmd == "help")
	{
		return usage(stdout, 0);
	}
	return usage(stderr, 1);
}
