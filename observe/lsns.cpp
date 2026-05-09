// SPDX-FileCopyrightText: 2026
// SPDX-License-Identifier: LGPL-2.1

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <numeric>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <sys/stat.h>
#include <sys/types.h>
#include <atomic>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pwd.h>

struct ns_key_t
{
	uint32_t type;
	uint64_t inum;
};

struct ns_owner_t
{
	uint32_t pid;
	uint32_t uid;
	uint32_t procs;
};

// Proc info for building process tree per-namespace
struct ProcInfo
{
	int pid;  // tgid
	int ppid; // parent's pid (usually parent's tgid)
	uint32_t uid;
	std::string cmd;
};
static std::atomic<bool> exit_flag(false);
static bool json_output = false;
static struct option lopts[] = {
	{"json", no_argument, 0, 'J'},
	{"help", no_argument, 0, 'h'},
	{0,		0,		   0, 0  },
};

// Structure for help messages
struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg;	  // Help message
};

// Help messages
static HelpMsg help_msg[] = {
	{"", "use JSON output format"	 },
	{"", "print this help message\n"},
};

// Convert long options to short options string
std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts = "";
	for (int i = 0; lopts[i].name; i++)
	{
		sopts += lopts[i].val; // Add short option character
		switch (lopts[i].has_arg)
		{
		case no_argument:
			break;
		case required_argument:
			sopts += ":"; // Required argument
			break;
		case optional_argument:
			sopts += "::"; // Optional argument
			break;
		default:
			std::cerr << "Code internal bug!!!\n";
			std::abort();
		}
	}
	return sopts;
}

void Usage(const char *arg0)
{
	printf("Usage:\n  %s [option] [<namespace>]\n", arg0);
	printf("list the Linux namespaces that the system is using\n\n");
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

// Parse command line arguments
void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'J': // JSON output
			json_output = true;
			break;
		case 'h': // Help
			Usage(argv[0]);
			exit(0);
			break;
		default: // Invalid option
			Usage(argv[0]);
			exit(-1);
			break;
		}
	}
}

void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; }; // Set exit flag on signal
	sa.sa_flags = 0;							   // No special flags
	sigemptyset(&sa.sa_mask); // No additional signals to block
	// Register the signal handler for SIGINT
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

// helper: read first token from /proc/<pid>/cmdline or fallback to
// /proc/<pid>/comm
static std::string read_proc_cmd(int pid)
{
	char path[256];
	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	FILE *f = fopen(path, "r");
	if (f)
	{
		std::string s;
		std::vector<char> buf(4096);
		size_t n = fread(buf.data(), 1, buf.size() - 1, f);
		fclose(f);
		if (n > 0)
		{
			// cmdline is NUL-separated; convert inner NULs to spaces to show
			// args
			buf[n] = '\0';
			for (size_t i = 0; i < n; ++i)
			{
				if (buf[i] == '\0')
				{
					buf[i] = ' ';
				}
			}
			// strip any trailing spaces
			while (n > 0 && buf[n - 1] == ' ')
			{
				buf[n - 1] = '\0';
				--n;
			}
			s = std::string(buf.data());
			if (!s.empty())
			{
				return s;
			}
		}
	}
	// fallback to comm
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");
	if (f)
	{
		char buf[256];
		if (fgets(buf, sizeof(buf), f))
		{
			fclose(f);
			// strip newline
			char *nl = strchr(buf, '\n');
			if (nl)
			{
				*nl = '\0';
			}
			return std::string(buf);
		}
		fclose(f);
	}
	return std::string("[") + std::to_string(pid) + "]";
}

// Parse PPid and Uid from /proc/<pid>/status
// Read PPid, Uid and Tgid from /proc/<pid>/status. Returns tgid via tgid_out.
static void
read_proc_ppid_uid(int pid, int &ppid_out, uint32_t &uid_out, int &tgid_out)
{
	ppid_out = 0;
	uid_out = 0;
	tgid_out = pid;
	char path[256];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	FILE *f = fopen(path, "r");
	if (!f)
	{
		return;
	}
	char line[512];
	while (fgets(line, sizeof(line), f))
	{
		if (strncmp(line, "PPid:", 5) == 0)
		{
			int p = 0;
			if (sscanf(line + 5, "%d", &p) == 1)
			{
				ppid_out = p;
			}
		}
		else if (strncmp(line, "Uid:", 4) == 0)
		{
			int u = 0;
			if (sscanf(line + 4, "%d", &u) == 1)
			{
				uid_out = (uint32_t)u;
			}
		}
		else if (strncmp(line, "Tgid:", 5) == 0)
		{
			int t = 0;
			if (sscanf(line + 5, "%d", &t) == 1)
			{
				tgid_out = t;
			}
		}
	}
	fclose(f);
}

// Scan /proc once and build a mapping key="type:inum" -> vector<ProcInfo>
static std::unordered_map<std::string, std::vector<ProcInfo>> scan_procs_by_ns()
{
	std::unordered_map<std::string, std::vector<ProcInfo>> m;
	DIR *d = opendir("/proc");
	if (!d)
	{
		return m;
	}
	struct dirent *de;
	char ns_path[256];
	const char *proc_names[10] = {
		"unknown",
		"user",
		"ipc",
		"mnt",
		"pid",
		"net",
		"uts",
		"time",
		"cgroup",
		"pid"
	};
	struct stat st;
	// We'll check the common namespace types 1..9
	for (;;)
	{
		de = readdir(d);
		if (!de)
		{
			break;
		}
		char *endptr;
		long pid = strtol(de->d_name, &endptr, 10);
		if (*endptr != '\0')
		{
			continue;
		}
		// for each ns type
		for (uint32_t t = 1; t <= 9; ++t)
		{
			const char *procname = proc_names[t];
			if (!procname)
			{
				continue;
			}
			snprintf(
				ns_path,
				sizeof(ns_path),
				"/proc/%ld/ns/%s",
				pid,
				procname
			);
			if (stat(ns_path, &st) != 0)
			{
				continue;
			}
			uint64_t inum = st.st_ino;
			std::string key = std::to_string(t) + ":" + std::to_string(inum);
			// Read status to get Tgid/PPid/Uid. We only want thread-group
			// leaders (tgid == pid)
			int ppid = 0;
			uint32_t uid = 0;
			int tgid = 0;
			read_proc_ppid_uid((int)pid, ppid, uid, tgid);
			if (tgid != (int)pid)
			{
				continue; // skip threads; only include TGID entries
			}
			ProcInfo pi;
			pi.pid = tgid; // leader id
			pi.ppid = ppid;
			pi.uid = uid;
			pi.cmd = read_proc_cmd((int)tgid);
			m[key].push_back(pi);
		}
	}
	closedir(d);
	// sort pid lists for deterministic order
	for (auto &kv : m)
	{
		auto &vec = kv.second;
		std::sort(
			vec.begin(),
			vec.end(),
			[](const ProcInfo &a, const ProcInfo &b) { return a.pid < b.pid; }
		);
	}
	return m;
}

// Print process tree rooted at owner_pid using the given proc list mapped by
// pid
static void print_tree_aligned(
	int owner_pid,
	const std::vector<ProcInfo> &procs,
	int pad_width
)
{
	std::unordered_map<int, std::vector<int>> children;
	std::unordered_map<int, std::string> cmd;
	for (const auto &p : procs)
	{
		cmd[p.pid] = p.cmd;
		children[p.ppid].push_back(p.pid);
	}
	for (auto &kv : children)
	{
		std::sort(kv.second.begin(), kv.second.end());
	}

	// recursive helper defined as a static function to avoid std::function
	// overhead
	std::function<void(int, const std::string &, bool)> printer =
		[&](int pid, const std::string &prefix, bool is_last)
	{
		std::string line = prefix + (is_last ? "└─" : "├─") +
						   (cmd.count(pid) ? cmd[pid] : std::to_string(pid));
		std::cout << std::left << std::setw(pad_width) << "" << line << "\n";
		auto it = children.find(pid);
		if (it == children.end())
		{
			return;
		}
		const auto &ch = it->second;
		for (size_t i = 0; i < ch.size(); ++i)
		{
			bool last = (i + 1 == ch.size());
			std::string child_prefix = prefix + (is_last ? "   " : "│  ");
			printer(ch[i], child_prefix, last);
		}
	};

	// start from children of owner_pid (owner already printed as header)
	auto it = children.find(owner_pid);
	if (it == children.end())
	{
		return;
	}
	const auto &root_children = it->second;
	for (size_t i = 0; i < root_children.size(); ++i)
	{
		bool last = (i + 1 == root_children.size());
		printer(root_children[i], std::string(), last);
	}
}
// return a human display name for the namespace type
static const char *ns_display_name(uint32_t t)
{
	switch (t)
	{
	case 1:
		return "user";
	case 2:
		return "ipc";
	case 3:
		return "mnt";
	case 4:
		return "pid";
	case 5:
		return "net";
	case 6:
		return "uts";
	case 7:
		return "time";
	case 8:
		return "cgroup";
	case 9:
		return "pid_for_children";
	default:
		return "unknown";
	}
}

// return the filename used under /proc/[pid]/ns/ for this namespace
// some internal kernel variants (eg pid_for_children) map to the same
// proc name as pid
static const char *ns_proc_name(uint32_t t)
{
	switch (t)
	{
	case 1:
		return "user";
	case 2:
		return "ipc";
	case 3:
		return "mnt";
	case 4:
		return "pid";
	case 5:
		return "net";
	case 6:
		return "uts";
	case 7:
		return "time";
	case 8:
		return "cgroup";
	case 9:
		return "pid"; // pid_for_children appears as "pid" in /proc
	default:
		return "unknown";
	}
}

// try to find a pid that owns the namespace in /proc
static int
find_owner_pid_for_ns(uint64_t inum, const char *nstype, time_t *ctime_out)
{
	DIR *d = opendir("/proc");
	if (!d)
	{
		return -1;
	}
	struct dirent *de;
	char path[256];
	struct stat st;
	int found = -1;
	while ((de = readdir(d)) != NULL)
	{
		// some filesystems return DT_UNKNOWN; don't rely on d_type
		// skip non-numeric
		char *endptr;
		long pid = strtol(de->d_name, &endptr, 10);
		if (*endptr != '\0')
		{
			continue;
		}
		snprintf(path, sizeof(path), "/proc/%s/ns/%s", de->d_name, nstype);
		if (stat(path, &st) == 0)
		{
			if ((uint64_t)st.st_ino == inum)
			{
				found = (int)pid;
				if (ctime_out)
				{
					*ctime_out = st.st_ctime;
				}
				break;
			}
		}
	}
	closedir(d);
	return found;
}

static int bump_memlock_rlimit()
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	if (setrlimit(RLIMIT_MEMLOCK, &r))
	{
		perror("setrlimit");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{

	if (bump_memlock_rlimit())
	{
		return 1;
	}

	libbpf_set_print(NULL);

	const char *candidates[] = {
		"bpf/observe/lsns.bpf.o",
		"bpf/build/observe/lsns.bpf.o",
		"/usr/lib/dkapture/lsns.bpf.o",
		NULL
	};
	parse_args(argc, argv);
	register_signal();
	struct bpf_object *obj = nullptr;
	int err = 0;
	for (const char **p = candidates; *p; ++p)
	{
		obj = bpf_object__open_file(*p, NULL);
		if (obj)
		{
			if ((err = bpf_object__load(obj)) == 0)
			{
				std::cerr << "loaded BPF object: " << *p << "\n";
				break;
			}
			bpf_object__close(obj);
			obj = nullptr;
		}
	}
	if (!obj)
	{
		std::cerr << "failed to open/load BPF object. build the .bpf.o "
					 "first.\n";
		std::cerr << "Try: make -C bpf/observe && make -C observe" << std::endl;
		return 1;
	}

	// find program by name (function name in bpf source)
	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "iter_tasks");
	if (!prog)
	{
		std::cerr << "failed to find iter_tasks program in object\n";
		bpf_object__close(obj);
		return 1;
	}

	/* new libbpf API requires an attach opts pointer; pass NULL when none
	 * needed */
	struct bpf_link *link = bpf_program__attach_iter(prog, NULL);
	if (!link)
	{
		std::cerr << "failed to attach iterator program\n";
		bpf_object__close(obj);
		return 1;
	}

	int iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0)
	{
		std::cerr << "bpf_iter_create failed: " << strerror(errno) << "\n";
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}

	// consume iterator until it finishes
	char buf[4096];
	while (read(iter_fd, buf, sizeof(buf)) > 0)
	{
		// drain
	}
	close(iter_fd);

	// fetch map
	struct bpf_map *map = bpf_object__find_map_by_name(obj, "ns_map");
	if (!map)
	{
		std::cerr << "failed to find ns_map in object\n";
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}
	int map_fd = bpf_map__fd(map);

	struct bpf_map *cnt_map = bpf_object__find_map_by_name(obj, "ns_cnt_map");
	int cnt_map_fd = -1;
	if (cnt_map)
	{
		cnt_map_fd = bpf_map__fd(cnt_map);
		std::cerr << "found per-cpu ns_cnt_map\n";
	}
	else
	{
		std::cerr << "per-cpu ns_cnt_map not found, falling back to "
					 "ns_map.procs if present\n";
	}

	// iterate keys
	ns_key_t prev = {};
	ns_key_t next = {};
	bool first = true;

	// Collect all entries, then sort by inum and print with NS first
	struct Entry
	{
		uint32_t type;
		uint64_t inum;
		uint32_t pid;
		uint32_t uid;
		uint32_t procs;
	};
	std::vector<Entry> entries;

	while (true)
	{
		int ret;
		if (first)
		{
			ret = bpf_map_get_next_key(map_fd, NULL, &next);
			first = false;
		}
		else
		{
			ret = bpf_map_get_next_key(map_fd, &prev, &next);
		}
		if (ret != 0)
		{
			break;
		}

		ns_owner_t owner = {0, 0, 0};
		if (bpf_map_lookup_elem(map_fd, &next, &owner) == 0)
		{
			entries.push_back(
				Entry{next.type, next.inum, owner.pid, owner.uid, owner.procs}
			);
		}
		else
		{
			entries.push_back(Entry{next.type, next.inum, 0, 0, 0});
		}

		prev = next;
	}

	// sort by inum ascending
	std::sort(
		entries.begin(),
		entries.end(),
		[](const Entry &a, const Entry &b) { return a.inum < b.inum; }
	);

	// Build a one-time /proc scan to map namespace (type:inum) -> processes
	auto ns_proc_map = scan_procs_by_ns();

	// Second pass: print headers in original order. We'll compute a tree prefix
	// for each representative and embed that prefix in the header's PATH
	// column. This matches the original lsns: every namespace header is printed
	// (we do not print extra tree-only rows) and the PATH column shows tree
	// prefixes for representative nodes.
	const int NS_type = 16;
	const int TYPE_type = 18;
	const int PROCS_type = 8;
	const int USER_type = 20;
	const int PID_type = 12;
	const int pad_width =
		NS_type + TYPE_type + PROCS_type + USER_type + PID_type;

	// print header: NS, TYPE, PROCS, USER, PID, COMMAND
	std::cout << std::left << std::setw(NS_type) << "NS" << std::setw(TYPE_type)
			  << "TYPE" << std::setw(PROCS_type) << "PROCS"
			  << std::setw(USER_type) << "USER" << std::setw(PID_type) << "PID"
			  << "COMMAND" << "\n";

	// First pass: collect header info and representatives (do not print yet)
	struct HeaderInfo
	{
		Entry e;
		std::string display;
		std::string procname;
		std::string pathbuf;
		std::string user_field;
		uint64_t total_procs;
		int rep_tgid;
		std::string owner_cmd;
	};
	std::vector<HeaderInfo> headers;
	struct RepInfo
	{
		int tgid;
		uint32_t type;
		uint64_t inum;
		std::string cmd;
	};
	std::unordered_map<int, RepInfo> reps;			// tgid -> RepInfo
	std::unordered_map<std::string, int> rep_by_ns; // key -> tgid

	for (auto &e : entries)
	{
		// Skip pid_for_children namespace type (we don't display it)
		if (e.type == 9)
		{
			continue;
		}
		HeaderInfo h = {};
		h.e = e;
		h.display = ns_display_name(e.type);
		h.procname = ns_proc_name(e.type);
		h.pathbuf = std::string("-");
		if (e.pid)
		{
			char tmp[256];
			snprintf(
				tmp,
				sizeof(tmp),
				"/proc/%u/ns/%s",
				e.pid,
				h.procname.c_str()
			);
			h.pathbuf = std::string(tmp);
		}

		// per-cpu counts -> total_procs
		h.total_procs = e.procs;
		if (cnt_map_fd >= 0)
		{
			int nr_cpus = 0;
			FILE *f = fopen("/sys/devices/system/cpu/online", "r");
			if (f)
			{
				char buf[256];
				if (fgets(buf, sizeof(buf), f))
				{
					int a, b;
					char *p = buf;
					while (*p)
					{
						if (sscanf(p, "%d-%d", &a, &b) == 2)
						{
							nr_cpus += (b - a + 1);
							char *comma = strchr(p, ',');
							if (!comma)
							{
								break;
							}
							p = comma + 1;
						}
						else if (sscanf(p, "%d", &a) == 1)
						{
							nr_cpus += 1;
							char *comma = strchr(p, ',');
							if (!comma)
							{
								break;
							}
							p = comma + 1;
						}
						else
						{
							break;
						}
					}
				}
				fclose(f);
			}
			if (nr_cpus <= 0)
			{
				nr_cpus = 1;
			}
			std::vector<uint32_t> pcnts(nr_cpus);
			if (bpf_map_lookup_elem(cnt_map_fd, &e, pcnts.data()) == 0)
			{
				uint64_t sum = 0;
				for (int i = 0; i < nr_cpus; ++i)
				{
					sum += pcnts[i];
				}
				h.total_procs = sum;
			}
		}

		// user field
		static std::unordered_map<uint32_t, std::string> uid_cache;
		if (e.pid)
		{
			auto it = uid_cache.find(e.uid);
			if (it != uid_cache.end())
			{
				h.user_field = it->second;
			}
			else
			{
				struct passwd pwd, *pwdp = NULL;
				long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
				if (bufsize < 0)
				{
					bufsize = 16384;
				}
				std::unique_ptr<char[]> buf(new char[bufsize]);
				char uname[64] = {0};
				bool have_name = false;
				if (getpwuid_r(e.uid, &pwd, buf.get(), bufsize, &pwdp) == 0 &&
					pwdp)
				{
					strncpy(uname, pwd.pw_name, sizeof(uname) - 1);
					uname[sizeof(uname) - 1] = '\0';
					have_name = true;
				}
				h.user_field =
					have_name ? std::string(uname) : std::to_string(e.uid);
				uid_cache[e.uid] = h.user_field;
			}
		}
		else
		{
			h.user_field = "-";
		}

		// representative
		h.rep_tgid = 0;
		h.owner_cmd = "-";
		std::string key = std::to_string(e.type) + ":" + std::to_string(e.inum);
		auto vecit = ns_proc_map.find(key);
		if (vecit != ns_proc_map.end() && !vecit->second.empty())
		{
			int min_tgid = vecit->second[0].pid;
			for (const auto &pi : vecit->second)
			{
				if (pi.pid < min_tgid)
				{
					min_tgid = pi.pid;
				}
			}
			h.rep_tgid = min_tgid;
			for (const auto &pi : vecit->second)
			{
				if (pi.pid == h.rep_tgid)
				{
					h.owner_cmd = pi.cmd;
					break;
				}
			}
		}
		else if (e.pid)
		{
			h.rep_tgid = e.pid;
			h.owner_cmd = read_proc_cmd(e.pid);
		}

		if (h.rep_tgid)
		{
			RepInfo ri{h.rep_tgid, e.type, e.inum, h.owner_cmd};
			reps[h.rep_tgid] = ri;
			rep_by_ns[key] = h.rep_tgid;
		}
		headers.push_back(std::move(h));
	}

	// Build a map from representative tgid -> HeaderInfo for easy lookup
	std::unordered_map<int, const HeaderInfo *> rep_header_map;
	for (const auto &h : headers)
	{
		if (h.rep_tgid)
		{
			rep_header_map[h.rep_tgid] = &h;
		}
	}
	// Build rep -> list of headers mapping (a representative may correspond to
	// multiple namespace headers), used to print all namespaces for a rep.
	std::unordered_map<int, std::vector<const HeaderInfo *>> rep_to_headers;
	for (const auto &h : headers)
	{
		if (h.rep_tgid)
		{
			rep_to_headers[h.rep_tgid].push_back(&h);
		}
	}

	// Build representative-only parent->children map
	std::unordered_map<int, std::vector<int>> rep_children;
	std::unordered_map<int, int> rep_parent;
	std::unordered_set<int> rep_roots;
	for (const auto &kv : reps)
	{
		rep_roots.insert(kv.first);
	}
	// raw parent map: store parent_tgid read from /proc for each rep (0 when
	// none)
	std::unordered_map<int, int> rep_parent_raw;
	for (const auto &kv : reps)
	{
		int tgid = kv.first;
		int ppid = 0;
		uint32_t uid = 0;
		int tgid_out = 0;
		read_proc_ppid_uid(tgid, ppid, uid, tgid_out);
		int parent_tgid = 0;
		if (ppid > 0)
		{
			int dummy_ppid = 0;
			uint32_t dummy_uid = 0;
			int parent_tgid_read = 0;
			read_proc_ppid_uid(ppid, dummy_ppid, dummy_uid, parent_tgid_read);
			parent_tgid = parent_tgid_read;
		}
		rep_parent_raw[tgid] = parent_tgid;
		if (parent_tgid > 0 && reps.count(parent_tgid))
		{
			rep_children[parent_tgid].push_back(tgid);
			rep_roots.erase(tgid);
			// record parent mapping for quick lookup
			rep_parent[tgid] = parent_tgid;
		}
	}

	// orphan roots: rep whose parent_tgid is present (non-zero) but parent is
	// not a rep
	std::unordered_set<int> orphan_roots;
	for (const auto &kv : rep_parent_raw)
	{
		int tgid = kv.first;
		int parent_tgid = kv.second;
		if (parent_tgid > 0 && !reps.count(parent_tgid))
		{
			orphan_roots.insert(tgid);
		}
	}

	// build orphan subtree set: all reps that are descendants of any orphan
	// root
	std::unordered_set<int> orphan_subtree;
	std::function<void(int)> collect_orphan_subtree = [&](int r)
	{
		if (orphan_subtree.count(r))
		{
			return;
		}
		orphan_subtree.insert(r);
		auto it = rep_children.find(r);
		if (it == rep_children.end())
		{
			return;
		}
		for (int c : it->second)
		{
			collect_orphan_subtree(c);
		}
	};
	for (int r : orphan_roots)
	{
		collect_orphan_subtree(r);
	}

	// Sort children lists by namespace inum (ascending) for deterministic order
	for (auto &kv : rep_children)
	{
		auto &vec = kv.second;
		std::sort(
			vec.begin(),
			vec.end(),
			[&](int a, int b)
			{
				uint64_t inum_a = reps.count(a) ? reps[a].inum : 0;
				uint64_t inum_b = reps.count(b) ? reps[b].inum : 0;
				if (inum_a != inum_b)
				{
					return inum_a < inum_b;
				}
				return a < b;
			}
		);
	}

	// Build prefix map: rep_prefix[rep_tgid] = prefix string (e.g. "├─" or "│
	// ├─...") to prepend to cmd
	std::unordered_map<int, std::string> rep_prefix;
	// recursive DFS to assign prefixes to children
	std::function<void(int, const std::string &)> build_prefix =
		[&](int tgid, const std::string &prefix)
	{
		auto it = rep_children.find(tgid);
		if (it == rep_children.end())
		{
			return;
		}
		const auto &ch = it->second;
		for (size_t i = 0; i < ch.size(); ++i)
		{
			bool last = (i + 1 == ch.size());
			std::string this_prefix = prefix + (last ? "└─" : "├─");
			rep_prefix[ch[i]] = this_prefix;
			std::string next_prefix = prefix + (last ? "   " : "│  ");
			build_prefix(ch[i], next_prefix);
		}
	};

	// run DFS from each root in deterministic order (sort roots by inum)
	std::vector<int> roots_vec(rep_roots.begin(), rep_roots.end());
	std::sort(
		roots_vec.begin(),
		roots_vec.end(),
		[&](int a, int b)
		{
			uint64_t ina = reps.count(a) ? reps[a].inum : 0;
			uint64_t inb = reps.count(b) ? reps[b].inum : 0;
			if (ina != inb)
			{
				return ina < inb;
			}
			return a < b;
		}
	);
	for (int r : roots_vec)
	{
		build_prefix(r, std::string());
	}

	if (!json_output)
	{
		// Now print headers in original order, embedding prefix if present.
		// However, skip printing headers that belong to orphan_subtree for now;
		// we'll print those after the normal headers, sorted by NS.
		std::vector<HeaderInfo> orphan_headers;
		for (const auto &h : headers)
		{
			if (h.rep_tgid && orphan_subtree.count(h.rep_tgid))
			{
				orphan_headers.push_back(h);
				continue;
			}
			std::string procs_field = h.total_procs
										  ? std::to_string(h.total_procs)
										  : std::string("-");
			std::string pid_field =
				h.rep_tgid ? std::to_string(h.rep_tgid) : std::string("-");
			std::string path_field = h.owner_cmd;
			if (h.rep_tgid && rep_prefix.count(h.rep_tgid))
			{
				path_field = rep_prefix[h.rep_tgid] + h.owner_cmd;
			}
			std::cout << std::left << std::setw(NS_type) << h.e.inum
					  << std::setw(TYPE_type) << h.display
					  << std::setw(PROCS_type) << procs_field
					  << std::setw(USER_type) << h.user_field
					  << std::setw(PID_type) << pid_field << path_field << "\n";
		}

		// Sort orphan headers by NS (inum) ascending and print them last. For
		// each orphan header we still display its subtree (if any) using the
		// same prefix logic.
		std::sort(
			orphan_headers.begin(),
			orphan_headers.end(),
			[](const HeaderInfo &a, const HeaderInfo &b)
			{ return a.e.inum < b.e.inum; }
		);
		for (const auto &h : orphan_headers)
		{
			std::string procs_field = h.total_procs
										  ? std::to_string(h.total_procs)
										  : std::string("-");
			std::string pid_field =
				h.rep_tgid ? std::to_string(h.rep_tgid) : std::string("-");
			std::string path_field = h.owner_cmd;
			if (h.rep_tgid && rep_prefix.count(h.rep_tgid))
			{
				path_field = rep_prefix[h.rep_tgid] + h.owner_cmd;
			}
			std::cout << std::left << std::setw(NS_type) << h.e.inum
					  << std::setw(TYPE_type) << h.display
					  << std::setw(PROCS_type) << procs_field
					  << std::setw(USER_type) << h.user_field
					  << std::setw(PID_type) << pid_field << path_field << "\n";
			// if this orphan has children, print them (they are in
			// rep_children)
			auto itc = rep_children.find(h.rep_tgid);
			if (itc == rep_children.end())
			{
				continue;
			}
			const auto &root_children = itc->second;
			// print recursively as full rows using rep_prefix already computed
			std::function<void(int, const std::string &, bool)>
				print_orphan_node =
					[&](int tgid, const std::string &prefix, bool is_last)
			{
				auto rit = reps.find(tgid);
				std::string cmd = (rit != reps.end()) ? rit->second.cmd
													  : std::to_string(tgid);
				const HeaderInfo *hh = nullptr;
				auto hit = rep_header_map.find(tgid);
				if (hit != rep_header_map.end())
				{
					hh = hit->second;
				}
				std::string path = prefix + (is_last ? "└─" : "├─") + cmd;
				if (hh)
				{
					std::string procs_f = hh->total_procs
											  ? std::to_string(hh->total_procs)
											  : std::string("-");
					std::string pid_f = std::to_string(hh->rep_tgid);
					std::cout << std::left << std::setw(NS_type) << hh->e.inum
							  << std::setw(TYPE_type)
							  << ns_display_name(hh->e.type)
							  << std::setw(PROCS_type) << procs_f
							  << std::setw(USER_type) << hh->user_field
							  << std::setw(PID_type) << pid_f << path << "\n";
				}
				else if (rit != reps.end())
				{
					auto &rinfo = rit->second;
					std::cout
						<< std::left << std::setw(NS_type) << rinfo.inum
						<< std::setw(TYPE_type) << ns_display_name(rinfo.type)
						<< std::setw(PROCS_type) << "-" << std::setw(USER_type)
						<< "-" << std::setw(PID_type)
						<< std::to_string(rinfo.tgid) << path << "\n";
				}
				else
				{
					std::cout << std::string(pad_width, ' ') << path << "\n";
				}
				auto itc2 = rep_children.find(tgid);
				if (itc2 == rep_children.end())
				{
					return;
				}
				const auto &ch = itc2->second;
				for (size_t i = 0; i < ch.size(); ++i)
				{
					bool last = (i + 1 == ch.size());
					std::string child_prefix =
						prefix + (is_last ? "   " : "│  ");
					print_orphan_node(ch[i], child_prefix, last);
				}
			};
			for (size_t i = 0; i < root_children.size(); ++i)
			{
				bool last = (i + 1 == root_children.size());
				print_orphan_node(root_children[i], std::string(), last);
			}
		}
	}
	else
	{
		// JSON output branch
		// simple JSON escaping helper
		auto json_escape = [](const std::string &s) -> std::string
		{
			std::string out;
			out.reserve(s.size());
			for (unsigned char c : s)
			{
				switch (c)
				{
				case '"':
					out += "\\\"";
					break;
				case '\\':
					out += "\\\\";
					break;
				case '\n':
					out += "\\n";
					break;
				case '\r':
					out += "\\r";
					break;
				case '\t':
					out += "\\t";
					break;
				default:
					if (c < 0x20)
					{
						char buf[8];
						snprintf(buf, sizeof(buf), "\\u%04x", c);
						out += buf;
					}
					else
					{
						out += (char)c;
					}
				}
			}
			return out;
		};

		// We'll print JSON per header to ensure every namespace header is
		// output. Keep a set of printed namespace keys to avoid duplicates when
		// a representative covers multiple namespace headers.
		std::unordered_set<std::string> printed_ns;
		auto spaces = [&](int n) { return std::string(n, ' '); };
		std::function<std::string(const HeaderInfo *, int)> build_header_json;
		build_header_json = [&](const HeaderInfo *hh, int indent) -> std::string
		{
			std::string key =
				std::to_string(hh->e.type) + ":" + std::to_string(hh->e.inum);
			if (printed_ns.count(key))
			{
				return std::string();
			}
			printed_ns.insert(key);
			std::ostringstream ss;
			ss << spaces(indent) << "{\n";
			ss << spaces(indent + 3) << "\"ns\": " << hh->e.inum << ",\n";
			ss << spaces(indent + 3) << "\"type\": \"" << hh->display
			   << "\",\n";
			ss << spaces(indent + 3) << "\"nprocs\": " << hh->total_procs
			   << ",\n";
			ss << spaces(indent + 3)
			   << "\"pid\": " << (hh->rep_tgid ? hh->rep_tgid : 0) << ",\n";
			ss << spaces(indent + 3) << "\"user\": \""
			   << json_escape(hh->user_field) << "\",\n";
			ss << spaces(indent + 3) << "\"command\": \""
			   << json_escape(hh->owner_cmd) << "\"";

			auto it = rep_children.find(hh->rep_tgid);
			if (it != rep_children.end() && !it->second.empty())
			{
				// check if there is at least one child header that hasn't been
				// printed
				bool have_child = false;
				for (int child_tgid : it->second)
				{
					auto phit = rep_to_headers.find(child_tgid);
					if (phit == rep_to_headers.end())
					{
						continue;
					}
					for (const HeaderInfo *child_hh : phit->second)
					{
						std::string child_key =
							std::to_string(child_hh->e.type) + ":" +
							std::to_string(child_hh->e.inum);
						if (!printed_ns.count(child_key))
						{
							have_child = true;
							break;
						}
					}
					if (have_child)
					{
						break;
					}
				}
				if (have_child)
				{
					ss << ",\n" << spaces(indent + 3) << "\"children\": [\n";
					bool first_child = true;
					for (int child_tgid : it->second)
					{
						auto phit = rep_to_headers.find(child_tgid);
						if (phit == rep_to_headers.end())
						{
							continue;
						}
						for (const HeaderInfo *child_hh : phit->second)
						{
							std::string child_key =
								std::to_string(child_hh->e.type) + ":" +
								std::to_string(child_hh->e.inum);
							if (printed_ns.count(child_key))
							{
								continue; // skip already-printed child
							}
							std::string child_json =
								build_header_json(child_hh, indent + 6);
							if (child_json.empty())
							{
								continue;
							}
							if (!first_child)
							{
								ss << ",\n";
							}
							first_child = false;
							ss << child_json;
						}
					}
					ss << "\n" << spaces(indent + 3) << "]";
				}
			}
			ss << "\n" << spaces(indent) << "}";
			return ss.str();
		};

		// Print top-level JSON array by iterating headers to ensure every
		// header from the table is emitted. For headers that reference a
		// representative tgid, print the rep tree if it hasn't already been
		// printed. For headers without a rep, print the header object directly.
		std::cout << "{\n  \"namespaces\": [\n";
		bool first_obj = true;
		std::vector<std::string> objs;
		objs.reserve(headers.size());
		for (const auto &h : headers)
		{
			std::string s = build_header_json(&h, 4);
			if (!s.empty())
			{
				objs.push_back(std::move(s));
			}
		}
		// any remaining reps not printed yet (possible reps not associated with
		// headers)
		for (const auto &kv : reps)
		{
			int tgid = kv.first;
			auto phit = rep_to_headers.find(tgid);
			if (phit == rep_to_headers.end())
			{
				// build a minimal object for this rep and append
				HeaderInfo tmp = {};
				tmp.e.type = kv.second.type;
				tmp.e.inum = kv.second.inum;
				tmp.e.procs = 0;
				tmp.rep_tgid = kv.second.tgid;
				tmp.display = ns_display_name(kv.second.type);
				tmp.user_field = "-";
				tmp.owner_cmd = kv.second.cmd;
				std::string s = build_header_json(&tmp, 4);
				if (!s.empty())
				{
					objs.push_back(std::move(s));
				}
			}
		}

		for (size_t i = 0; i < objs.size(); ++i)
		{
			if (i)
			{
				std::cout << ",\n";
			}
			std::cout << objs[i];
		}
		std::cout << "\n  ]\n}\n";
	}

	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
