#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
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
#include <uuid/uuid.h>

#include <fstream>
#include <sstream>
#include <unordered_map>
#include <string>

#include "bio-stat.skel.h"
#include "Ucom.h"
#include "jhash.h"
#include "blk_types.h"

#define MAP_MAX_ENTRY 10000

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100

#define DISK_NAME_LEN 32
#define TASK_COMM_LEN 16
#define RWBS_LEN 8

#define MKDEV(ma, mi) ((ma) << 8 | (mi))


struct Rule
{
	pid_t pid;
	dev_t dev;
	char comm[TASK_COMM_LEN];
	u64 min_ns;
	u32 duration;
} rule;

struct info_t
{
	u32 pid;
	int rwflag;
	int major;
	int minor;
	char name[16];
};

struct val_t
{
	u64 bytes;
	u64 us;
	u32 io;
};
static bio_stat_bpf *obj;
static int counts_map_fd;
struct ring_buffer *rb = NULL;
static int filter_fd;
static int interval = 1;
static pthread_t t1;
static bool top_mode = false;
static std::unordered_map<u32, std::string> disklookup;
static std::atomic<bool> exit_flag(false);

static struct option lopts[] = {
	{"pid", required_argument, 0, 'p'},
	{"comm", required_argument, 0, 'c'},
	{"dev", required_argument, 0, 'd'},
	{"duration", required_argument, 0, 'D'},
	{"interval", required_argument, 0, 'i'},
	{"top", no_argument, 0, 't'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}};

struct HelpMsg
{
	const char *argparam;
	const char *msg;
};

static HelpMsg help_msg[] = {
	{"[pid]", "filter output by the pid\n"},
	{"[comm]", "filter output by the process comm.\n"},
	{"[dev]", "filter output by device number, format val=(major << 8 | minor)\n"},
	{"[duration]", "set the duration time when to exit\n"},
	{"[interval]", "statistic interval\n"},
	{"[top]", "output infomation in a top way\n"},
	{"", "print this help message\n"},
};

void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  To monitor the block io speed per process per disk.\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf("  -%c, --%s %s\n\t%s\n",
			   lopts[i].val,
			   lopts[i].name,
			   help_msg[i].argparam,
			   help_msg[i].msg);
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
		case 'p':
			rule.pid = atoi(optarg);
			break;
		case 'c':
			strncpy(rule.comm, optarg, 16);
			rule.comm[15] = 0;
			break;
		case 'd':
			rule.dev = atoi(optarg);
			break;
		case 'D':
			rule.duration = atoi(optarg);
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 't':
			top_mode = true;
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
	sa.sa_handler = [](int)
	{
		exit_flag = true;
	};
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

static void disable_bpf_autoload(bio_stat_bpf *obj)
{
	bpf_object_skeleton *s = obj->skeleton;
	for (int i = 0; i < s->prog_cnt; i++)
	{
		bpf_prog_skeleton &prog = s->progs[i];
		// std::string name = prog.name;
		// if (name == "trace_pid_start" ||
		// 	name == "trace_req_completion" ||
		// 	name == "blk_account_io_start")
		// {
			bpf_program__set_autoload(*prog.prog, false);
		// 	continue;
		// }
	}
}

static const char* top_mode_bpf_progs[] = {
	"trace_req_start",
	"trace_pid_start_tp",
	"trace_req_completion_tp",
	NULL,
};

static const char* tailing_mode_bpf_progs[] = {
	"block_rq_complete",
	"block_rq_issue",
	"block_rq_insert",
	"blk_account_io_merge_bio",
	"block_io_start",
	NULL,
};

static void enable_bpf_autoload(bio_stat_bpf *obj, const char *progs[])
{
	bpf_object_skeleton *s;
	for (u32 i = 0; progs[i]; i++)
	{
		const char *tprog = progs[i];
		s = obj->skeleton;
		for (int i = 0; i < s->prog_cnt; i++)
		{
			bpf_prog_skeleton &prog = s->progs[i];
			std::string name = prog.name;
			if (name == tprog)
				bpf_program__set_autoload(*prog.prog, true);
		}
	}
}

template <typename T>
static int lookup_keys(T *keys)
{
	T key = {};
	T nxt_key = {};
	int i = 0;
	while (0 == bpf_map_get_next_key(counts_map_fd, &key, &nxt_key))
	{
		key = nxt_key;
		keys[i++] = key;
	}
	return i;
}

static void read_disk_names(void)
{

	std::string diskstats = "/proc/diskstats";
	std::ifstream stats(diskstats);
	std::string line;

	while (std::getline(stats, line))
	{
		std::istringstream iss(line);
		u32 major, minor;
		std::string name;
		iss >> major >> minor >> name;
		dev_t dev = MKDEV(major, minor);
		disklookup[dev] = name;
	}
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

static void blk_fill_rwbs(char *rwbs, unsigned int op)
{
	int i = 0;

	if (op & REQ_PREFLUSH)
		rwbs[i++] = 'F';

	switch (op & REQ_OP_MASK)
	{
	case REQ_OP_WRITE:
	case REQ_OP_WRITE_SAME:
		rwbs[i++] = 'W';
		break;
	case REQ_OP_DISCARD:
		rwbs[i++] = 'D';
		break;
	case REQ_OP_SECURE_ERASE:
		rwbs[i++] = 'D';
		rwbs[i++] = 'E';
		break;
	case REQ_OP_FLUSH:
		rwbs[i++] = 'F';
		break;
	case REQ_OP_READ:
		rwbs[i++] = 'R';
		break;
	default:
		rwbs[i++] = 'N';
	}

	if (op & REQ_FUA)
		rwbs[i++] = 'F';
	if (op & REQ_RAHEAD)
		rwbs[i++] = 'A';
	if (op & REQ_SYNC)
		rwbs[i++] = 'S';
	if (op & REQ_META)
		rwbs[i++] = 'M';

	rwbs[i] = '\0';
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	char rwbs[RWBS_LEN];
	struct timespec ct;
	struct tm *tm;
	char ts[32];

	if (data_sz < sizeof(e))
	{
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	/* Since `bpf_ktime_get_boot_ns` requires at least 5.8 kernel,
	 * so get time from usespace instead */
	clock_gettime(CLOCK_REALTIME, &ct);
	tm = localtime(&ct.tv_sec);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s.%03ld ", ts, ct.tv_nsec / 1000000);
	blk_fill_rwbs(rwbs, e.cmd_flags);
	dev_t dev = e.dev;
	std::string diskname;
	if (disklookup.find(dev) != disklookup.end())
		diskname = disklookup[dev];
	else
		diskname = "?";
	printf("%-14.14s %-7d %-7s %-4s %-10lld %-7d ",
		   e.comm, e.pid, diskname.c_str(), rwbs,
		   e.sector, e.len);
		
	printf("%7.3f ", e.qdelta != (__u64)-1 ? e.qdelta / 1000000.0 : -1);
	printf("%7.3f\n", e.delta / 1000000.0);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void snoop(void)
{
	int err = 0;
	struct perf_buffer *pb = NULL;
	time_t time_end;

	if (rule.duration)
		time_end = time(NULL) + rule.duration;

	pb = perf_buffer__new(
		bpf_map__fd(obj->maps.events),
		PERF_BUFFER_PAGES,
		handle_event,
		handle_lost_events,
		NULL, NULL);
	if (!pb)
	{
		fprintf(stderr, "failed to open perf buffer: %d\n", errno);
		return;
	}
	printf("%-12s %-14s %-7s %-7s %-4s %-10s %-7s %7s %7s\n",
		   "TIMESTAMP", "COMM", "PID", "DISK", "T", "SECTOR",
		   "BYTES", "QUE(ms)", "LAT(ms)");

	while (!exit_flag)
	{
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR)
		{
			fprintf(stderr, "pr_error polling perf buffer: %s\n", strerror(-err));
			break;
		}

		if (rule.duration && time(NULL) > time_end)
			break;
	}
	perf_buffer__free(pb);
}

static void top(void)
{
	long ret;
	info_t *keys;
	val_t *vals;
	u32 count;
	time_t time_end;

	if (rule.duration)
		time_end = time(NULL) + rule.duration;

	keys = new info_t[MAP_MAX_ENTRY];
	vals = new val_t[MAP_MAX_ENTRY];
	while (!exit_flag)
	{
		// clear the terminal screen
		printf("\33[H\33[2J\33[3J");
		printf("Tracing... Output every %d secs. Hit Ctrl-C to end\n\n", interval);
		printf("%-7s %-16s %1s %7s %-8s %5s %7s %6s\n", "PID", "COMM",
			   "D", "DEV  ", "DISK", "I/O", "Kbytes", "AVGms");
		u32 batch;
		count = lookup_keys(keys);
		ret = bpf_map_lookup_and_delete_batch(
			counts_map_fd, NULL, &batch,
			keys, vals, &count, NULL);
		if (ret == -EFAULT)
		{
			pr_error("lookup_and_delete_batch: %ld: %s\n",
				  ret, strerror(errno));
			sleep(interval);
			continue;
		}

		for (u32 i = 0; i < count; i++)
		{
			info_t k = keys[i];
			val_t v = vals[i];
			dev_t dev = MKDEV(k.major, k.minor);
			std::string diskname;
			if (disklookup.find(dev) != disklookup.end())
				diskname = disklookup[dev];
			else
				diskname = "?";

			float avg_ms = (float(v.us) / 1000) / v.io;
			printf("%-7d %-16s %1s %3d:%-3d %-8s %5u %7llu %6.2f\n",
				   k.pid, k.name, k.rwflag ? "W" : "R",
				   k.major, k.minor, diskname.c_str(),
				   v.io, v.bytes / 1024, avg_ms);
		}
		sleep(interval);

		if (rule.duration && time(NULL) > time_end)
			break;
	}
	delete[] keys;
	delete[] vals;
}

int main(int argc, char *args[])
{
	long ret;

	parse_args(argc, args);
	register_signal();
	read_disk_names();

	int key = 0;
	obj = bio_stat_bpf::open();
	if (!obj)
		exit(-1);

	disable_bpf_autoload(obj);
	if (top_mode)
		enable_bpf_autoload(obj, top_mode_bpf_progs);
	else
		enable_bpf_autoload(obj, tailing_mode_bpf_progs);

	if (bio_stat_bpf::load(obj))
	{
		printf("Error: bio_stat_bpf::load\n");
		exit(-1);
	}

	if (0 != bio_stat_bpf::attach(obj))
	{
		printf("Error: bio_stat_bpf::attach\n");
		exit(-1);
	}

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);

	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		goto err_out;
	}

	counts_map_fd = bpf_get_map_fd(obj->obj, "counts", goto err_out);

	ret = pthread_create(&t1, NULL, [](void *) -> void *
		{ 
			follow_trace_pipe();
			return NULL; 
		}, NULL);
	if (ret)
	{
		pr_error("cannot create thread: %s\n", strerror(errno));
		goto err_out;
	}
	if (!top_mode)
		snoop();
	else
		top();

	printf("main routine done!\n");
	stop_trace();
	pthread_kill(t1, SIGINT);
	pthread_join(t1, NULL);

err_out:
	if (rb)
		ring_buffer__free(rb);
	bio_stat_bpf::detach(obj);
	bio_stat_bpf::destroy(obj);
	return 0;
}