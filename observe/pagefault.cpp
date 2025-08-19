#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "pagefault.skel.h"

static volatile bool exiting = false;

struct page_fault_t
{
	pid_t pid;
	pid_t tid;
	char comm[16];
	int stack_id;
	__u64 timestamp;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};

static void sig_handler(int signo)
{
	exiting = true;
}

static void usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n", prog);
	printf("Options:\n");
	printf("  -p, --pid <pid>         只跟踪指定进程的pagefault\n");
	printf("  -u, --user              只跟踪用户态pagefault\n");
	printf("  -k, --kernel            只跟踪内核态pagefault\n");
	printf("  -s, --stack             显示用户态堆栈信息\n");
	printf("  -t, --timestamp         显示时间戳\n");
	printf("  -h, --help              显示帮助信息\n");
}

struct env_t
{
	pid_t pid;
	bool user;
	bool kernel;
	bool show_stack;
	bool show_ts;
} env = {};

static int print_stack(struct pagefault_bpf *skel, int stack_id)
{
	if (stack_id < 0)
		return 0;
	int n = 0;
	char sym[256];
	__u64 ips[128] = {};
	int fd = bpf_map__fd(skel->maps.stack_traces);
	n = bpf_map_lookup_elem(fd, &stack_id, ips);
	if (n < 0)
	{
		printf("    [Failed to get stack trace]\n");
		return 0;
	}
	printf("    User stack:\n");
	for (int i = 0; i < 128 && ips[i]; i++)
	{
		snprintf(sym, sizeof(sym), "        0x%llx",
			 (unsigned long long)ips[i]);
		printf("%s\n", sym);
	}
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct page_fault_t *e = (const struct page_fault_t *)data;
	if (env.pid && e->pid != env.pid)
		return 0;
	printf("PID:%d TID:%d COMM:%s ADDR:0x%lx IP:0x%lx ERR:0x%lx", e->pid,
	       e->tid, e->comm, e->address, e->ip, e->error_code);
	if (env.show_ts)
		printf(" TS:%llu", e->timestamp);
	printf("\n");
	if (env.show_stack)
		print_stack((struct pagefault_bpf *)ctx, e->stack_id);
	return 0;
}

int main(int argc, char **argv)
{
	struct pagefault_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err = 0, opt;
	static const struct option long_options[] = {
		{ "pid", required_argument, 0, 'p' },
		{ "user", no_argument, 0, 'u' },
		{ "kernel", no_argument, 0, 'k' },
		{ "stack", no_argument, 0, 's' },
		{ "timestamp", no_argument, 0, 't' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "p:uksth", long_options, NULL)) !=
	       -1)
	{
		switch (opt)
		{
		case 'p':
			env.pid = atoi(optarg);
			break;
		case 'u':
			env.user = true;
			break;
		case 'k':
			env.kernel = true;
			break;
		case 's':
			env.show_stack = true;
			break;
		case 't':
			env.show_ts = true;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return 0;
		}
	}

	if (!env.user && !env.kernel)
		env.user = env.kernel = true;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
	setrlimit(RLIMIT_MEMLOCK, &rlim);

	skel = pagefault_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	int key = 0;
	// 过滤pid
	if (env.pid)
		bpf_map_update_elem(bpf_map__fd(skel->maps.filter), &key,
				    &env.pid, BPF_ANY);

	if (!env.user)
		skel->links.page_fault_user = NULL;
	if (!env.kernel)
		skel->links.page_fault_kernel = NULL;

	err = pagefault_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}
	err = pagefault_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      skel, NULL);
	if (!rb)
	{
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Tracing page faults... Hit Ctrl-C to exit.\n");
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
			break;
		if (err < 0)
		{
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	pagefault_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}