#include "Ulog.h"
#include <cstdint>
#include <stdio.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <getopt.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <vector>
#include <thread>
#include <atomic>
#include <dirent.h>

#include "Ucom.h"

#include "frtp.skel.h"

static frtp_bpf *obj;

typedef uint32_t Action;

#define FMODE_READ (0x1)
#define FMODE_WRITE (0x2)
#define FMODE_EXEC (0x20)

static inline uint32_t dev_old2new(dev_t old)
{
	uint32_t major = gnu_dev_major(old);
	uint32_t minor = gnu_dev_minor(old);
	return ((major & 0xfff) << 20) | (minor & 0xfffff);
}

struct Target {
	uint32_t dev;
	ino_t ino;
};

struct Rule {
	union {
		struct {
			uint32_t not_pid;
			pid_t pid;
		};
		char process[4096];
	};
	Action act;
	struct Target target;
};

struct BpfData {
	Action act;
	pid_t pid;
	char process[];
};

char line[8192];
struct Rule rule = { 0 };
static int filter_fd;
static int log_map_fd;
struct ring_buffer *rb = NULL;
static std::atomic<bool> exit_flag(false);
const char *policy_file = NULL;

static struct option lopts[] = { { "policy-file", required_argument, 0, 'p' },
				 { "help", no_argument, 0, 'h' },
				 { 0, 0, 0, 0 } };

// Structure for help messages
struct HelpMsg {
	const char *argparam; // Argument parameter
	const char *msg; // Help message
};

// Help messages
static HelpMsg help_msg[] = {
	{ "<policy-file>", "specify the policy file to load policy\n" },
	{ "", "print this help message\n" },
};

// Function to print usage information
void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  protect system files from malicious opening according to the policy file\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++) {
		printf("  -%c, --%s %s\n\t%s\n", lopts[i].val, lopts[i].name,
		       help_msg[i].argparam, help_msg[i].msg);
	}
}

// Convert long options to short options string
std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts = "";
	for (int i = 0; lopts[i].name; i++) {
		sopts += lopts[i].val; // Add short option character
		switch (lopts[i].has_arg) {
		case no_argument:
			break;
		case required_argument:
			sopts += ":"; // Required argument
			break;
		case optional_argument:
			sopts += "::"; // Optional argument
			break;
		default:
			DIE("Code internal bug!!!\n");
			abort();
		}
	}
	return sopts;
}

// Parse command line arguments
void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	std::string sopts = long_opt2short_opt(
		lopts); // Convert long options to short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) >
	       0) {
		switch (opt) {
		case 'p': // Process ID
			policy_file = optarg;
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

	if (!policy_file) {
		policy_file = "frtp.pol";
		pr_info("No policy file specified, use frtp.pol as default");
	}
}

static std::string act2str(Action act)
{
	std::string str;
	if (act & FMODE_READ)
		str += "read/";
	if (act & FMODE_WRITE)
		str += "write/";
	if (act & FMODE_EXEC)
		str += "exec/";

	if (!str.empty()) {
		str.pop_back();
	}
	return str;
}

static void path2target(const char *path, struct Target *target)
{
	if (access(path, F_OK) == -1) {
		pr_error("File %s pr_error: %s\n", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct stat st;
	if (stat(path, &st) != 0) {
		pr_error("stat %s: %s\n", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	target->ino = st.st_ino;
	target->dev = dev_old2new(st.st_dev);
}

static void add_directories_recursively(const char *dir_path,
					const struct Rule *base_rule,
					std::vector<struct Rule> &rules)
{
	struct Rule dir_rule = *base_rule;
	path2target(dir_path, &dir_rule.target);
	rules.emplace_back(dir_rule);

	DIR *dir = opendir(dir_path);
	if (!dir) {
		pr_error( "Cannot open directory %s: %s", dir_path,
			strerror(errno));
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		char full_path[PATH_MAX];
		snprintf(full_path, sizeof(full_path), "%s/%s", dir_path,
			 entry->d_name);

		struct stat st;
		if (stat(full_path, &st) != 0) {
			pr_error( "Cannot stat %s: %s", full_path,
				strerror(errno));
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			add_directories_recursively(full_path, base_rule,
						    rules);
		}
	}

	closedir(dir);
}

std::vector<struct Rule> parse_policy_file(const char *filename)
{
	std::vector<struct Rule> rules;
	FILE *file = fopen(filename, "r");
	if (!file) {
		pr_error("fopen: %s: %s\n", strerror(errno), filename);
		exit(EXIT_FAILURE);
	}

	char line[8192];
	while (fgets(line, sizeof(line), file)) {
		char action[3];
		char type[6];
		char identifier[4096];
		char target_path[4096];

		if (line[0] == '#')
			continue;

		if (sscanf(line, "forbid %5[^=]=%4095s %2s %4095s", type,
			   identifier, action, target_path) != 4) {
			pr_error( "Invalid line: %s", line);
			continue;
		}

		struct Rule rule = { 0 };

		if (strcmp(type, "proc") == 0) {
			strncpy(rule.process, identifier, sizeof(rule.process));
			rule.process[sizeof(rule.process) - 1] = 0;
		} else if (strcmp(type, "pid") == 0) {
			rule.pid = strtol(identifier, NULL, 10);
			rule.not_pid = 0;
		} else {
			pr_error( "Invalid type: %s", type);
			continue;
		}

		if (strcmp(action, "r") == 0) {
			rule.act = FMODE_READ;
		} else if (strcmp(action, "w") == 0) {
			rule.act = FMODE_WRITE;
		} else if (strcmp(action, "rw") == 0) {
			rule.act = FMODE_READ | FMODE_WRITE;
		} else {
			pr_error( "Invalid action: %s", action);
			continue;
		}

		bool is_dir = false;
		size_t path_len = strlen(target_path);

		if (path_len >= 2 &&
		    strcmp(target_path + path_len - 2, "/*") == 0) {
			target_path[path_len - 2] = '\0';
			is_dir = true;
		} else if (path_len > 1 && target_path[path_len - 1] == '/') {
			target_path[path_len - 1] = '\0';
			is_dir = true;
		}

		struct stat st;
		if (stat(target_path, &st) != 0) {
			pr_error("Cannot access path %s: %s",
				target_path, strerror(errno));
			continue;
		}

		if (is_dir) {
			if (S_ISDIR(st.st_mode)) {
				pr_info("Rule (diretory): %s %s %s %s", type,
					identifier, action, target_path);
				add_directories_recursively(target_path, &rule,
							    rules);
			} else {
				pr_error(
					"Path %s with wildcard is not a directory",
					target_path);
				continue;
			}
		} else {
			if (S_ISREG(st.st_mode)) {
				path2target(target_path, &rule.target);
				rules.emplace_back(rule);
				pr_info("Rule (regular file): %s %s %s %s",
					type, identifier, action, target_path);
			} else {
				pr_error("Path %s is not a regular file",
					 target_path);
				continue;
			}
		}
	}

	fclose(file);
	return rules;
}

void load_rules(const std::vector<struct Rule> &rules)
{
	uint32_t key = 0;
	for (const auto &rule : rules) {
		key++;
		if (bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY) != 0) {
			perror("bpf_map_update_elem");
			exit(EXIT_FAILURE);
		}
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log =
		(const struct BpfData *)data; // Cast data to BpfData structure
	size_t plen = strlen(log->process);
	const char *target = log->process + plen + 1;
	pr_warn("[%s]!!!: %s[%d] tried to %s (%s), denied!", get_time().c_str(),
		log->process, log->pid, act2str(log->act).c_str(), target);
	return 0;
}

void ringbuf_worker(void)
{
	while (!exit_flag) {
		int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
		// Check for errors during polling
		if (err < 0 && err != -EINTR) {
			pr_error("Error polling ring buffer: %d\n", err);
			sleep(5); // Sleep before retrying
		}
	}
}

void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) {
		exit_flag = true;
	}; // Set exit flag on signal
	sa.sa_flags = 0; // No special flags
	sigemptyset(&sa.sa_mask); // No additional signals to block
	// Register the signal handler for SIGINT
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	std::vector<struct Rule> rules;

	parse_args(argc, argv);

	register_signal();
	std::thread *rb_thread;

	obj = frtp_bpf::open_and_load();
	if (!obj)
		exit(-1);
	if (0 != frtp_bpf::attach(obj))
		exit(-1);

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);

	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
		goto err_out; // Handle pr_error
	rules = parse_policy_file(policy_file);
	load_rules(rules);

	rb_thread = new std::thread(ringbuf_worker);
	follow_trace_pipe();

	rb_thread->join();
	delete rb_thread;
err_out:
	frtp_bpf::detach(obj); // Detach BPF program
	frtp_bpf::destroy(obj); // Clean up BPF object
	return -1;
}