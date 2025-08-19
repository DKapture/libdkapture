#include "Ulog.h"
#include <cstdint>
#include <stdio.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <vector>
#include <thread>
#include <atomic>
#include <uuid/uuid.h>
#include <dirent.h>
#include <pwd.h>
#include "Ucom.h"

#include "elfverify.skel.h"

static elfverify_bpf *obj;

static inline uint32_t dev_old2new(dev_t old)
{
	uint32_t major = gnu_dev_major(old);
	uint32_t minor = gnu_dev_minor(old);
	return ((major & 0xfff) << 20) | (minor & 0xfffff);
}

struct Target
{
	uint32_t dev;
	ino_t ino;
};

struct Rule
{
	union
	{
		struct Target target;
		struct
		{
			int not_uid;
			uid_t uid;
		};
	};
};

struct BpfData
{
	uid_t uid;
	pid_t pid;
	int is_binary;
	struct Target target;
};

char line[8192];
static int whitelist_fd;
static int log_map_fd;
struct ring_buffer *rb = NULL;
static std::atomic<bool> exit_flag(false);
const char *policy_file = NULL;

static struct option lopts[] = { { "policy-file", required_argument, 0, 'p' },
				 { "help", no_argument, 0, 'h' },
				 { 0, 0, 0, 0 } };

// Structure for help messages
struct HelpMsg
{
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
	printf("  prevent the execution of applications from untrusted sources according to the policy file\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf("  -%c, --%s %s\n\t%s\n", lopts[i].val, lopts[i].name,
		       help_msg[i].argparam, help_msg[i].msg);
	}
}

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
			DIE("Code internal bug!!!\n");
			abort();
		}
	}
	return sopts;
}

void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	std::string sopts = long_opt2short_opt(
		lopts); // Convert long options to short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) >
	       0)
	{
		switch (opt)
		{
		case 'p': // Policy File
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

	if (!policy_file)
	{
		policy_file = "elfverify.pol";
		printf("\nNo policy file specified, use elfverify.pol as default\n\n");
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
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

static void path2target(const char *path, struct Target *target)
{
	if (access(path, F_OK) == -1)
	{
		pr_error("file %s: %s", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct stat st;
	if (stat(path, &st) != 0)
	{
		pr_error("stat %s: %s", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	target->ino = st.st_ino;
	target->dev = dev_old2new(st.st_dev);
	// pr_info("Add file: %x %lu", target->dev, target->ino);
}

static void add_directories_recursively(const char *dir_path,
					const struct Rule *base_rule,
					std::vector<struct Rule> &rules)
{
	struct Rule dir_rule = *base_rule;
	path2target(dir_path, &dir_rule.target);
	rules.emplace_back(dir_rule);

	DIR *dir = opendir(dir_path);
	if (!dir)
	{
		pr_error("Cannot open directory %s: %s", dir_path,
			 strerror(errno));
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		char full_path[PATH_MAX];
		snprintf(full_path, sizeof(full_path), "%s/%s", dir_path,
			 entry->d_name);

		struct stat st;
		if (lstat(full_path, &st) != 0)
		{
			pr_error("Cannot lstat %s: %s", full_path,
				 strerror(errno));
			continue;
		}

		if (S_ISLNK(st.st_mode))
		{
			continue;
		}

		if (S_ISDIR(st.st_mode))
		{
			add_directories_recursively(full_path, base_rule,
						    rules);
		}
	}

	closedir(dir);
}

static void user2uid(const char *user, uid_t *uid)
{
	struct passwd *pw = getpwnam(user);
	if (pw)
	{
		*uid = pw->pw_uid;
	}
	else
	{
		exit(EXIT_FAILURE);
	}
}

std::vector<struct Rule> parse_policy_file(const char *filename)
{
	std::vector<struct Rule> rules;
	FILE *file = fopen(filename, "r");
	if (!file)
	{
		pr_error("fopen: %s: %s", strerror(errno), filename);
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), file))
	{
		char type[5];
		char content[4096];

		if (line[0] == '#')
			continue;

		if (sscanf(line, "%4[^=]=%4095s", type, content) != 2)
		{
			pr_error("Invalid line: %s", line);
			continue;
		}
		struct Rule rule = { 0 };

		if (strcmp(type, "path") == 0)
		{
			struct stat st;
			if (stat(content, &st) != 0)
			{
				pr_error("Cannot access path %s: %s", content,
					 strerror(errno));
				continue;
			}
			if (S_ISDIR(st.st_mode))
			{
				add_directories_recursively(content, &rule,
							    rules);
			}
			else
			{
				path2target(content, &rule.target);
				rules.emplace_back(rule);
			}
		}
		else if (strcmp(type, "user") == 0)
		{
			user2uid(content, &rule.uid);
			rules.emplace_back(rule);
		}

		pr_info("Rule: %s %s", type, content);
	}
	fclose(file);
	return rules;
}

void load_rules(const std::vector<struct Rule> &rules)
{
	uint32_t key = 0;
	for (const auto &rule : rules)
	{
		key++;
		if (bpf_map_update_elem(whitelist_fd, &key, &rule, BPF_ANY) !=
		    0)
		{
			perror("bpf_map_update_elem");
			exit(EXIT_FAILURE);
		}
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log =
		(const struct BpfData *)data; // Cast data to BpfData structure
	pr_info("process %d of user %d tried to execve %s file "
		"(dev: %x, ino: %lu), denied!",
		log->pid, log->uid, log->is_binary ? "binary" : "script",
		log->target.dev, log->target.ino);
	return 0;
}

void ringbuf_worker(void)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
		// Check for errors during polling
		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d", err);
			sleep(5); // Sleep before retrying
		}
	}
}

int main(int argc, char **argv)
{
	std::vector<struct Rule> rules;
	std::thread *rb_thread;

	parse_args(argc, argv);
	register_signal();

	obj = elfverify_bpf::open_and_load();
	if (!obj)
		exit(-1);

	whitelist_fd = bpf_get_map_fd(obj->obj, "whitelist", goto err_out);
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
		goto err_out;
	rules = parse_policy_file(policy_file);
	load_rules(rules);

	pr_info("Program start");
	if (0 != elfverify_bpf::attach(obj))
		exit(-1);

	rb_thread = new std::thread(ringbuf_worker);
	follow_trace_pipe();

	rb_thread->join();
	delete rb_thread;
err_out:
	elfverify_bpf::detach(obj);
	elfverify_bpf::destroy(obj);
	return -1;
}