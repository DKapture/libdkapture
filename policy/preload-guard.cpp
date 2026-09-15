// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

/**
 * @file preload-guard.cpp
 * @brief LD_PRELOAD 环境变量监测与管控用户空间程序
 */

#include "log.h"

#include <atomic>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/limits.h>
#include <map>
#include <pwd.h>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

#include "com.h"
#include "preload-guard.skel.h"

struct Target
{
	uint32_t dev;
	uint64_t ino;
};

struct AuditEvent
{
	uint32_t type;
	pid_t pid;
	uint32_t uid;
	char comm[16];
	char preload_val[64];
	struct Target so_target;
};

struct Config
{
	uint32_t enforce;
	uint32_t reserved[7];
};

struct RuleUid
{
	uint32_t uid;
};

static preload_guard_bpf *obj = nullptr;
static int allowed_so_fd = -1;
static int allowed_uid_fd = -1;
static int config_fd = -1;
static int log_map_fd = -1;
static struct ring_buffer *rb = nullptr;
static std::atomic<bool> exit_flag(false);
static const char *policy_file = nullptr;
static int enforce_mode = 0;
static std::map<std::string, std::tuple<dev_t, ino_t>> system_lib_cache;

static struct option lopts[] = {
	{"policy-file", required_argument, 0, 'p'},
	{"enforce", no_argument, 0, 'e'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

struct HelpMsg
{
	const char *argparam;
	const char *msg;
};

static HelpMsg help_msg[] = {
	{"<policy-file>", "specify the whitelist policy file\n"},
	{"", "enable enforce mode (block unlisted .so loading)\n"},
	{"", "print this help message\n"},
};

static inline uint32_t dev_old2new(dev_t old)
{
	uint32_t major = gnu_dev_major(old);
	uint32_t minor = gnu_dev_minor(old);
	return ((major & 0xfff) << 20) | (minor & 0xfffff);
}

static void usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  Monitor and control LD_PRELOAD usage via eBPF.\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf("  -%c, --%s %s\t%s",
		       lopts[i].val,
		       lopts[i].name,
		       help_msg[i].argparam,
		       help_msg[i].msg);
	}
	printf("\nPolicy file format:\n");
	printf("  # Comment lines start with #\n");
	printf("  so=<path/to/library.so>  # Whitelist a shared library or directory\n");
	printf("  uid=<username>           # Whitelist a user (all preloads allowed)\n");
}

static std::string long_opt2short_opt(const option opts[])
{
	std::string sopts;
	for (int i = 0; opts[i].name; i++)
	{
		sopts += opts[i].val;
		switch (opts[i].has_arg)
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
			abort();
		}
	}
	return sopts;
}

static void register_signal(void)
{
	struct sigaction sa = {};
	sa.sa_handler = [](int) { exit_flag = true; };
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);
}

static void parse_args(int argc, char **argv)
{
	std::string sopts = long_opt2short_opt(lopts);
	int opt = 0;

	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, nullptr)) != -1)
	{
		switch (opt)
		{
		case 'p':
			policy_file = optarg;
			break;
		case 'e':
			enforce_mode = 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}

static void path2target(const char *path, struct Target *target)
{
	struct stat st = {};
	if (stat(path, &st) == 0)
	{
		target->dev = dev_old2new(st.st_dev);
		target->ino = st.st_ino;
	}
}

static void user2uid(const char *user, uid_t *uid)
{
	struct passwd *pw = getpwnam(user);
	if (!pw)
	{
		pr_error("user not found: %s", user);
		exit(EXIT_FAILURE);
	}
	*uid = pw->pw_uid;
}

static void collect_dir(const char *dir_path)
{
	DIR *dir = opendir(dir_path);
	if (!dir)
		return;

	struct dirent *entry = nullptr;
	while ((entry = readdir(dir)) != nullptr)
	{
		if (entry->d_type == DT_DIR)
		{
			if (strcmp(entry->d_name, ".") == 0 ||
			    strcmp(entry->d_name, "..") == 0)
				continue;

			char sub[PATH_MAX];
			snprintf(sub, sizeof(sub), "%s/%s", dir_path, entry->d_name);
			collect_dir(sub);
			continue;
		}

		if (entry->d_type != DT_REG && entry->d_type != DT_LNK &&
		    entry->d_type != DT_UNKNOWN)
			continue;

		std::string name = entry->d_name;
		if (name.find(".so") == std::string::npos)
			continue;

		std::string full = std::string(dir_path) + "/" + name;
		struct stat st = {};
		if (stat(full.c_str(), &st) == 0)
			system_lib_cache[full] = std::make_tuple(st.st_dev, st.st_ino);
	}

	closedir(dir);
}

static void collect_system_libs(void)
{
	const char *lib_dirs[] = {
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		"/lib/x86_64-linux-gnu",
		"/lib/aarch64-linux-gnu",
		"/lib/loongarch64-linux-gnu",
		nullptr,
	};

	for (int d = 0; lib_dirs[d]; d++)
		collect_dir(lib_dirs[d]);

	pr_info("Collected %zu system libraries into cache", system_lib_cache.size());
}

static void add_library_rule(const char *path)
{
	struct Target target = {};
	uint8_t allow = 1;

	path2target(path, &target);
	if (!target.dev || !target.ino)
	{
		pr_warn("skip invalid library target: %s", path);
		return;
	}

	if (bpf_map_update_elem(allowed_so_fd, &target, &allow, BPF_ANY) != 0)
	{
		pr_error("bpf_map_update_elem allowed_so failed for %s: %s",
		         path, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void add_libraries_recursively(const char *dir_path)
{
	DIR *dir = opendir(dir_path);
	if (!dir)
		return;

	struct dirent *entry = nullptr;
	while ((entry = readdir(dir)) != nullptr)
	{
		if (entry->d_type == DT_DIR)
		{
			if (strcmp(entry->d_name, ".") == 0 ||
			    strcmp(entry->d_name, "..") == 0)
				continue;

			char full_path[PATH_MAX];
			snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
			add_libraries_recursively(full_path);
			continue;
		}

		if (entry->d_type != DT_REG && entry->d_type != DT_LNK &&
		    entry->d_type != DT_UNKNOWN)
			continue;

		std::string name = entry->d_name;
		if (name.find(".so") == std::string::npos)
			continue;

		char full_path[PATH_MAX];
		snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
		add_library_rule(full_path);
	}

	closedir(dir);
}

static void load_default_system_rules(void)
{
	size_t count = 0;
	for (const auto &kv : system_lib_cache)
	{
		add_library_rule(kv.first.c_str());
		count++;
	}
	pr_info("Loaded %zu system library rules (auto mode)", count);
}

static void load_policy_file(const char *filename)
{
	FILE *file = fopen(filename, "r");
	if (!file)
	{
		pr_error("fopen %s failed: %s", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	size_t so_rules = 0;
	size_t uid_rules = 0;
	char line[8192];

	while (fgets(line, sizeof(line), file))
	{
		char type[16] = {};
		char content[4096] = {};

		if (line[0] == '#' || line[0] == '\n')
			continue;

		if (sscanf(line, "%15[^=]=%4095s", type, content) != 2)
			continue;

		if (strcmp(type, "so") == 0)
		{
			struct stat st = {};
			if (stat(content, &st) != 0)
			{
				pr_error("Cannot access %s: %s", content, strerror(errno));
				continue;
			}

			if (S_ISDIR(st.st_mode))
			{
				add_libraries_recursively(content);
			}
			else
			{
				add_library_rule(content);
			}
			so_rules++;
		}
		else if (strcmp(type, "uid") == 0)
		{
			struct RuleUid rule = {};
			uint8_t allow = 1;
			user2uid(content, &rule.uid);
			if (bpf_map_update_elem(allowed_uid_fd, &rule.uid, &allow, BPF_ANY) != 0)
			{
				pr_error("bpf_map_update_elem allowed_uid failed for %s: %s",
				         content, strerror(errno));
				fclose(file);
				exit(EXIT_FAILURE);
			}
			uid_rules++;
		}

		pr_info("Rule: %s=%s", type, content);
	}

	fclose(file);
	pr_info("Loaded %zu so-rules and %zu uid-rules", so_rules, uid_rules);
}

static void set_config(void)
{
	uint32_t key = 0;
	struct Config cfg = {};
	cfg.enforce = enforce_mode;

	if (bpf_map_update_elem(config_fd, &key, &cfg, BPF_ANY) != 0)
	{
		pr_error("bpf_map_update_elem config failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	pr_info("Mode: %s", enforce_mode ? "ENFORCE" : "MONITOR");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	const struct AuditEvent *ev = static_cast<const struct AuditEvent *>(data);

	if (data_sz < sizeof(*ev))
		return 0;

	if (ev->type == 0)
	{
		pr_info("[DETECT] pid=%u uid=%u comm=%s LD_PRELOAD=%s",
		        ev->pid, ev->uid, ev->comm, ev->preload_val);
	}
	else if (ev->type == 1)
	{
		pr_warn("[BLOCK] pid=%u uid=%u comm=%s blocked .so load (dev=%x ino=%lu)",
		        ev->pid, ev->uid, ev->comm,
		        ev->so_target.dev, ev->so_target.ino);
	}
	else if (ev->type == 2)
	{
		pr_warn("[BLOCK] pid=%u uid=%u comm=%s env entries exceed limit",
		        ev->pid, ev->uid, ev->comm);
	}

	return 0;
}

static void ringbuf_worker(void)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(rb, 1000);
		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d", err);
			sleep(1);
		}
	}
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);
	register_signal();
	collect_system_libs();

	obj = preload_guard_bpf::open_and_load();
	if (!obj)
	{
		pr_error("failed to open and load preload-guard BPF object");
		return EXIT_FAILURE;
	}

	allowed_so_fd = bpf_get_map_fd(obj->obj, "allowed_so", goto err_out);
	allowed_uid_fd = bpf_get_map_fd(obj->obj, "allowed_uid", goto err_out);
	config_fd = bpf_get_map_fd(obj->obj, "pg_config", goto err_out);
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);

	rb = ring_buffer__new(log_map_fd, handle_event, nullptr, nullptr);
	if (!rb)
	{
		pr_error("failed to create ring buffer");
		goto err_out;
	}

	if (policy_file)
		load_policy_file(policy_file);
	else
		load_default_system_rules();

	set_config();

	if (preload_guard_bpf::attach(obj) != 0)
	{
		pr_error("failed to attach preload-guard BPF programs");
		goto err_out;
	}

	pr_info("preload-guard started (mode=%s)",
	        enforce_mode ? "enforce" : "monitor");

	{
		std::thread rb_thread(ringbuf_worker);
		while (!exit_flag)
			sleep(1);
		rb_thread.join();
	}

	ring_buffer__free(rb);
	preload_guard_bpf::destroy(obj);
	return EXIT_SUCCESS;

err_out:
	if (rb)
		ring_buffer__free(rb);
	if (obj)
		preload_guard_bpf::destroy(obj);
	return EXIT_FAILURE;
}
