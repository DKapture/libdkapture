// SPDX-License-Identifier: GPL-2.0

#include <asm/unistd.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>
#include <pthread.h>

#include <string>

#include <linux/netfilter.h>

#include "net-filter.skel.h"
#include "net.h"
#include "net-filter.h"
#include "Ucom.h"
#include "Ulog.h"

void NetFilter::read_trace_pipe(FILE *fp)
{
	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
	{ // this should never happen
		pr_error("fail to open /sys/kernel/debug/tracing/trace_pipe\n");
		return;
	}
	if (fp == nullptr)
		fp = stdout;

	char *buf = (char *)calloc(4096, 1);
	if (!buf)
	{
		pr_error("Failed to allocate buffer from heap\n");
		close(trace_fd);
		return;
	}

	while (1)
	{
		ssize_t sz = read(trace_fd, buf, 4096);
		if (sz > 0)
			fwrite(buf, 1, sz, fp);
		if (sz < 0)
			break;
	}

	free(buf);
	close(trace_fd);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	if (data_sz < sizeof(struct BpfData))
	{
		pr_error("invalid data size: %lu\n", data_sz);
		return 0;
	}
	NetFilter *nf;
	const struct BpfData *log;
	nf = (NetFilter *)ctx;
	log = (const struct BpfData *)data;
	if (nf->log_cb)
		nf->log_cb(*log);

	return 0;
}

static bool check_bpf_env(void)
{
	char *buf = (char *)calloc(4096, 1);
	if (!buf)
	{
		pr_error("Failed to allocate buffer from heap\n");
		return false;
	}
	char fs_type[16];
	std::string securityfs_lsm;
	FILE *mnt_fp = fopen("/proc/self/mountinfo", "r");
	if (mnt_fp == nullptr)
	{
		pr_error("open mountinfo: %s\n", strerror(errno));
		free(buf);
		return false;
	}
	char *line = nullptr;
	size_t len;
	ssize_t rd_sz;

	while ((rd_sz = getline(&line, &len, mnt_fp)) != -1)
	{
		buf[0] = fs_type[0] = '\0';
		sscanf(line, "%*s %*s %*s %*s %4096s %*s %*s %*s %16s %*s %*s",
		       buf, fs_type);
		if (strcmp(fs_type, "securityfs") == 0)
		{
			securityfs_lsm = buf;
			securityfs_lsm += "/lsm";
			break;
		}
	}

	free(line);
	fclose(mnt_fp);

	int fd = open(securityfs_lsm.c_str(), O_RDONLY);
	if (fd < 0)
	{
		pr_error("open %s: %s\n", securityfs_lsm.c_str(),
			 strerror(errno));
		free(buf);
		return false;
	}

	memset(buf, 0, 4096);
	read(fd, buf, 4095); // pr_error ignored
	close(fd);

	bool result = !!strstr(buf, "bpf");
	free(buf);
	return result;
}

int NetFilter::init(LogCallback cb)
{
	union bpf_attr attr = {};
	uid_t uid = getuid();
	if (uid != 0)
	{
		pr_error("bpf must be run as root\n");
		goto err_out;
	}

	if (!check_bpf_env())
	{
		pr_error("bpf-lsm isn't activated,"
			 " process name filtering feature of "
			 "net-monitor won't be available\n");
	}
	obj = net_filter_bpf::open(NULL);
	if (!obj)
	{
		pr_error("fail to open bpf object\n");
		goto err_out;
	}

	// prog fd and map fd already generated in obj after bpf_object__load
	if (net_filter_bpf::load(obj))
	{
		pr_error("loading BPF object file failed\n");
		goto err_out;
	}

	rules_map_fd = bpf_get_map_fd(obj->obj, "rules", goto err_out);
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	conf_map_fd = bpf_get_map_fd(obj->obj, "configs", goto err_out);

	rb = ring_buffer__new(log_map_fd, handle_event, this, NULL);
	if (!rb)
		goto err_out;

	// bpf_links.push_back(bpf_attach_kretprobe(kretprobe_send_prog, "kr_sock_sendmsg"));
	bpf_links.push_back(bpf_attach_kretprobe(obj->progs.kr_sock_sendmsg,
						 "sock_sendmsg"));
	bpf_links.push_back(bpf_attach_kretprobe(obj->progs.kr_sock_sendmsg,
						 "sock_write_iter"));
	bpf_links.push_back(bpf_attach_kretprobe(obj->progs.kr_sock_sendmsg,
						 "__sys_sendto"));
	bpf_links.push_back(bpf_attach_kretprobe(obj->progs.kr_sock_sendmsg,
						 "____sys_sendmsg"));
	bpf_links.push_back(bpf_attach_kretprobe(obj->progs.kr_sock_recvmsg,
						 "sock_recvmsg"));

	link_fds.clear();
	/* attach to netfilter forward handler */
	attr.link_create.prog_fd = bpf_get_prog_fd(obj->progs.netfilter_hook);
	attr.link_create.attach_type = BPF_NETFILTER;
	attr.link_create.netfilter.pf = NFPROTO_IPV4;
	attr.link_create.netfilter.hooknum = NF_INET_LOCAL_OUT;
	attr.link_create.netfilter.priority = -128;

	link_fds.push_back(bpf_syscall(BPF_LINK_CREATE, attr));

	attr.link_create.netfilter.pf = NFPROTO_IPV6;
	link_fds.push_back(bpf_syscall(BPF_LINK_CREATE, attr));

	attr.link_create.netfilter.hooknum = NF_INET_LOCAL_IN;
	link_fds.push_back(bpf_syscall(BPF_LINK_CREATE, attr));

	attr.link_create.netfilter.pf = NFPROTO_IPV4;
	link_fds.push_back(bpf_syscall(BPF_LINK_CREATE, attr));

	memset(&attr.link_create, 0, sizeof(attr.link_create));

#ifndef __loongarch__
	attr.link_create.attach_type = BPF_LSM_MAC;
	attr.link_create.prog_fd =
		bpf_get_prog_fd(obj->progs.lsm_socket_sendmsg);
	link_fds.push_back(bpf_syscall(BPF_LINK_CREATE, attr));

	attr.link_create.prog_fd =
		bpf_get_prog_fd(obj->progs.lsm_socket_recvmsg);
	link_fds.push_back(bpf_syscall(BPF_LINK_CREATE, attr));
#else
	bpf_links.push_back(bpf_attach_kprobe(obj->progs.k_socket_sendmsg,
					      "security_socket_sendmsg"));
	bpf_links.push_back(bpf_attach_kprobe(obj->progs.k_socket_recvmsg,
					      "security_socket_recvmsg"));
#endif

	printf("bpf program/map loaded....\n");
	log_cb = cb;
	conf.enable = true;

	return 0;

err_out:
	deinit();
	return -1;
}

void NetFilter::deinit(void)
{
	for (auto fd : link_fds)
	{
		close(fd);
	}
	link_fds.clear();
	for (auto link : bpf_links)
	{
		bpf_link__destroy(link);
	}
	bpf_links.clear();
	if (rb)
		ring_buffer__free(rb);
	if (obj)
		net_filter_bpf::destroy(obj);
	log_cb = NULL;
	conf.enable = false;
}

int NetFilter::add_rule(const Rule &rule)
{
	int err =
		bpf_map_update_elem(rules_map_fd, &key_cnt, &rule, BPF_NOEXIST);

	if (err == 0)
		return key_cnt++;

	return -1;
}

bool NetFilter::load_rules(const char *rule_file)
{
	FILE *fp = fopen(rule_file, "r");

	if (!fp)
	{
		pr_error("open %s: %s\n", rule_file, strerror(errno));
		return false;
	}

	char *line = NULL;
	size_t len;
	ssize_t read;

	while ((read = getline(&line, &len, fp)) != -1)
	{
		Rule rule;

		if (line[0] == '#' || line[0] == '\n')
		{
			continue;
		}

		if (!parse_rule(line, rule))
			continue;

		int key;
		key = add_rule(rule);

		if (key < 0)
		{
			printf("syntax pr_error in config file\n");
			fclose(fp);
			return false;
		}
	}

	free(line);
	fclose(fp);
	return true;
}

int NetFilter::update_rule(u32 key, const Rule &rule)
{
	int err = bpf_map_update_elem(rules_map_fd, &key_cnt, &rule, BPF_EXIST);

	return err ? -1 : 0;
}

void NetFilter::del_rule(u32 rule_id)
{
	bpf_map_delete_elem(rules_map_fd, &rule_id);
}

void NetFilter::clear_rules(void)
{
	u32 key = 0, nxt_key;
	while (0 == bpf_map_get_next_key(rules_map_fd, &key, &nxt_key))
	{
		bpf_map_delete_elem(rules_map_fd, &nxt_key);
		key = nxt_key;
	}
}

void NetFilter::dump_rules(std::map<u32, Rule> &rules) const
{
	u32 key = 0, nxt_key;
	Rule rule;
	rules.clear();
	while (0 == bpf_map_get_next_key(rules_map_fd, &key, &nxt_key))
	{
		bpf_map_lookup_elem(rules_map_fd, &nxt_key, &rule);
		rules[nxt_key] = rule;

		key = nxt_key;
	}
}

void NetFilter::set_bpf_debug(int type)
{
	int key = 0;
	conf.debug = type;
	if (0 != bpf_map_update_elem(conf_map_fd, &key, &conf, BPF_ANY))
		pr_error("set_bpf_debug\n");
}

void NetFilter::enable(bool state)
{
	int key = 0;
	conf.debug = state;
	if (0 != bpf_map_update_elem(conf_map_fd, &key, &conf, BPF_ANY))
		pr_error("%s net-monitor\n", state ? "enable" : "disable");
}

void NetFilter::loop(void)
{
	loop_flag = true;

	while (loop_flag)
	{
		int err = ring_buffer__poll(rb, 1000 /* timeout, ms */);

		/* The callback handle_event returns pr_error*/
		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d\n", err);
			sleep(5);
		}
	}
}

void NetFilter::exit(void)
{
	loop_flag = false;
	if (trace_fd >= 0)
	{
		close(trace_fd);
		trace_fd = -1;
	}
}

static void parse_area(char *str, char *out1, char *out2, size_t sz)
{
	char *token;
	token = strtok(str, "--");
	strncpy(out1, token, sz);
	token = strtok(NULL, "--");
	strncpy(out2, token, sz);
	out1[sz - 1] = 0;
	out2[sz - 1] = 0;
}

static int parse_ip(char *ip_str, void *ips, void *ipe, bool is_ipv6)
{
	char begin[40] = { 0 }, end[40] = { 0 };
	struct in_addr ip;
	struct in6_addr ipv6;

#define return_error(msg)                                 \
	{                                                 \
		pr_error("invalid rule part: %s\n", msg); \
		return -1;                                \
	}

	if (strstr(ip_str, "--"))
	{
		// ip start
		parse_area(ip_str, begin, end, 40);
		if (!is_ipv6 && inet_pton(AF_INET, begin, &ip) == 1)
		{
			u32 tmp = ntohl(ip.s_addr);
			memmove(ips, &tmp, sizeof(tmp));
		}
		else if (is_ipv6 && inet_pton(AF_INET6, begin, &ipv6) == 1)
		{
			ntoh16(&ipv6);
			memmove(ips, &ipv6, sizeof(ipv6));
		}
		else
		{
			return_error(begin);
		}
		// ip end
		if (!is_ipv6 && inet_pton(AF_INET, end, &ip) == 1)
		{
			u32 tmp = ntohl(ip.s_addr);
			memmove(ipe, &tmp, sizeof(tmp));
		}
		else if (is_ipv6 && inet_pton(AF_INET6, end, &ipv6) == 1)
		{
			ntoh16(&ipv6);
			memmove(ipe, &ipv6, sizeof(ipv6));
		}
		else
		{
			return_error(end);
		}
	}
	else
	{
		if (!is_ipv6 && inet_pton(AF_INET, ip_str, &ip) == 1)
		{
			u32 tmp = ntohl(ip.s_addr);
			memmove(ips, &tmp, sizeof(tmp));
			memmove(ipe, &tmp, sizeof(tmp));
		}
		else if (is_ipv6 && inet_pton(AF_INET6, ip_str, &ipv6) == 1)
		{
			ntoh16(&ipv6);
			memmove(ips, &ipv6, sizeof(ipv6));
			memmove(ipe, &ipv6, sizeof(ipv6));
		}
		else
		{
			return_error(ip_str);
		}
	}
	return 0;
}

static int parse_port(char *port_str, u16 &sport, u16 &dport)
{
	char begin[8], end[8];

#define return_if_invalid(p, msg, ep)                             \
	{                                                         \
		if (p < 0 || p > 65535 || msg == ep)              \
		{                                                 \
			pr_error("invalid rule part: %s\n", msg); \
			return -1;                                \
		}                                                 \
	}

	int n;
	char *tmp;
	if (strstr(port_str, "--"))
	{
		parse_area(port_str, begin, end, 8);
		n = strtol(begin, &tmp, 10);
		return_if_invalid(n, begin, tmp);
		sport = (u16)n;
		n = strtol(end, NULL, 10);
		return_if_invalid(n, end, tmp);
		dport = (u16)n;
	}
	else
	{
		n = strtol(port_str, NULL, 10);
		return_if_invalid(n, begin, tmp);
		sport = (u16)n;
		dport = sport;
	}
	return 0;
}

static int parse_ip_pair(char *ip1, char *ip2, char *sport, char *dport,
			 char *protocol, struct Rule &rule)
{
	bool is_ipv6 = rule.ip_proto == 6;
	// src ip
	if (0 != parse_ip(ip1, &rule.sip, &rule.sip_end, is_ipv6))
		return -1;

	// dst ip
	if (0 != parse_ip(ip2, &rule.dip, &rule.dip_end, is_ipv6))
		return -1;

	// src port
	if (0 != parse_port(sport, rule.sport, rule.sport_end))
		return -1;

	// dst port
	if (0 != parse_port(dport, rule.dport, rule.dport_end))
		return -1;

	// protocol
	if (strcasecmp(protocol, "TCP") == 0)
	{
		rule.tl_proto = IPPROTO_TCP;
	}
	else if (strcasecmp(protocol, "UDP") == 0)
	{
		rule.tl_proto = IPPROTO_UDP;
	}
	else if (strcasecmp(protocol, "icmp") == 0)
	{
		rule.tl_proto = rule.ip_proto == 4 ? (u8)IPPROTO_ICMP :
						     (u8)IPPROTO_ICMPV6;
		if (rule.comm[0] != 0)
		{
			pr_error(
				"filter comm(%s) can't work with protocol icmp\n",
				rule.comm);
			return -1;
		}
	}
	else
	{
		pr_error("unsupported protocol: %s\n", protocol);
		return -1;
	}
	return 0;
}

static int parse_action(const char *act_str)
{
	std::string act = ",";
	act += act_str;
	act += ',';
	int action = 0;
	if (act.find(",drop,") != std::string::npos)
		action |= NM_DROP;

	if (act.find(",log,") != std::string::npos)
		action |= NM_LOG;

	return action;
}

static int parse_pkg_dir(const char *dir_str)
{
	if (!dir_str[0])
		return PKG_DIR_ANY;

	if (strncasecmp(dir_str, "/in", 3) == 0)
		return PKG_DIR_IN;

	if (strncasecmp(dir_str, "/out", 4) == 0)
		return PKG_DIR_OUT;

	if (strncasecmp(dir_str, "/any", 4) == 0)
		return PKG_DIR_ANY;

	pr_error("rule syntax pr_error: %s. 'any' is applied\n", dir_str);
	return PKG_DIR_ANY;
}

bool NetFilter::parse_rule(const char *line, Rule &rule)
{
	while (*line == ' ') // skip prefix spaces
		line++;

	memset(&rule, 0, sizeof(rule));
	int ret = 0;
	char family[10] = {};
	char saddr[88] = {};
	char daddr[88] = {};
	char sport[16] = {};
	char dport[16] = {};
	char protocol[6] = {};
	char action[32] = {};
	char process_name[16] = { 0 };

	ret = sscanf(line, "%9s %87s %87s %15s %15s %5s %31s %15s", family,
		     saddr, daddr, sport, dport, protocol, action,
		     process_name);

	if (ret < 7)
	{
		pr_error("at least 7 parameters needed\n");
		goto err_out;
	}

	if (strncmp(family, "ipv4", 4) == 0)
	{
		rule.ip_proto = 4;
	}
	else if (strncmp(family, "ipv6", 4) == 0)
	{
		rule.ip_proto = 6;
	}
	else
	{
		pr_error("need to specify ipv4/ipv6\n");
		goto err_out;
	}

	strncpy(rule.comm, process_name, 16);
	rule.action = parse_action(action);
	rule.pkg_dir = parse_pkg_dir(family + 4);

	ret = parse_ip_pair(saddr, daddr, sport, dport, protocol, rule);
	if (ret != 0)
		goto err_out;

	return true;

err_out:
	printf("in rule: %s\n", line);
	return false;
}

#define DEFAULT_POLI_PATH "/etc/net-monitor/"
#define DEFAULT_BPF_PATH "/lib/net-monitor-bpf/"
#define DEFAULT_LOG_PATH "/var/log/net-monitor/"

#define SIZE_1M (1024 * 1024)

#define LOG(fmt, args...)                                         \
	{                                                         \
		printf("[%s]: " fmt, get_time().c_str(), ##args); \
		fflush(stdout);                                   \
	}

static std::string log_path;
std::string poli_path = DEFAULT_POLI_PATH "policy.conf";
std::string bpf_path = DEFAULT_BPF_PATH "/net-monitor.bpf.o";
static bool exit_flag = false;
int dbg_lvl = DEBUG_NONE;
static pthread_t log_thread;
static pthread_t trace_pipe_thread;

NetFilter nf;

static std::string get_date(void)
{
	char buffer[20] = { 0 };
	time_t timestamp = time(NULL);
	struct tm *info = localtime(&timestamp);
	if (!info)
		return "";
	strftime(buffer, sizeof buffer, "%Y-%m-%d", info);

	return std::string(buffer);
}

static const char *proto_str(u8 proto)
{
	const char *str = "";
	switch (proto)
	{
	case IPPROTO_UDP:
		str = "udp";
		break;
	case IPPROTO_TCP:
		str = "tcp";
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		str = "icmp";
		break;

	default:
		printf("=========== coding pr_error ===========\n");
		abort();
		break;
	}
	return str;
}

void print_rule(const Rule &rule)
{
	LOG("============== rule ==============\n");
	if (rule.ip_proto == 4)
	{
		LOG("src: %u.%u.%u.%u-%u.%u.%u.%u : %u-%u\n",
		    SLICE_IP(rule.sip), SLICE_IP(rule.sip_end), rule.sport,
		    rule.sport_end);
		LOG("dst: %u.%u.%u.%u-%u.%u.%u.%u : %u-%u\n",
		    SLICE_IP(rule.dip), SLICE_IP(rule.dip_end), rule.dport,
		    rule.dport_end);
	}
	else
	{
		LOG("src: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x-"
		    "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x : %u-%u\n",
		    SLICE_IPv6(rule.sipv6), SLICE_IPv6(rule.sipv6_end),
		    rule.sport, rule.sport_end);
		LOG("dst: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x-"
		    "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x : %u-%u\n",
		    SLICE_IPv6(rule.dipv6), SLICE_IPv6(rule.dipv6_end),
		    rule.sport, rule.sport_end);
	}

	const char *pkg_dir;
	switch (rule.pkg_dir)
	{
	case PKG_DIR_IN:
		pkg_dir = "in";
		break;
	case PKG_DIR_OUT:
		pkg_dir = "out";
		break;
	case PKG_DIR_ANY:
		pkg_dir = "any";
		break;

	default:
		printf("coding pr_error\n");
		abort();
		break;
	}
	LOG("pkg_dir: %s\n", pkg_dir);

	std::string action;
	if (rule.action & NM_DROP)
		action += "drop,";
	if (rule.action & NM_LOG)
		action += "log,";

	if (!action.empty())
		action.pop_back();

	const char *proto = proto_str(rule.tl_proto);
	LOG("proto: %s\n", proto);
	LOG("comm: %s\n", rule.comm);
	LOG("action: %s\n\n", action.c_str());
}

void sig_handle(int)
{
	exit_flag = true;
	nf.exit();
}

static struct option lopts[] = { { "policy", required_argument, 0, 'p' },
				 { "help", no_argument, 0, 'h' },
				 { "debug", optional_argument, 0, 'd' },
				 { 0, 0, 0, 0 } };

struct HelpMsg
{
	const char *argparam;
	const char *msg;
};

static HelpMsg help_msg[] = {
	{ "<path>", "set the policy file path\n"
		    "\tdefault: " DEFAULT_POLI_PATH "policy.conf\n" },
	{ "", "print this help message\n" },
	{ "[level]", "set debug log level:\n"
		     "\t0: no debug(default)\n"
		     "\t1: output TCP package capture with LSM\n"
		     "\t2: output UDP package capture with LSM\n"
		     "\t3: output ICMP package capture with LSM\n"
		     "\t4: output all package capture with LSM\n"
		     "\t5: outtput TCP package capture with NETFILTER\n"
		     "\t6: outtput UDP package capture with NETFILTER\n"
		     "\t7: outtput ICMP package capture with NETFILTER\n"
		     "\t8: outtput all package capture with NETFILTER\n"
		     "\t9: outtput all package capture while rule matching\n" },
};

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
			printf("code internal bug!!!\n");
			abort();
			break;
		}
	}
	return sopts;
}

void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf("  -%c, --%s %s\n\t%s\n", lopts[i].val, lopts[i].name,
		       help_msg[i].argparam, help_msg[i].msg);
	}
}

void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	optind = 1;
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) >
	       0)
	{
		switch (opt)
		{
		case 'b':
			bpf_path = optarg;
			break;
		case 'p':
			poli_path = optarg;
			break;
		case 'h':
			Usage(argv[0]);
			exit(0);
			break;
		case 'd':
			dbg_lvl = DEBUG_NONE;
			if (optarg)
			{
				dbg_lvl = strtol(optarg, NULL, 10);
			}
			break;

		default:
			Usage(argv[0]);
			exit(-1);
			break;
		}
	}
}

void *log_maintainor(void *)
{
	while (!exit_flag)
	{
		sleep(60);
		std::string tmp = DEFAULT_LOG_PATH + get_date() + ".log";
		if (tmp == log_path)
			continue;

		log_path = tmp;
		freopen(log_path.c_str(), "a+", stdout);
	}
	return NULL;
}

void log_printer(const struct BpfData &log)
{
	struct ip_tuple tuple = log.tuple;
	if (tuple.pkg_dir == PKG_DIR_IN)
	{
		std::swap(tuple.sport, tuple.dport);
		std::swap(tuple.sipv6, tuple.dipv6);
	}
	if (tuple.ip_proto == 4)
	{
		LOG("%llu (%s:%d) %s %d.%d.%d.%d:%d %s %d.%d.%d.%d:%d sz(%d)\n",
		    log.timestamp, tuple.comm, log.pid,
		    proto_str(tuple.tl_proto), SLICE_IP(tuple.sip), tuple.sport,
		    tuple.pkg_dir == PKG_DIR_IN ? "<-" : "->",
		    SLICE_IP(tuple.dip), tuple.dport, log.data_len);
	}
	else
	{
		LOG("%llu (%s:%d) %s %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%d "
		    "%s %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%d sz(%d)\n",
		    log.timestamp, tuple.comm, log.pid,
		    proto_str(tuple.tl_proto), SLICE_IPv6(tuple.sipv6),
		    tuple.sport, tuple.pkg_dir == PKG_DIR_IN ? "<-" : "->",
		    SLICE_IPv6(tuple.dipv6), tuple.dport, log.data_len);
	}
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);
	signal(SIGINT, sig_handle);
	atexit([]() {
		exit_flag = true;
		LOG("*************** net-monitor exited ***************\n");
	});

	log_path = DEFAULT_LOG_PATH + get_date() + ".log";

	if (getppid() == 1)
	{
		mkdir(DEFAULT_LOG_PATH, 0644);
		freopen(log_path.c_str(), "a+", stdout);
	}

	pthread_create(&log_thread, NULL, log_maintainor, NULL);

	LOG("************ new start for net-monitor ************\n");

	if (0 != nf.init(log_printer))
	{
		return -1;
	}

	// if (!nf.load_rules(poli_path.c_str()))
	// 	return -1;
	struct Rule rule;
	if (!NetFilter::parse_rule("ipv4 0.0.0.0 0.0.0.0 0 0 tcp log", rule))
	{
		pr_error("rule parse pr_error: %s\n", strerror(errno));
		return -1;
	}
	nf.add_rule(rule);

	std::map<u32, Rule> rules;
	nf.dump_rules(rules);
	LOG("rules size: %lu\n", rules.size());
	for (auto &it : rules)
		print_rule(it.second);

	if (dbg_lvl != DEBUG_NONE)
	{
		pthread_create(
			&trace_pipe_thread, NULL,
			[](void *) -> void * {
				NetFilter::read_trace_pipe();
				return nullptr;
			},
			NULL);
	}

	nf.set_bpf_debug(dbg_lvl);
	nf.loop();
	nf.clear_rules();
	rules.clear();
	nf.dump_rules(rules);
	LOG("rules size after cleaning: %lu\n", rules.size());

	nf.deinit();
	pthread_kill(log_thread, SIGINT);
	pthread_join(log_thread, NULL);
	if (trace_pipe_thread)
	{
		pthread_kill(trace_pipe_thread, SIGINT);
		pthread_join(trace_pipe_thread, NULL);
	}
	return 0;
}