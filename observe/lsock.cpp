// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <signal.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <vector>
#include <thread>
#include <atomic>
#include <map>
#include <stdexcept>
#include <algorithm>

#include "com.h"

#include "lsock.skel.h"
#include "types.h"
#include "dkapture.h"
#include "net.h"
#include <sys/mman.h>

#define ITER_PASS_STRING 0

#define SWITCH_TCP (1 << 0)
#define SWITCH_UDP (1 << 1)
#define SWITCH_UNX (1 << 2)
#define SWITCH_IPV4 (1 << 8)
#define SWITCH_IPV6 (1 << 9)
#define SWITCH_ALL (0xffffffff)

enum
{
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_MAX_STATES = 13,
};

enum LogType
{
	LOG_UNIX,
	LOG_UDP_IPV4,
	LOG_UDP_IPV6,
	LOG_TCP_IPV4,
	LOG_TCP_IPV6,
};

static lsock_bpf *obj;

struct Rule
{
	u32 bit_switch;

	unsigned int lip;
	unsigned int rip;
	unsigned int lip_end;
	unsigned int rip_end;

	struct in6_addr lipv6;
	struct in6_addr ripv6;
	struct in6_addr lipv6_end;
	struct in6_addr ripv6_end;

	unsigned short lport;
	unsigned short rport;
	unsigned short lport_end;
	unsigned short rport_end;
	uid_t uid;
};

struct BpfData
{
	union
	{
		unsigned int lip; // local ip address
		struct in6_addr lipv6;
	};
	union
	{
		unsigned int rip; // remote ip address
		struct in6_addr ripv6;
	};

	u16 lport; // local port
	u16 rport; // remote port
	int state;

	u32 tx_queue;
	u32 rx_queue;

	union
	{
		u16 sk_type; // for unix socket
		int tr;
	};
	enum LogType log_type;

	u8 retrnsmt; // 重传次数
	u8 timeout;
	uid_t uid;
	char sk_addr[18];

	u64 tm_when;
	u64 ino;
	// fields below normally used for debug only
	u64 icsk_rto;
	u64 icsk_ack;
	u32 bit_flags;
	u32 snd_cwnd; // 发送窗口大小
	u32 sk_ref;
	union
	{
		int plen;	  // path length for unix socket
		int ssthresh; // slow start thresh
	};
	char path[]; // for unix socket only
};

struct TaskSock
{
	pid_t pid;
	u32 fd;
	char comm[16];
	u64 ino;
	unsigned int family; // 套接字协议族，例如 AF_INET, AF_INET6 等
	unsigned int type;	 // 套接字类型，例如 SOCK_STREAM, SOCK_DGRAM 等
	unsigned int protocol;
	unsigned int state; // 套接字状态，例如 TCP_ESTABLISHED, TCP_LISTEN 等
	union
	{ // 本地 IP 地址，使用网络字节序
		u32 lip;
		struct in6_addr lipv6;
	};
	union
	{ // 远程 IP 地址，使用网络字节序
		u32 rip;
		struct in6_addr ripv6;
	};
	short lport; // 本地端口
	short rport; // 远端端口
};

#ifndef BUILTIN
static struct Rule rule = {};
static int filter_fd;
static std::atomic<bool> exit_flag(false);
static std::vector<int> iter_fds;
static Trace trace;
static std::map<pid_t, std::vector<TaskSock>> task_sock;
static std::map<u64 /* inode */, std::vector<TaskSock>> sock_task;
static std::map<u64 /* inode */, BpfData> sock_info;

static struct option lopts[] = {
	{"sip",	required_argument, 0, 'i'},
	{"dip",	required_argument, 0, 'I'},
	{"sport",  required_argument, 0, 'p'},
	{"dport",  required_argument, 0, 'P'},
	{"tcp",	no_argument,		 0, 't'},
	{"udp",	no_argument,		 0, 'u'},
	{"unix",	 no_argument,		  0, 'x'},
	{"ipv4",	 no_argument,		  0, '4'},
	{"ipv6",	 no_argument,		  0, '6'},
	{"listen", no_argument,		0, 'l'},
	{"help",	 no_argument,		  0, 'h'},
	{0,		0,				 0, 0  }
};

// Structure for help messages
struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg;	  // Help message
};

// Help messages
static HelpMsg help_msg[] = {
	{"<source ip>",	"process name to filter\n"		  },
	{"<dest ip>",	  "process id to filter\n"			  },
	{"<source port>", "remote ip to filter\n"			 },
	{"<dest port>",	"remote port to filter\n"			 },
	{"",			  "filter tcp socket\n"				  },
	{"",			  "filter udp socket\n"				  },
	{"",			  "filter unix socket\n"			   },
	{"",			  "filter ipv4 socket\n"			   },
	{"",			  "filter ipv6 socket\n"			   },
	{"",			  "filter socket in state LISTENING\n"},
	{"",			  "print this help message\n"			},
};

// Function to print usage information
void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  list the sockets that the system is using\n\n");
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
// Helper function to parse IP range
u32 parse_ip_range(
	const char *arg,
	unsigned int &start,
	unsigned int &end,
	struct in6_addr &start_v6,
	struct in6_addr &end_v6
)
{
	start = end = 0;
	memset(&start_v6, 0, sizeof(start_v6));
	memset(&end_v6, 0, sizeof(end_v6));

	std::string input(arg);
	size_t dash_pos = input.find('-');
	if (dash_pos == std::string::npos)
	{
		// Single IP
		if (inet_pton(AF_INET, arg, &start) == 1)
		{
			end = start;
			return SWITCH_IPV4;
		}
		else if (inet_pton(AF_INET6, arg, &start_v6) == 1)
		{
			end_v6 = start_v6;
			return SWITCH_IPV6;
		}
		else
		{
			throw std::invalid_argument("Invalid IP address format");
		}
	}
	else
	{
		// IP range
		std::string start_ip = input.substr(0, dash_pos);
		std::string end_ip = input.substr(dash_pos + 1);
		if (inet_pton(AF_INET, start_ip.c_str(), &start) == 1 &&
			inet_pton(AF_INET, end_ip.c_str(), &end) == 1)
		{
			return SWITCH_IPV4;
		}
		else if (inet_pton(AF_INET6, start_ip.c_str(), &start_v6) ==
				 1 &&
			 inet_pton(AF_INET6, end_ip.c_str(), &end_v6) == 1)
		{
			return SWITCH_IPV6;
		}
		else
		{
			throw std::invalid_argument("Invalid IP range format");
		}
	}
}

// Helper function to parse port range
void parse_port_range(
	const char *arg,
	unsigned short &start,
	unsigned short &end
)
{
	std::string input(arg);
	size_t dash_pos = input.find('-');
	if (dash_pos == std::string::npos)
	{
		// Single port
		start = end = static_cast<unsigned short>(std::stoi(input));
	}
	else
	{
		// Port range
		std::string start_port = input.substr(0, dash_pos);
		std::string end_port = input.substr(dash_pos + 1);
		start = static_cast<unsigned short>(std::stoi(start_port));
		end = static_cast<unsigned short>(std::stoi(end_port));
	}
}

// Parse command line arguments
void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	u32 bit_switch = 0;
	bool has_ip = false;
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'i': // Source IP
			has_ip = true;
			try
			{
				bit_switch |= parse_ip_range(
					optarg,
					rule.lip,
					rule.lip_end,
					rule.lipv6,
					rule.lipv6_end
				);
			}
			catch (const std::exception &e)
			{
				fprintf(stderr, "Error parsing source IP: %s\n", e.what());
				exit(-1);
			}
			break;
		case 'I': // Destination IP
			has_ip = true;
			try
			{
				bit_switch |= parse_ip_range(
					optarg,
					rule.rip,
					rule.rip_end,
					rule.ripv6,
					rule.ripv6_end
				);
			}
			catch (const std::exception &e)
			{
				fprintf(stderr, "Error parsing destination IP: %s\n", e.what());
				exit(-1);
			}
			break;
		case 'p': // Source port
			try
			{
				parse_port_range(optarg, rule.lport, rule.lport_end);
			}
			catch (const std::exception &e)
			{
				fprintf(stderr, "Error parsing source port: %s\n", e.what());
				exit(-1);
			}
			break;
		case 'P': // Destination port
			try
			{
				parse_port_range(optarg, rule.rport, rule.rport_end);
			}
			catch (const std::exception &e)
			{
				fprintf(
					stderr,
					"Error parsing destination port: %s\n",
					e.what()
				);
				exit(-1);
			}
			break;
		case 't':
			bit_switch |= SWITCH_TCP;
			break;
		case 'u':
			bit_switch |= SWITCH_UDP;
			break;
		case 'x':
			bit_switch |= SWITCH_UNX;
			break;
		case '4':
			bit_switch |= SWITCH_IPV4;
			break;
		case '6':
			bit_switch |= SWITCH_IPV6;
			break;
		case 'l':
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
	if (bit_switch)
	{
		if (has_ip && (bit_switch & SWITCH_IPV4) && (bit_switch & SWITCH_IPV6))
		{
			fprintf(stderr, "IP address type conflict\n");
			exit(-1);
		}
		rule.bit_switch = bit_switch;
	}
	if ((rule.bit_switch & (SWITCH_IPV4 | SWITCH_IPV6)) == 0)
	{
		rule.bit_switch |= (SWITCH_IPV4 | SWITCH_IPV6);
	}
	if (rule.bit_switch & (SWITCH_IPV4 | SWITCH_IPV6) &&
		(rule.bit_switch & (SWITCH_TCP | SWITCH_UDP)) == 0)
	{
		rule.bit_switch |= (SWITCH_TCP | SWITCH_UDP);
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

static void rule_init()
{
	rule.bit_switch = SWITCH_ALL;
	rule.uid = -1;
}

static const char *unix_titles = "Num               "
								 "RefCount "
								 "Protocol "
								 "Flags    "
								 "Type "
								 "St    "
								 "Inode "
								 "Path";

static const char *tcp_titles = "  sl  "
								"local_address "
								"rem_address   "
								"st "
								"tx_queue "
								"rx_queue "
								"tr "
								"tm->when "
								"retrnsmt   "
								"uid  "
								"timeout "
								"inode";

static const char *tcp6_titles = "  sl  "
								 "local_address                         "
								 "remote_address                        "
								 "st "
								 "tx_queue "
								 "rx_queue "
								 "tr "
								 "tm->when "
								 "retrnsmt   "
								 "uid  "
								 "timeout "
								 "inode";

static const char *udp_titles = "   sl  "
								"local_address "
								"rem_address   "
								"st "
								"tx_queue "
								"rx_queue "
								"tr "
								"tm->when "
								"retrnsmt   "
								"uid  "
								"timeout "
								"inode "
								"ref "
								"pointer "
								"drops";

static const char *udp6_titles = "  sl  "
								 "local_address                         "
								 "remote_address                        "
								 "st "
								 "tx_queue "
								 "rx_queue "
								 "tr "
								 "tm->when "
								 "retrnsmt   "
								 "uid  "
								 "timeout "
								 "inode "
								 "ref "
								 "pointer "
								 "drops";

static void print_log_titles(const BpfData &log)
{
	const char *log_titles = nullptr;
	static const char *last_log_titles = nullptr;
	switch (log.log_type)
	{
	case LOG_UNIX:
		log_titles = unix_titles;
		break;
	case LOG_TCP_IPV4:
		log_titles = tcp_titles;
		break;
	case LOG_TCP_IPV6:
		log_titles = tcp6_titles;
		break;
	case LOG_UDP_IPV4:
		log_titles = udp_titles;
		break;
	case LOG_UDP_IPV6:
		log_titles = udp6_titles;
		break;
	default:
		pr_error("unknown log type: %d\n", log.log_type);
		break;
	}
	if (log_titles != last_log_titles)
	{
		printf("%s\n", log_titles);
		last_log_titles = log_titles;
	}
}

static size_t dump_log(BpfData &log, size_t left)
{
	DEBUG(
		0,
		"logtype: %ld %d\n",
		(long)&log.log_type - (long)&log,
		log.log_type
	);

	print_log_titles(log);
	switch (log.log_type)
	{
	case LOG_UNIX:
		if (sizeof(BpfData) + log.plen > left)
		{
			return 0;
		}
		if (log.plen)
		{
			std::replace(
				log.path,
				log.path + log.plen - 1,
				(char)'\0',
				(char)'@'
			);
		}
		printf(
			"%s: %08X %08X %08X %04X %02X %8llu %s\n",
			log.sk_addr,
			log.sk_ref,
			0,
			log.bit_flags,
			log.sk_type,
			log.state,
			log.ino,
			log.plen ? log.path : ""
		);
		return sizeof(BpfData) + log.plen;
	case LOG_TCP_IPV4:
		printf(
			"%4d: %08X:%04X %08X:%04X ",
			0,
			log.lip,
			log.lport,
			log.rip,
			log.rport
		);
		printf(
			"%02X %08X:%08X %02X:%08llX %08X %5u %8d %llu %d ",
			log.state,
			log.tx_queue,
			log.rx_queue,
			log.tr,
			log.tm_when,
			log.retrnsmt,
			log.uid,
			log.timeout,
			log.ino,
			log.sk_ref
		);
		printf(
			"%s %llu %llu %u %u %d\n",
			log.sk_addr,
			log.icsk_rto,
			log.icsk_ack,
			log.bit_flags,
			log.snd_cwnd,
			log.ssthresh
		);
		return sizeof(BpfData);
	case LOG_TCP_IPV6:
		printf(
			"%4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X ",
			0,
			log.lipv6.s6_addr32[0],
			log.lipv6.s6_addr32[1],
			log.lipv6.s6_addr32[2],
			log.lipv6.s6_addr32[3],
			log.lport,
			log.ripv6.s6_addr32[0],
			log.ripv6.s6_addr32[1],
			log.ripv6.s6_addr32[2],
			log.ripv6.s6_addr32[3],
			log.rport
		);
		printf(
			"%02X %08X:%08X %02X:%08llX %08X %5u %8d %llu %d ",
			log.state,
			log.tx_queue,
			log.rx_queue,
			log.tr,
			log.tm_when,
			log.retrnsmt,
			log.uid,
			log.timeout,
			log.ino,
			log.sk_ref
		);
		printf(
			"%s %llu %llu %u %u %d\n",
			log.sk_addr,
			log.icsk_rto,
			log.icsk_ack,
			log.bit_flags,
			log.snd_cwnd,
			log.ssthresh
		);
		return sizeof(BpfData);
	case LOG_UDP_IPV4:
		printf(
			"%5d: %08X:%04X %08X:%04X ",
			0,
			log.lip,
			log.lport,
			log.rip,
			log.rport
		);

		printf(
			"%02X %08X:%08X %02X:%08lX %08X %5u %8d %llu %d %s %llu\n",
			log.state,
			log.tx_queue,
			log.rx_queue,
			0,
			0L,
			0,
			log.uid,
			0,
			log.ino,
			log.sk_ref,
			log.sk_addr,
			log.icsk_rto
		);
		return sizeof(BpfData);
	case LOG_UDP_IPV6:
		printf(
			"%5d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X ",
			0,
			log.lipv6.s6_addr32[0],
			log.lipv6.s6_addr32[1],
			log.lipv6.s6_addr32[2],
			log.lipv6.s6_addr32[3],
			log.lport,
			log.ripv6.s6_addr32[0],
			log.ripv6.s6_addr32[1],
			log.ripv6.s6_addr32[2],
			log.ripv6.s6_addr32[3],
			log.rport
		);

		printf(
			"%02X %08X:%08X %02X:%08lX %08X %5u %8d %llu %d %s %llu\n",
			log.state,
			log.tx_queue,
			log.rx_queue,
			0,
			0L,
			0,
			log.uid,
			0,
			log.ino,
			log.sk_ref,
			log.sk_addr,
			log.icsk_rto
		);
		return sizeof(BpfData);
	default:
		pr_error("unknown log type: %d\n", log.log_type);
		break;
	}
	return 0;
}

static size_t process_ring_buf(const char *buf, size_t bsz)
{
	BpfData *log;
	size_t llen;
	while (bsz >= sizeof(BpfData))
	{
		log = (BpfData *)buf;
		DEBUG(0, "bsz: %lu log: %p\n", bsz, log);
		llen = dump_log(*log, bsz);
		// 0 means dump_log needs more than 'bsz'
		if (llen == 0)
		{
			break;
		}
		// log memory is aligned to 8 bytes by kernel
		if (llen % 8)
		{
			llen += 8 - llen % 8;
		}
		bsz -= llen;
		buf += llen;
	}
	return bsz;
}

static u32 page_size = 4096;
#define CIRCLE_BUF_SIZE (page_size * 2)

class CircleBuf
{
  private:
	size_t rdi;
	size_t wri;
	size_t bsz; // totle buffer size
	size_t usz; // used buffer size
	int shmid = -1;
	void *addr_map = nullptr;

  public:
	CircleBuf(size_t bsz)
	{
		void *addr1 = nullptr;
		void *addr2 = nullptr;
		if (bsz % page_size)
		{
			pr_error("buf size must be multiple of page size\n");
			goto err;
		}
		addr_map = mmap(
			nullptr,
			bsz * 2,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS,
			-1,
			0
		);
		if (addr1 == MAP_FAILED)
		{
			pr_error("mmap: %s\n", strerror(errno));
			goto err;
		}
		shmid = shmget(IPC_PRIVATE, bsz, IPC_CREAT | 0600);
		if (shmid < 0)
		{
			pr_error("shmget: %s\n", strerror(errno));
			goto err;
		}
		addr1 = addr_map;
		addr2 = (char *)addr_map + bsz;
		addr1 = shmat(shmid, addr1, SHM_REMAP);
		if (addr1 == (void *)-1)
		{
			pr_error("shmat: %s\n", strerror(errno));
			goto err;
		}
		DEBUG(0, "shm addr1: %p\n", addr1);
		addr2 = shmat(shmid, addr2, SHM_REMAP);
		if (addr2 == (void *)-1)
		{
			pr_error("shmat: %s", strerror(errno));
			goto err;
		}
		DEBUG(0, "shm addr2: %p\n", addr2);

		*(long *)addr1 = 0xa0a0a0a0a0;
		*(long *)addr2 = 0x0a0a0a0a0a;

		if (*(long *)addr1 != 0x0a0a0a0a0a)
		{
			pr_error("share memory map failure\n");
			goto err;
		}
		rdi = 0;
		wri = 0;
		usz = 0;
		this->bsz = bsz;
		return;
	err:
		this->~CircleBuf();
		throw std::runtime_error("circle buf memory construction failure"
								 ", check stdout for error details");
	}
	~CircleBuf()
	{
		if (addr_map)
		{
			munmap(addr_map, bsz * 2);
		}
		if (shmid >= 0)
		{
			shmctl(shmid, IPC_RMID, NULL);
		}
	}
	char *buf()
	{
		return (char *)addr_map;
	}
	size_t write(void *data, size_t dsz)
	{
		// in case overflow happens when usz + dsz
		if (dsz > bsz || usz + dsz > bsz)
		{
			dsz = bsz - usz;
		}
		memcpy(addr_map, data, dsz);
		wri += dsz;
		usz += dsz;
		wri %= bsz;
		return dsz;
	}
	size_t read(void *data, size_t dsz)
	{
		if (usz < dsz)
		{
			dsz = usz;
		}
		memcpy(data, addr_map, dsz);
		rdi += dsz;
		usz -= dsz;
		rdi %= bsz;
		return dsz;
	}
};

#else // definded BUILTIN

static int
parse_task_sock(const TaskSock ts, DKapture::DKCallback cb, void *ctx)
{
	int ret = 0;
	size_t dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidSock);
	DKapture::DataHdr *hdr = (typeof(hdr))malloc(dsz);
	if (!hdr)
	{
		pr_error("malloc: %s\n", strerror(errno));
		return -1;
	}
	hdr->pid = ts.pid;
	hdr->tgid = ts.pid;
	strncpy(hdr->comm, ts.comm, TASK_COMM_LEN);
	hdr->comm[TASK_COMM_LEN - 1] = '\0'; // Ensure null termination
	hdr->type = DKapture::PROC_PID_sock;
	hdr->dsz = sizeof(ProcPidSock);
	ProcPidSock *sk = (typeof(sk))hdr->data;
	sk->fd = ts.fd;
	sk->ino = ts.ino;
	sk->family = ts.family; // 套接字协议族
	sk->type = ts.type;		// 套接字类型
	sk->state = ts.state;	// 套接字状态
	sk->lipv6 = ts.lipv6;	// 本地 IP 地址
	sk->ripv6 = ts.ripv6;	// 远程 IP 地址
	sk->lport = ts.lport;	// 本地端口
	sk->rport = ts.rport;	// 远端端口
	ret = cb(ctx, hdr, dsz);
	free(hdr);
	return ret;
}
#endif

static int get_task_sock(
#ifndef BUILTIN
	std::map<pid_t, std::vector<TaskSock>> &task_sock
#else
	DKapture::DKCallback callback,
	void *ctx
#endif
)
{
	int fd = -1;
	TaskSock *ti;
	char *buf = nullptr;
	ssize_t rd_sz;
#ifndef BUILTIN
	task_sock.clear();
	sock_task.clear();
#endif
	fd = bpf_create_iter(obj->links.dump_task_ino, goto exit);
	buf = new char[256];
	while ((rd_sz = read(fd, buf, 256)) > 0)
	{
		ti = (TaskSock *)buf;
		while (rd_sz >= (ssize_t)sizeof(TaskSock))
		{
#ifndef BUILTIN
			task_sock[ti->pid].push_back(*ti);
			sock_task[ti->ino].push_back(*ti);
#else
			if (parse_task_sock(*ti, callback, ctx))
			{
				goto exit;
			}
#endif
			rd_sz -= sizeof(TaskSock);
			ti++;
		}
	}
	if (rd_sz < 0)
	{
		pr_error("read iter(%d): %s\n", fd, strerror(errno));
	}

#ifndef BUILTIN
	if (0)
	{ // for debug
		int len;
		len = printf("%10s %16s %10s", "pid", "comm", "ino\n");
		while (len--)
		{
			printf("=");
		}
		printf("\n");
		for (auto &it : task_sock)
		{
			auto &tss = it.second;
			for (auto &ts : tss)
			{
				if (&ts == &tss[0])
				{
					printf("%10d %16s %10llu\n", ts.pid, ts.comm, ts.ino);
				}
				else
				{
					printf("%10s %16s %10llu\n", "", "", ts.ino);
				}
			}
			printf("\n");
		}
		len = printf("%10s %10s %16s", "sock-ino", "pid", "comm\n");
		while (len--)
		{
			printf("=");
		}
		printf("\n");
		for (auto &it : sock_task)
		{
			auto &sts = it.second;
			for (auto &st : sts)
			{
				if (&st == &sts[0])
				{
					printf("%10llu %10d %16s\n", st.ino, st.pid, st.comm);
				}
				else
				{
					printf("%10s %10d %16s\n", "", st.pid, st.comm);
				}
			}
			printf("\n");
		}
		exit(0);
	}
#endif

exit:
	if (fd > 0)
	{
		close(fd);
	}
	if (buf)
	{
		delete[] buf;
	}
	return 0;
}

#ifdef BUILTIN
int lsock_query(DKapture::DKCallback callback, void *ctx)
{
	int ret = -1;
	obj = lsock_bpf::open();
	if (!obj)
	{
		return -1;
	}

	if (lsock_bpf::load(obj) < 0)
	{
		goto out;
	}

	if (0 != lsock_bpf::attach(obj))
	{
		goto out;
	}

	ret = get_task_sock(callback, ctx);
out:
	lsock_bpf::detach(obj);	 // Detach BPF program
	lsock_bpf::destroy(obj); // Clean up BPF object
	return ret;
}
#else
int main(int argc, char **argv)
{
	int iter_fd;
	ssize_t rd_sz;
	CircleBuf *cb;
	u32 key = 0;

	rule_init();
	parse_args(argc, argv);
	page_size = sysconf(_SC_PAGESIZE);
	DEBUG(0, "page size: %u\n", page_size);
	DEBUG(0, "BpfData header size: %lu\n", sizeof(BpfData));

	register_signal();
	cb = new CircleBuf(CIRCLE_BUF_SIZE);
	memset(cb->buf(), 0, CIRCLE_BUF_SIZE);

	trace.start();
	trace.async_follow();

	obj = lsock_bpf::open();
	if (!obj)
	{
		goto err_out;
	}

	if (lsock_bpf::load(obj) < 0)
	{
		goto err_out;
	}

	if (0 != lsock_bpf::attach(obj))
	{
		goto err_out;
	}

	get_task_sock(task_sock);
	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
	bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY);

	if (rule.bit_switch & SWITCH_TCP)
	{
		iter_fd = bpf_create_iter(obj->links.dump_tcp, goto err_out);
		iter_fds.push_back(iter_fd);
	}
	if (rule.bit_switch & SWITCH_UDP)
	{
		iter_fd = bpf_create_iter(obj->links.dump_udp, goto err_out);
		iter_fds.push_back(iter_fd);
	}
	if (rule.bit_switch & SWITCH_UNX)
	{
		iter_fd = bpf_create_iter(obj->links.dump_unix, goto err_out);
		iter_fds.push_back(iter_fd);
	}

	for (auto fd : iter_fds)
	{
		size_t left = 0;
		while ((rd_sz = read(fd, cb->buf(), CIRCLE_BUF_SIZE - left)) > 0)
		{
#if ITER_PASS_STRING
			write(fileno(stdout), cb->buf(), rd_sz);
#else
			DEBUG(0, "rd_sz: %ld left: %lu\n", rd_sz, left);
			left = process_ring_buf(
				cb->buf() + CIRCLE_BUF_SIZE - left,
				rd_sz + left
			);
#endif
		}
		if (rd_sz < 0)
		{
			pr_error("read iter(%d): %s\n", fd, strerror(errno));
		}
		close(fd);
	}
	trace.stop();

	lsock_bpf::detach(obj);	 // Detach BPF program
	lsock_bpf::destroy(obj); // Clean up BPF object
	delete cb;
	return 0;

err_out:
	if (obj)
	{
		lsock_bpf::detach(obj);	 // Detach BPF program
		lsock_bpf::destroy(obj); // Clean up BPF object
	}
	if (cb)
	{
		delete cb;
	}
	return -1;
}
#endif
