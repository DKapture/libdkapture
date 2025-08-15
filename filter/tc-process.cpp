// SPDX-License-Identifier: GPL-2.0

#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <getopt.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/netfilter.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "tc-process.skel.h"
#include "../include/Ulog.h"

#define EGRESS   1
#define INGRESS  0
#define DEFAULT_RATE_BPS 5 * 1024 * 1024  // Default 5MB/s

struct ProcInfo
{
	__u32 pid;
	char comm[16];
};


// Event structure (must match BPF side layout expectations when used)
struct event_t {
    struct ProcInfo proc;   // Process info (PID, comm)
    __u32    bytes_sent;
    __u32    bytes_dropped;
    __u32    packets_sent;
    __u32    packets_dropped;
    __u64    timestamp;
    __u8     flag;          // Event type
    __u32    ip;
    __u16    port;          // Port
    __u8     protocol;      // Protocol (IPPROTO_*)
};

// progress rules structure
struct ProcessRule {
    uint32_t target_pid;  
    uint64_t rate_bps;    
    uint8_t gress;        
    uint32_t time_scale;   
};

// Global state
static struct tc_process_bpf *skel = nullptr;
static struct ring_buffer *rb = nullptr;

static struct bpf_link *recvmsg_kprobe_link = nullptr;
static struct bpf_link *send_kprobe_link = nullptr;
static struct bpf_link *connect_kprobe_link = nullptr;
static struct bpf_link *listen_kprobe_link = nullptr;

static int netfilter_fd_ingress = -1;
static int netfilter_fd_egress = -1;
static volatile bool running = true;
static struct ProcessRule rule = {0};


// CLI options
static struct option lopts[] = {

{"pid", required_argument, 0, 'p'},
{"rate", required_argument, 0, 'r'},
{"direction", required_argument, 0, 'd'},
{"timescale", required_argument, 0, 't'},
{"help", no_argument, 0, 'h'},
{0, 0, 0, 0}
};

// Parse bandwidth string (supports K/M/G suffix)
static uint64_t parse_bandwidth(const char *str)
{
    if (!str)
    {
        return DEFAULT_RATE_BPS;
    }
    
    char *endptr;
    uint64_t value = strtoull(str, &endptr, 10);
    
    if (*endptr == '\0')
    {
        return value;
    }
    else if (strcasecmp(endptr, "K") == 0)
    {
        return value * 1024;
    }
    else if (strcasecmp(endptr, "M") == 0)
    {
        return value * 1024 * 1024;
    }
    else if (strcasecmp(endptr, "G") == 0)
    {
        return value * 1024 * 1024 * 1024;
    }
    
    return DEFAULT_RATE_BPS;
}



void handle_process_map_event(const struct event_t *e)
{
    pr_info("[进程映射] PID=%u (%s) 建立socket映射", e->proc.pid, e->proc.comm);
}

void handle_packet_parse_event(const struct event_t *e)
{
    pr_info("[数据包解析]");
    std::string protocol_name;
    switch (e->protocol)
    {
        case 6:  // IPPROTO_TCP
            protocol_name = "TCP";
            break;
        case 17: // IPPROTO_UDP
            protocol_name = "UDP";
            break;
        case 1:  // IPPROTO_ICMP
            protocol_name = "ICMP";
            break;
        default:
            protocol_name = "UNKNOWN(" + std::to_string(e->protocol) + ")";
            break;
    }
    
    pr_info("IP=%s 端口=%u 协议=%s",
            inet_ntoa(*(struct in_addr*)&e->ip),
            ntohs(e->port),
            protocol_name.c_str());
}

void handle_send_drop_event(const struct event_t *e)
{
    // 打印流量信息
    if (e->bytes_dropped > 0)
    {
        pr_warn("[丢包] PID=%u (%s) 丢包: %u bytes (%u packets)",
                e->proc.pid, e->proc.comm, e->bytes_dropped, e->packets_dropped);
    }
    else if (e->bytes_sent > 0)
    {
        pr_info("[发送] PID=%u (%s) 发送: %u bytes (%u packets)",
                e->proc.pid, e->proc.comm, e->bytes_sent, e->packets_sent);
    }
    else
    {
        pr_info("[流量监控] PID=%u (%s)", e->proc.pid, e->proc.comm);
    }
}

void handle_network_tuple_event(const struct event_t *e)
{
    // 获取协议名称
    std::string protocol_name;
    switch (e->protocol)
    {
        case 6:  // IPPROTO_TCP
            protocol_name = "TCP";
            break;
        case 17: // IPPROTO_UDP
            protocol_name = "UDP";
            break;
        case 1:  // IPPROTO_ICMP
            protocol_name = "ICMP";
            break;
        default:
            protocol_name = "UNKNOWN(" + std::to_string(e->protocol) + ")";
            break;
    }
    
    pr_info("[网络三元组] PID=%u (%s) IP=%s 端口=%u 协议=%s 数据包大小=%u bytes",
            e->proc.pid,
            e->proc.comm,
            inet_ntoa(*(struct in_addr*)&e->ip),
            ntohs(e->port),
            protocol_name.c_str(),
            e->bytes_sent);
}

// Ring buffer event handler - dispatch by event type
static int handle_traffic_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz != sizeof(event_t))
    {
        return 0;
    }
    
    const struct event_t *e = static_cast<const struct event_t*>(data);
    
    // 根据事件类型分别处理
    switch (e->flag)
    {
        case 0: // PROCESS_MAP
            handle_process_map_event(e);
            break;
        case 1: // PACKET_PARSE
            handle_packet_parse_event(e);
            break;
        case 2: // SEND_DROP
            handle_send_drop_event(e);
            break;
        case 3: // IP_AND_PORT
            pr_info("[IP和端口] PID=%u (%s) IP=%s 端口=%u 时间刻度=%u秒",
                    e->proc.pid,
                    e->proc.comm,
                    inet_ntoa(*(struct in_addr*)&e->ip),
                    ntohs(e->port),
                    rule.time_scale);
            break;
        case 4: // NETWORK_TUPLE
            handle_network_tuple_event(e);
            break;
        default:
            pr_warn("[未知事件] 类型: %d", (int)e->flag);
            break;
    }
    
    return 0;
}

// Signal handler
static void sig_handler(int sig)
{
    pr_info("收到信号 %d, 正在退出...", sig);
    running = false;
}

// libbpf log print callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

// Print usage
void Usage(const char *arg0)
{
    pr_info("用法: %s [选项]", arg0);
    pr_info("选项:");
    pr_info("  -p, --pid <pid>       要限速的进程PID");
    pr_info("  -r, --rate <rate>     带宽限制 (支持K/M/G后缀)");
    pr_info("  -d, --direction <dir> 匹配方向 (egress=发送, ingress=接收)");
    pr_info("  -t, --timescale <sec> 时间刻度 (秒, 控制突发流量容忍度)");
    pr_info("  -h, --help           显示帮助信息");
    pr_info("");
    pr_info("时间刻度说明:");
    pr_info("  -t 1     : 1秒时间刻度，严格限速，突发容忍度低");
    pr_info("  -t 60    : 1分钟时间刻度，允许短期突发，长期平均限速");
    pr_info("  -t 3600  : 1小时时间刻度，允许长期突发，适合长期带宽管理");
    pr_info("");
    pr_info("工作原理:");
    pr_info("  1. 通过kprobe监控socket创建，建立socket与进程PID的映射");
    pr_info("     - 支持所有协议：TCP、UDP、Unix domain等");
    pr_info("     - 在socket创建时建立映射，覆盖全面");
    pr_info("  2. 通过netfilter hook监控数据包，根据socket指针查找对应进程");
    pr_info("     - 处理TCP和UDP的发送/接收方向限流");
    pr_info("     - 通过hook状态精确区分数据包方向");
    pr_info("  3. 使用令牌桶算法对目标进程进行流量控制");
    pr_info("  4. 实时输出流量监控和限速事件");
    pr_info("");
    pr_info("示例:");
    pr_info("  %s -p 1234 -r 1M -d egress -t 60", arg0);
    pr_info("  %s -p 5678 -r 100K -d ingress -t 1", arg0);
    pr_info("");
}

// Safe string-to-integer conversion helper
template<typename T>
static bool safe_str_to_int(const char *str, T *result, T min_val, T max_val)
{
    static_assert(std::is_integral_v<T>, "T must be an integral type");
    
    if (!str || !result)
    {
        return false;
    }
    
    char *endptr;
    errno = 0;
    
    if constexpr (std::is_signed_v<T>)
    {
        long val = strtol(str, &endptr, 10);
        if (errno == ERANGE || val < static_cast<long>(min_val) || val > static_cast<long>(max_val))
        {
            return false;
        }
        *result = static_cast<T>(val);
    }
    else
    {
        unsigned long val = strtoul(str, &endptr, 10);
        if (errno == ERANGE || val > static_cast<unsigned long>(max_val))
        {
            return false;
        }
        *result = static_cast<T>(val);
    }
    
    if (*endptr != '\0')
    {
        return false;
    }
    
    return true;
}

// Parse CLI arguments
void parse_args(int argc, char **argv)
{
    int opt, opt_idx;
    std::string sopts = "p:r:d:t:h";
    
    while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
    {
        switch (opt)
        {

        case 'p': // target PID
            if (!safe_str_to_int(optarg, &rule.target_pid, static_cast<uint32_t>(1), static_cast<uint32_t>(0x7FFFFFFF)))
            {
                pr_error("错误: 无效的进程PID '%s'", optarg);
                exit(-1);
            }
            break;
        case 'r': // bandwidth
            rule.rate_bps = parse_bandwidth(optarg);
            if (rule.rate_bps == 0)
            {
                pr_error("错误: 无效的带宽限制 '%s'", optarg);
                exit(-1);
            }
            break;
        case 'd': // direction
            if (strcasecmp(optarg, "egress") == 0)
            {
                rule.gress = EGRESS; // 匹配发送方向
            }
            else if (strcasecmp(optarg, "ingress") == 0)
            {
                rule.gress = INGRESS; // 匹配接收方向
            } else {
                pr_error("错误: 无效的匹配方向 '%s'", optarg);
                exit(-1);
            }
            break;
        case 't': // time scale
            if (!safe_str_to_int(optarg, &rule.time_scale, static_cast<uint32_t>(1), static_cast<uint32_t>(3600)))
            {
                pr_error("错误: 无效的时间刻度 '%s'", optarg);
                exit(-1);
            }
            break;
        case 'h': // help
            Usage(argv[0]);
            exit(0);
            break;
        default: // invalid option
            Usage(argv[0]);
            exit(-1);
            break;
        }
    }
    
    // Validate required args
    if (rule.target_pid == 0)
    {
        pr_error("错误: 必须指定目标进程PID (-p)");
        Usage(argv[0]);
        exit(-1);
    }

    // Defaults
    if (rule.rate_bps == 0)
    {
        pr_info("使用默认带宽限制: %u B/s (%.2f MB/s)",
                (unsigned)DEFAULT_RATE_BPS,
                (DEFAULT_RATE_BPS / 1024.0 / 1024.0));
        rule.rate_bps = DEFAULT_RATE_BPS;
    }
    else
    {
        pr_info("设置带宽限制: %llu B/s (%.2f MB/s)",
                rule.rate_bps,
                (rule.rate_bps / 1024.0 / 1024.0));
    }
    
    if (rule.time_scale == 0)
    {
        rule.time_scale = 1;  // 默认1秒时间刻度
        pr_info("使用默认时间刻度: 1秒");
    }
    else
    {
        pr_info("设置时间刻度: %u秒", rule.time_scale);
    }
    
    pr_info("目标进程PID: %u", rule.target_pid);
    pr_info("匹配方向: %s", (rule.gress ? "发送(EGRESS)" : "接收(INGRESS)"));
    pr_info("带宽限制: %llu B/s (%.2f MB/s)", rule.rate_bps, (rule.rate_bps / 1024.0 / 1024.0));
    pr_info("时间刻度: %u秒 (最大桶容量: %.2f MB)", rule.time_scale, (rule.rate_bps * rule.time_scale / 1024.0 / 1024.0));
}

// Configure process rule into BPF map
static bool setup_process_rules()
{
    struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, "process_rules");
    if (!map)
    {
        pr_error("找不到 process_rules map");
        return false;
    }
    
    uint32_t key = 0;
    
    struct {
        __u32 target_pid;
        __u64 rate_bps;
        __u8 gress;
        __u32 time_scale;
    } rule_data = {
        .target_pid = rule.target_pid,
        .rate_bps = rule.rate_bps,
        .gress = rule.gress,
        .time_scale = rule.time_scale
    };
    
    int err = bpf_map__update_elem(map, &key, sizeof(key), &rule_data, sizeof(rule_data), BPF_ANY);
    if (err)
    {
        pr_error("设置进程限速规则失败: %d", err);
        return false;
    }
    
    return true;
}

// Get local IPv4 address (best-effort)
std::string get_local_ip_address()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        return "127.0.0.1"; // 默认返回localhost
    }
    
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8"); // 使用Google DNS作为目标
    addr.sin_port = htons(53);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return "127.0.0.1";
    }
    
    socklen_t len = sizeof(addr);
    if (getsockname(sock, (struct sockaddr*)&addr, &len) < 0)
    {
        close(sock);
        return "127.0.0.1";
    }
    
    close(sock);
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
    
    return std::string(ip_str);
}

// Configure local IPv4 address into BPF map
static bool setup_local_ip_map()
{
    struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, "local_ip_map");
    if (!map)
    {
        pr_error("找不到 local_ip_map");
        return false;
    }
    
    // Fetch local IP
    std::string local_ip = get_local_ip_address();
    pr_info("本机IP地址: %s", local_ip.c_str());
    
    // Convert to network order
    uint32_t key = 0;
    uint32_t ip_addr = inet_addr(local_ip.c_str());
    
    int err = bpf_map__update_elem(map, &key, sizeof(key), &ip_addr, sizeof(ip_addr), BPF_ANY);
    if (err)
    {
        pr_error("设置本机IP地址失败: %d", err);
        return false;
    }
    
    pr_info("成功设置本机IP地址到BPF map");
    return true;
}

// Entry point
int main(int argc, char **argv)
{

    int err;
    union bpf_attr attr = {};
    int netfilter_fd_ingress = -1;
    int netfilter_fd_egress = -1;
    
    // Require root
    if (getuid() != 0)
    {
        pr_error("错误: 此程序必须以root权限运行");
        return 1;
    }
    
    // Parse args
    parse_args(argc, argv);

    // Set libbpf logger
    libbpf_set_print(libbpf_print_fn);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Open and load BPF skeleton
    skel = tc_process_bpf__open_and_load();
    if (!skel)
    {
        pr_error("打开并加载 BPF skeleton 失败");
        return 1;
    }
    
    // Attach recvmsg kprobe
    recvmsg_kprobe_link = bpf_program__attach(skel->progs.security_socket_recvmsg);
    if (!recvmsg_kprobe_link)
    {
        pr_error("加载recvmsg kprobe程序失败");
        goto cleanup;
    }
    
    // Attach sendmsg kprobe
    send_kprobe_link = bpf_program__attach(skel->progs.security_socket_sendmsg);
    if (!send_kprobe_link)
    {
        pr_error("加载发送端kprobe程序失败");
        goto cleanup;
    }
   
    // Attach connect kprobe
    connect_kprobe_link = bpf_program__attach(skel->progs.security_socket_connect);
    if (!connect_kprobe_link)
    {
        pr_error("加载connect kprobe程序失败");
        goto cleanup;
    }
   
    // Attach connect kprobe
    listen_kprobe_link = bpf_program__attach(skel->progs.security_socket_listen);
    if (!listen_kprobe_link)
    {
        pr_error("listen kprobe程序失败");
        goto cleanup;
    }
    
    // Configure process rule map
    if (!setup_process_rules())
    {
        goto cleanup;
    }

    // Configure local IP map
    if (!setup_local_ip_map())
    {
        goto cleanup;
    }

    // Attach netfilter program for both directions (via BPF_LINK_CREATE)
    
    // Attach to ingress hook (NF_INET_LOCAL_IN)
    attr.link_create.prog_fd = bpf_program__fd(skel->progs.netfilter_hook);
    attr.link_create.attach_type = BPF_NETFILTER;
    attr.link_create.netfilter.pf = NFPROTO_IPV4;
    attr.link_create.netfilter.hooknum = NF_INET_LOCAL_IN;
    attr.link_create.netfilter.priority = -128;
    
    netfilter_fd_ingress = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
    if (netfilter_fd_ingress < 0)
    {
        pr_error("附加netfilter ingress程序失败: %s", strerror(errno));
        goto cleanup;
    }
   
    
    // Attach to egress hook (NF_INET_LOCAL_OUT)
    attr.link_create.netfilter.hooknum = NF_INET_LOCAL_OUT;
    netfilter_fd_egress = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
    if (netfilter_fd_egress < 0)
    {
        pr_error("附加netfilter egress程序失败: %s", strerror(errno));
        close(netfilter_fd_ingress);
        goto cleanup;
    }
    
    
    // Save FDs to globals
    ::netfilter_fd_ingress = netfilter_fd_ingress;
    ::netfilter_fd_egress = netfilter_fd_egress;
    
    pr_info("成功附加netfilter程序，处理两个方向的流量");
    
    pr_info("=== 流量控制配置 ===");
    pr_info("目标进程PID: %u", rule.target_pid);
    pr_info("匹配方向: %s", (rule.gress ? "发送(EGRESS)" : "接收(INGRESS)"));
    pr_info("带宽限制: %llu B/s (%.2f MB/s)", rule.rate_bps, (rule.rate_bps / 1024.0 / 1024.0));
    pr_info("时间刻度: %u秒", rule.time_scale);
    pr_info("最大桶容量: %.2f MB", (rule.rate_bps * rule.time_scale / 1024.0 / 1024.0));
    pr_info("===================");
    
    // Create ring buffer for events
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_traffic_event, nullptr, nullptr);
    if (!rb)
    {
        pr_error("创建环形缓冲区失败");
        err = -1;
        goto cleanup;
    }
    
    pr_info("开始监控进程流量...");
    pr_info("按 Ctrl+C 停止监控");
    pr_info("===================");
    
    // Main event loop
    while (running)
    {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
        {
            continue; // interrupted by signal
        }
        if (err < 0)
        {
            pr_error("轮询环形缓冲区错误: %d", err);
            break;
        }
    }
    
    // Netfilter links will be destroyed on exit
    pr_info("netfilter程序将在程序退出时自动卸载");
    
cleanup:

    // Detach recvmsg kprobe
    if (recvmsg_kprobe_link)
    {
        bpf_link__destroy(recvmsg_kprobe_link);
    }

    // Detach sendmsg kprobe
    if (send_kprobe_link)
    {
        bpf_link__destroy(send_kprobe_link);
    }
    
    // Detach connect kprobe
    if (connect_kprobe_link)
    {
        bpf_link__destroy(connect_kprobe_link);
    }

    // Detach listen kprobe
    if (listen_kprobe_link)
    {
        bpf_link__destroy(listen_kprobe_link);
    }

    // Close netfilter link FDs
    if (netfilter_fd_ingress >= 0)
    {
        close(netfilter_fd_ingress);
    }
    if (netfilter_fd_egress >= 0)
    {
        close(netfilter_fd_egress);
    }
    
    if (rb)
    {
        ring_buffer__free(rb);
    }
    if (skel)
    {
        tc_process_bpf__destroy(skel);
    }
    
    return -err;
}
