/**
 * @file net-filter.h
 * @brief 网络过滤器头文件，定义网络监控和过滤相关的数据结构和常量
 */

#pragma once
#include "types.h"
#include "endian.h"
#include "net.h"

// net monitor action
/** @brief 接受数据包 */
#define NM_ACCEPT (unsigned int)0x00
/** @brief 记录数据包 */
#define NM_LOG (unsigned int)0x01
/** @brief 丢弃数据包 */
#define NM_DROP (unsigned int)0x02
/** @brief 拒绝数据包 */
#define NM_REJECT (unsigned int)0x04
/** @brief 网络监控动作掩码 */
#define NM_MASK (unsigned int)0x0f

/** @brief 无调试输出 */
#define DEBUG_NONE 0
/** @brief 调试LSM TCP包 */
#define DEBUG_LSM_TCP_PKG 1
/** @brief 调试LSM UDP包 */
#define DEBUG_LSM_UDP_PKG 2
/** @brief 调试LSM ICMP包 */
#define DEBUG_LSM_ICMP_PKG 3
/** @brief 调试LSM所有包 */
#define DEBUG_LSM_ALL_PKG 4
/** @brief 调试Netfilter TCP包 */
#define DEBUG_NF_TCP_PKG 5
/** @brief 调试Netfilter UDP包 */
#define DEBUG_NF_UDP_PKG 6
/** @brief 调试Netfilter ICMP包 */
#define DEBUG_NF_ICMP_PKG 7
/** @brief 调试Netfilter所有包 */
#define DEBUG_NF_ALL_PKG 8
/** @brief 调试规则匹配 */
#define DEBUG_RULE_MATCH 9

/** @brief 仅关注入站数据包 */
#define NET_DIR_IN (unsigned int)0x100
/** @brief 仅关注出站数据包 */
#define NET_DIR_OUT (unsigned int)0x200
/** @brief 网络方向掩码 */
#define NET_DIR_MASK (unsigned int)0x300

/** @brief IPv6以太网类型 */
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
/** @brief IPv4以太网类型 */
#define ETH_P_IP 0x0800	  /* Internet Protocol packet	*/

/** @brief 最大规则长度，必须是2的幂 */
#define MAX_RULES_LEN 256 // must be order of 2

/** @brief 入站数据包方向 */
#define PKG_DIR_IN (1 << 0)
/** @brief 出站数据包方向 */
#define PKG_DIR_OUT (1 << 1)
/** @brief 任意方向数据包 */
#define PKG_DIR_ANY (PKG_DIR_IN | PKG_DIR_OUT)

/** @brief 网络字节序到主机字节序转换（16位） */
#define ntoh16(x) byte_reverse(x, 16)
/** @brief 主机字节序到网络字节序转换（16位） */
#define hton16(x) byte_reverse(x, 16)

/**
 * @brief 网络过滤器配置结构体
 */
struct Configs
{
	bool enable; ///< 模块的全局开关
	int debug;   ///< 启用调试输出到trace_pipe
};

/**
 * @brief IP元组结构体，用于描述网络连接的五元组信息
 */
struct ip_tuple
{
	// all host ending, mostly little ending
	union
	{
		unsigned int sip;       ///< IPv4源地址
		struct in6_addr sipv6;  ///< IPv6源地址
	};
	union
	{
		unsigned int dip;       ///< IPv4目的地址
		struct in6_addr dipv6;  ///< IPv6目的地址
	};
	unsigned short sport;       ///< 源端口
	unsigned short dport;       ///< 目的端口
	unsigned char ip_proto;     ///< IP层协议
	unsigned char tl_proto;     ///< 传输层协议
	struct
	{
		unsigned char pkg_dir : 2;  ///< 数据包方向：PKG_DIR_IN输入，PKG_DIR_OUT输出
		unsigned char reseverd : 6; ///< 保留字段
	};
	char comm[16];              ///< 进程名称
};

/**
 * @brief BPF数据结构体，用于在内核和用户空间之间传递网络数据信息
 */
struct BpfData
{
	unsigned int data_len;         ///< 数据长度（包括协议头）
	int pid;                       ///< 进程ID
	unsigned long long timestamp;  ///< 时间戳
	unsigned long long start_time; ///< 开始时间
	unsigned char action;          ///< 执行的动作
	struct ip_tuple tuple;         ///< IP元组信息
};
/**
 * @brief 网络过滤规则结构体，定义了网络过滤的匹配条件和动作
 */
struct Rule
{
	// struct bpf_spin_lock lock;
	struct
	{
		unsigned int action : 8;   ///< 执行动作（8位）
		unsigned int pkg_dir : 2;  ///< 数据包方向（2位）
		unsigned int reserved : 22;///< 保留字段（22位）
	};
	union
	{
		unsigned int sip;          ///< IPv4源地址起始
		struct in6_addr sipv6;     ///< IPv6源地址起始
	};
	union
	{
		unsigned int dip;          ///< IPv4目的地址起始
		struct in6_addr dipv6;     ///< IPv6目的地址起始
	};
	union
	{
		unsigned int sip_end;      ///< IPv4源地址结束
		struct in6_addr sipv6_end; ///< IPv6源地址结束
	};
	union
	{
		unsigned int dip_end;      ///< IPv4目的地址结束
		struct in6_addr dipv6_end; ///< IPv6目的地址结束
	};

	unsigned short sport;          ///< 源端口起始
	unsigned short dport;          ///< 目的端口起始
	unsigned short sport_end;      ///< 源端口结束
	unsigned short dport_end;      ///< 目的端口结束
	unsigned char ip_proto;        ///< IP协议类型
	unsigned char tl_proto;        ///< 传输层协议类型
	char comm[16];                 ///< 进程名称
};

#ifdef __cplusplus

#include <map>
#include <vector>

// 前向声明
struct net_filter_bpf;
struct bpf_link;
struct ring_buffer;

/**
 * @brief 网络过滤器类，提供网络数据包监控和过滤功能
 * 
 * 该类封装了基于eBPF的网络过滤功能，支持：
 * - 网络数据包的监控和过滤
 * - 基于规则的流量控制
 * - 实时日志记录和回调
 * - 多种调试模式
 */
class NetFilter
{
  public:
	/**
	 * @brief 日志回调函数类型定义
	 * @param log BPF数据日志信息
	 */
	typedef void (*LogCallback)(const BpfData &log);

	/**
	 * @brief 初始化
	 * @param cb 日志回调函数，用于接收bpf程序产生的日志信息
	 */
	int init(LogCallback cb = nullptr);
	
	/**
	 * @brief 反初始化，清理资源
	 */
	void deinit(void);
	/**
	 * @brief 添加规则
	 * @param rule 规则
	 * @return 返回与该规则对应的唯一id，失败返回-1，以errno指示错误
	 */
	int add_rule(const Rule &rule);
	/**
	 * @brief 更新已存在的规则
	 * @param rule_id 规则对应的唯一id
	 * @param rule 需要更新的规则
	 * @return 成功返回0，失败返回-1，以errno指示错误
	 */
	int update_rule(unsigned int rule_id, const Rule &rule);
	/**
	 * @brief 删除规则
	 * @param rule_id 规则对应唯一id
	 */
	void del_rule(unsigned int rule_id);
	/**
	 * @brief 清空规则
	 */
	void clear_rules(void);
	/**
	 * @brief 从配置文件加载规则
	 * @param rule_file 规则文件路径
	 * @return 成功返回true，失败返回false
	 */
	bool load_rules(const char *rule_file);
	
	/**
	 * @brief 获取所有规则
	 * @param rules 输出参数，存储所有规则的映射表
	 */
	void dump_rules(std::map<unsigned int, Rule> &rules) const;
	
	/**
	 * @brief 设置BPF程序的调试日志等级
	 * @param type 调试类型，参见DEBUG_*常量
	 */
	void set_bpf_debug(int type);
	
	/**
	 * @brief 使能/失能整个net-monitor内核功能
	 * @param state true为使能，false为失能，失能后不再有过滤效果，默认使能
	 */
	void enable(bool state);
	/**
	 * @brief 将规则字符串转化成规则数据结构体
	 * @param str 规则字符串
	 * @param rule 输出规则数据结构
	 * @return 返回成功或失败，失败会有错误标准输出
	 */
	static bool parse_rule(const char *str, Rule &rule);
	/**
	 * @brief 用于调试, 读/sys/kernel/debug/tracing/trace_pipe,
	 * 输出到fp指向的文件
	 *        trace_pipe的内容包含ebpf程序的调试日志。注意：会包含所有bpf程序的调试日志
	 *        而不只是net-monitor.bpf
	 * @param fp 指向目标输出文件，为空是指向标准输出
	 * @return 这个函数从不返回，直到有其他线程调用NetFilter.exit()
	 */
	static void read_trace_pipe(FILE *fp = nullptr);
	/**
	 * @brief 开始网络监控的主循环
	 * 这是一个阻塞调用，会持续监控网络流量直到调用exit()
	 */
	void loop(void);
	
	/**
	 * @brief 退出主循环
	 * 设置退出标志，使loop()函数返回
	 */
	void exit(void);
	
	LogCallback log_cb; ///< 日志回调函数指针

  private: // 私有变量，请勿修改
	int rules_map_fd;                       ///< 规则映射文件描述符
	int log_map_fd;                         ///< 日志映射文件描述符
	int conf_map_fd;                        ///< 配置映射文件描述符
	net_filter_bpf *obj;                    ///< BPF对象指针
	std::vector<int> link_fds;              ///< 链接文件描述符列表
	std::vector<struct bpf_link *> bpf_links; ///< BPF链接指针列表
	struct ring_buffer *rb = nullptr;       ///< 环形缓冲区指针
	unsigned int key_cnt = 1;               ///< 键计数器
	volatile bool loop_flag;                ///< 循环标志
	Configs conf;                           ///< 配置信息
};
#endif