#pragma once
#include "types.h"
#include "endian.h"
#include "net.h"

// net monitor action
#define NM_ACCEPT (unsigned int)0x00
#define NM_LOG (unsigned int)0x01
#define NM_DROP (unsigned int)0x02
#define NM_REJECT (unsigned int)0x04
#define NM_MASK (unsigned int)0x0f

#define DEBUG_NONE 0
#define DEBUG_LSM_TCP_PKG 1
#define DEBUG_LSM_UDP_PKG 2
#define DEBUG_LSM_ICMP_PKG 3
#define DEBUG_LSM_ALL_PKG 4
#define DEBUG_NF_TCP_PKG 5
#define DEBUG_NF_UDP_PKG 6
#define DEBUG_NF_ICMP_PKG 7
#define DEBUG_NF_ALL_PKG 8
#define DEBUG_RULE_MATCH 9

#define NET_DIR_IN (unsigned int)0x100	// only concerned with incoming packets
#define NET_DIR_OUT (unsigned int)0x200 // only concerned with outgoing packets
#define NET_DIR_MASK (unsigned int)0x300

#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
#define ETH_P_IP 0x0800	  /* Internet Protocol packet	*/

#define MAX_RULES_LEN 256 // must be order of 2

#define PKG_DIR_IN (1 << 0)
#define PKG_DIR_OUT (1 << 1)
#define PKG_DIR_ANY (PKG_DIR_IN | PKG_DIR_OUT)

#define ntoh16(x) byte_reverse(x, 16)
#define hton16(x) byte_reverse(x, 16)

struct Configs
{
	bool enable; // the global switch for this module
	// enable debug output to trace_pipe
	int debug;
};

struct ip_tuple
{
	// all host ending, mostly little ending
	union
	{
		unsigned int sip;
		struct in6_addr sipv6;
	};
	union
	{
		unsigned int dip;
		struct in6_addr dipv6;
	};
	unsigned short sport;
	unsigned short dport;
	unsigned char ip_proto; // ip layer protocol
	unsigned char tl_proto; // transport layer protocol
	struct
	{
		unsigned char pkg_dir : 2; // package direction: PKG_DIR_IN: input
								   // PKG_DIR_OUT: output
		unsigned char reseverd : 6;
	};
	char comm[16];
};

struct BpfData
{
	unsigned int data_len; // including protocol headers
	int pid;
	unsigned long long timestamp;
	unsigned long long start_time;
	unsigned char action;
	struct ip_tuple tuple;
};
struct Rule
{
	// struct bpf_spin_lock lock;
	struct
	{
		unsigned int action : 8;
		unsigned int pkg_dir : 2;
		unsigned int reserved : 22;
	};
	union
	{
		unsigned int sip;
		struct in6_addr sipv6;
	};
	union
	{
		unsigned int dip;
		struct in6_addr dipv6;
	};
	union
	{
		unsigned int sip_end;
		struct in6_addr sipv6_end;
	};
	union
	{
		unsigned int dip_end;
		struct in6_addr dipv6_end;
	};

	unsigned short sport;
	unsigned short dport;
	unsigned short sport_end;
	unsigned short dport_end;
	unsigned char ip_proto;
	unsigned char tl_proto;
	char comm[16]; // process comm
};

#ifdef __cplusplus

#include <map>
#include <vector>
class NetFilter
{
  public:
	typedef void (*LogCallback)(const BpfData &log);

	/**
	 * @brief 初始化
	 * @param cb 日志回调函数，用于接收bpf程序产生的日志信息
	 */
	int init(LogCallback cb = nullptr);
	void deinit(void);
	/**
	 * @brief 添加规则
	 * @param rule 规则
	 * @return 返回与该规则对应的唯一id，失败返回-1，以errno指示错误
	 */
	int add_rule(const Rule &rule);
	/**
	 * @brief update an existing rule
	 * @param rule_id 规则对应的唯一id
	 * @param rule 需要更新的规则
	 * @return 成功返回0，否则返回失败，失败返回-1，以errno指示错误
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
	 */
	bool load_rules(const char *rule_file);
	/**
	 * @brief 获取所有规则
	 */
	void dump_rules(std::map<unsigned int, Rule> &rules) const;
	/**
	 * @brief 设置bpf程序的调试日志等级
	 */
	void set_bpf_debug(int type);
	/**
	 * @brief 使能/失能整net-monitor内核功能，失能后不在有过滤效果，默认使能
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
	 * @brief 完成net-monitor工作的死循环
	 */
	void loop(void);
	/**
	 * @brief 退出 loop 循环
	 */
	void exit(void);
	LogCallback log_cb;

  private: // 私有变量，请勿修改
	int rules_map_fd;
	int log_map_fd;
	int conf_map_fd;
	net_filter_bpf *obj;
	std::vector<int> link_fds;
	std::vector<struct bpf_link *> bpf_links;
	struct ring_buffer *rb = NULL;
	unsigned int key_cnt = 1;
	volatile bool loop_flag;
	Configs conf;
};
#endif