/**
 * @file signal-filter.h
 * @brief 信号过滤器头文件，定义信号监控和过滤相关的常量和数据结构
 */

#ifndef __SIGNAL_FILTER_H__
#define __SIGNAL_FILTER_H__

/** @brief 事件类型数量 */
#define EVENTNUMBER 2

/** @brief 信号跟踪标志 */
#define TRACESIGNAL 0
/** @brief 过滤标志 */
#define FILTERFLAG 1

/** @brief 最大过滤进程ID数量 */
#define MAX_FILTER_PIDS 64
/** @brief 最大过滤用户ID数量 */
#define MAX_FILTER_UIDS 64
/** @brief 最大过滤信号数量 */
#define MAX_FILTER_SIGNALS 32

/** @brief 仅监控模式 */
#define MODE_MONITOR_ONLY 0
/** @brief 进程ID过滤模式 */
#define MODE_PID_FILTER 1
/** @brief 用户ID过滤模式 */
#define MODE_UID_FILTER 2
/** @brief 信号过滤模式 */
#define MODE_SIGNAL_FILTER 3
/** @brief 规则过滤模式 */
#define MODE_RULE_FILTER 4

/**
 * @brief 信号过滤规则结构体
 * 定义了信号过滤的匹配条件，包括发送者和接收者的进程信息以及信号类型
 */
struct Rule
{
	pid_t sender_pid; ///< 发送者进程ID
	pid_t recv_pid;   ///< 接收者进程ID
	uid_t sender_uid; ///< 发送者用户ID
	int sig;          ///< 信号类型
};

#endif