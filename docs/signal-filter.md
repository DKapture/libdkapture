# Signal Filter 信号过滤器

## 功能描述

Signal Filter 是一个基于 eBPF 的 Linux 信号追踪和过滤工具，能够实时追踪进程间的信号通信，并根据设定的规则进行信号拦截。本工具结合了信号追踪和信号拦截功能，提供强大的信号监控和安全防护能力。

### 主要功能

1. **信号追踪**：实时追踪信号的来源和去向，记录信号发送者、接收者、信号类型和传递时间
2. **信号拦截**：根据设定的规则拦截特定信号，支持基于发送者PID、接收者PID、发送者UID、信号类型的过滤
3. **规则过滤**：所有规则必须同时满足才会拦截信号（逻辑AND），当没有设置任何规则时，所有信号都允许通过

## 命令选项说明

```bash
./signal-filter -h
Usage: ./filter/signal-filter [option]
  Trace and filter signal communication between processes.

Options:
  -P, --sender-pid <sender-pid>
        Filter by sender process ID

  -p, --recv-pid <recv-pid>
        Filter by receiver process ID

  -U, --sender-uid <sender-uid>
        Filter by sender user ID

  -S, --sig <signal>
        Filter by signal type (name or number)

  -h, --help 
        Show this help message
```

### 参数说明

- **-P, --sender-pid**：指定发送进程的PID，用于过滤信号的发送方
- **-p, --recv-pid**：指定接收进程的PID，用于过滤信号的目的地
- **-U, --sender-uid**：指定发送者的用户ID，用于过滤特定用户发送的信号
- **-S, --sig**：指定要过滤的信号类型，支持信号名称（如SIGUSR1）或信号编号
- **-h, --help**：显示帮助信息

### 支持的信号类型

支持所有标准信号名称，包括但不限于：
- `SIGUSR1`, `SIGUSR2` - 用户自定义信号
- `SIGTERM`, `SIGKILL` - 终止信号
- `SIGINT`, `SIGQUIT` - 中断信号
- `SIGCHLD`, `SIGPIPE` - 系统信号
- `SIGHUP`, `SIGALRM` - 其他系统信号

## 运行示例

### 基本信号追踪

```bash
sudo ./signal-filter
```

输出示例：
```
=== eBPF Signal Filter Started ===
Press Ctrl+C to stop filter

TIME      SENDER           S-COMM             RCVER           R-COMM             SIGNAL             RESULT        LATENCY
16:41:42      79161            sleep              79149           cpuUsage.sh        SIGCHLD        0              190.50   us
16:41:43      79162            bash               79150           test.sh            SIGTERM        0              125.30   us
```

### 基于规则的信号过滤

```bash
# 拦截特定进程发送的信号
sudo ./signal-filter -P 12345

# 拦截特定进程接收的信号
sudo ./signal-filter -p 67890

# 拦截特定用户发送的信号
sudo ./signal-filter -U 1000

# 拦截特定信号类型
sudo ./signal-filter -S SIGUSR1

# 组合规则：拦截用户1000向进程12345发送的SIGUSR1信号
sudo ./signal-filter -U 1000 -P 12345 -S SIGUSR1
```

输出示例：
```
=== eBPF Signal Filter Started ===
Mode: Rule-based filtering
Rules: sender_pid=12345, recv_pid=67890, sender_uid=1000, signal=SIGUSR1
Press Ctrl+C to stop filter

[RULE-INTERCEPT] TIME      SENDER_PID    SENDER_UID    RECV_PID    SIGNAL    ACTION
[RULE-INTERCEPT] 16:41:42      12345          1000          67890      SIGUSR1   BLOCKED
```

## 输出格式说明

### 信号追踪输出

```
TIME      SENDER           S-COMM             RCVER           R-COMM             SIGNAL             RESULT        LATENCY
16:41:42      79161            sleep              79149           cpuUsage.sh        SIGCHLD        0              190.50   us
```

字段说明：
- **TIME**：信号发送时间（时:分:秒）
- **SENDER**：发送信号的进程PID
- **S-COMM**：发送信号的进程名称
- **RCVER**：接收信号的进程PID
- **R-COMM**：接收信号的进程名称
- **SIGNAL**：信号类型（如SIGCHLD、SIGINT等）
- **RESULT**：信号处理结果（0表示成功）
- **LATENCY**：信号从生成到投递的延迟时间（微秒）

### 拦截输出

```
[INTERCEPT] TIME      TARGET_PID       TARGET_COMM        SIGNAL          ACTION
[INTERCEPT] 16:41:42      24883            node                 UNKNOWN                 ALLOWED 
```

字段说明：
- **[INTERCEPT]**：标识这是默认信号拦截事件
- **TIME**：拦截检查时间
- **TARGET_PID**：目标进程PID
- **TARGET_COMM**：目标进程名称
- **SIGNAL**：信号类型（UNKNOWN表示未知信号）
- **ACTION**：拦截动作（ALLOWED/BLOCKED/IGNORED）

## 规则过滤逻辑

### 规则结构

```c
struct Rule {
    u32 sender_pid;    // 发送者进程PID，0表示不限制
    u32 recv_pid;      // 接收者进程PID，0表示不限制
    u32 sender_uid;    // 发送者用户ID，0表示不限制
    u32 sig;           // 信号类型，0表示不限制
};
```

### 过滤逻辑

1. **逻辑AND**：所有设置的规则必须同时满足才会拦截信号
2. **默认允许**：当没有设置任何规则时，所有信号都允许通过
3. **规则优先级**：规则过滤优先于默认的信号类型拦截
4. **UID限制**：信号不能跨UID传递，因此只需要指定发送者UID

### 规则示例

```bash
# 示例1：拦截进程12345发送的所有信号
sudo ./signal-filter -P 12345

# 示例2：拦截用户1000发送的SIGUSR1信号
sudo ./signal-filter -U 1000 -S SIGUSR1

# 示例3：拦截进程12345向进程67890发送的信号
sudo ./signal-filter -P 12345 -p 67890

# 示例4：拦截用户1000向进程12345发送的SIGUSR1信号
sudo ./signal-filter -U 1000 -P 12345 -S SIGUSR1
```

