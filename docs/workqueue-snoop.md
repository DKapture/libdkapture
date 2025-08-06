# workqueue-snoop - 内核工作队列事件跟踪工具

## 概述

workqueue-snoop 是一个基于 eBPF 的工具，用于实时跟踪Linux内核工作队列(workqueue)的各种事件。它通过监听内核中的 workqueue tracepoint 来收集工作队列活动信息，可以帮助系统管理员和开发者理解内核工作负载调度行为和性能特征。

## 功能特性

workqueue-snoop 可以跟踪以下工作队列事件：

- **入队事件** (`QUEUE`) - 工作项被添加到工作队列
- **激活事件** (`ACTIVATE`) - 工作项被激活并准备执行
- **开始执行** (`START`) - 工作项开始在worker线程中执行
- **执行结束** (`END`) - 工作项执行完成

支持的高级功能：
- 进程级过滤 - 只跟踪特定进程的工作队列活动
- CPU级过滤 - 只跟踪特定CPU上的事件
- 工作队列名称过滤 - 只跟踪指定的工作队列
- 函数名过滤 - 只跟踪包含特定字符串的函数
- 统计模式 - 提供汇总统计信息
- 多种输出格式 - 支持表格和JSON格式输出
- 时间戳支持 - 可选择显示精确的时间戳
- 自动退出保护 - 防止程序无法响应信号

## 编译和安装

### 前提条件

- Linux 内核版本 ≥ 4.18 (支持 eBPF)
- 已安装 libbpf 开发库
- 已安装 bpftool
- 编译工具链 (gcc, clang)

### 编译步骤

```bash
# 进入项目目录
cd dkapture/observe

# 编译 workqueue-snoop
make workqueue-snoop
```

编译成功后会生成以下文件：
- `workqueue-snoop` - 可执行文件
- `workqueue-snoop.bpf.o` - BPF 对象文件
- `workqueue-snoop.skel.h` - BPF skeleton 头文件

## 使用方法

### 基本语法

```bash
sudo ./workqueue-snoop [选项]
```

### 命令行选项

| 选项 | 参数 | 描述 |
|------|------|------|
| `-p, --pid` | PID | 只跟踪指定进程ID |
| `-c, --cpu` | CPU | 只跟踪指定CPU |
| `-w, --workqueue` | NAME | 只跟踪指定工作队列名称 |
| `-f, --function` | FUNC | 只跟踪包含指定字符串的函数 |
| `-d, --duration` | SECONDS | 跟踪持续时间（秒） |
| `--timeout` | SECONDS | 同 --duration |
| `-s, --statistics` | - | 只显示统计摘要 |
| `-t, --timestamp` | - | 在输出中包含时间戳 |
| `-j, --json` | - | 以JSON格式输出 |
| `-v, --verbose` | - | 详细调试输出 |
| `-h, --help` | - | 显示帮助信息 |

### 使用示例

#### 1. 基本跟踪
跟踪所有工作队列事件：

```bash
sudo ./workqueue-snoop
```

#### 2. 跟踪特定进程
只跟踪 PID 为 1234 的进程：

```bash
sudo ./workqueue-snoop -p 1234
```

#### 3. 跟踪特定CPU
只跟踪 CPU 0 上的事件：

```bash
sudo ./workqueue-snoop -c 0
```

#### 4. 跟踪特定工作队列
只跟踪 events 工作队列：

```bash
sudo ./workqueue-snoop -w events
```

#### 5. 函数过滤
只跟踪包含 "flush" 的函数：

```bash
sudo ./workqueue-snoop -f flush
```

#### 6. 限时跟踪
跟踪 10 秒后自动退出：

```bash
sudo ./workqueue-snoop -d 10
```

#### 7. 统计模式
显示 30 秒的统计信息：

```bash
sudo ./workqueue-snoop -s -d 30
```

#### 8. JSON输出
以JSON格式输出事件：

```bash
sudo ./workqueue-snoop -j
```

#### 9. 详细模式
包含时间戳和详细信息：

```bash
sudo ./workqueue-snoop -v -t
```

#### 10. 组合选项
跟踪特定进程的events工作队列，持续5分钟：

```bash
sudo ./workqueue-snoop -p 1234 -w events -d 300
```

## 输出格式

### 表格格式输出

默认输出格式包含以下列：

```
TIME               PID    CPU COMM             EVENT    WORK           FUNCTION                       WORKQUEUE            REQ_DELAY/EXEC
```

- **TIME** - 事件时间戳（如果启用-t选项）
- **PID** - 进程ID
- **CPU** - CPU编号
- **COMM** - 进程名称
- **EVENT** - 事件类型（QUEUE/ACTIVATE/START/END）
- **WORK** - 工作项指针地址
- **FUNCTION** - 执行的函数名
- **WORKQUEUE** - 工作队列名称
- **REQ_DELAY/EXEC** - 请求CPU/延迟或执行时间

### JSON格式输出

启用 `-j` 选项时，每个事件以JSON对象格式输出：

```json
{
  "timestamp": "83061.468134",
  "pid": 668,
  "cpu": 1,
  "comm": "usecd",
  "event": "QUEUE",
  "work": "0xffff8dca448ce408",
  "function": "bpf_prog_free_deferred",
  "workqueue": "events",
  "req_cpu": 8192
}
```

对于START和END事件，还包含额外字段：
- **queue_delay_ns** - 入队到开始执行的延迟（纳秒）
- **exec_time_ns** - 执行时间（纳秒）

## 输出示例

### 基本输出示例

```bash
$ sudo ./workqueue-snoop -d 3
TIME               PID    CPU COMM             EVENT    WORK           FUNCTION                       WORKQUEUE            REQ_DELAY/EXEC
83054.914393       599812 1   kworker/u10:1    START    0xffff8dc9f3163e08 flush_to_ldisc                 -                   58.36us
83054.914401       599812 1   kworker/u10:1    END      0xffff8dc9f3163e08 flush_to_ldisc                 -                    9.21us
83054.914484       602219 2   sudo             QUEUE    0xffff8dc9e405d408 flush_to_ldisc                 events_unbound       8192
83054.914485       602219 2   sudo             ACTIVATE 0xffff8dc9e405d408 -                              -                    -
```

### 详细模式输出

```bash
$ sudo ./workqueue-snoop -v -d 3
Starting workqueue tracing...
Self PID: 602232 (events from this process will be filtered)
Duration: 3 seconds
TIME               PID    CPU COMM             EVENT    WORK           FUNCTION                       WORKQUEUE            REQ_DELAY/EXEC
83054.914382       583202 1   kworker/1:0      START    0xffff8dca448ce408 bpf_prog_free_deferred         -                    -
83054.914387       583202 1   kworker/1:0      END      0xffff8dca448ce408 bpf_prog_free_deferred         -                    -
```

### JSON格式输出示例

```bash
$ sudo ./workqueue-snoop -j -d 2
{"timestamp":"83061.468134","pid":668,"cpu":1,"comm":"usecd","event":"QUEUE","work":"0xffff8dca448ce408","function":"bpf_prog_free_deferred","workqueue":"events","req_cpu":8192}
{"timestamp":"83061.468135","pid":668,"cpu":1,"comm":"usecd","event":"ACTIVATE","work":"0xffff8dca448ce408"}
{"timestamp":"83061.468244","pid":583202,"cpu":1,"comm":"kworker/1:0","event":"START","work":"0xffff8dca448ce408","function":"bpf_prog_free_deferred","queue_delay_ns":111445}
{"timestamp":"83061.468327","pid":583202,"cpu":1,"comm":"kworker/1:0","event":"END","work":"0xffff8dca448ce408","function":"bpf_prog_free_deferred","exec_time_ns":87077}
```

## 事件类型说明

| 事件类型 | 描述 | 关键字段 |
|----------|------|----------|
| QUEUE | 工作项被添加到工作队列 | function, workqueue, req_cpu |
| ACTIVATE | 工作项被激活准备执行 | work指针 |
| START | 工作项开始执行 | function, queue_delay_ns |
| END | 工作项执行完成 | function, exec_time_ns |

## 性能提示

1. **过滤使用**：在高负载系统上使用过滤选项（-p, -c, -w, -f）来减少输出量
2. **JSON vs 表格**：JSON格式输出开销较小，适合自动化处理
3. **统计模式**：使用 `-s` 选项获取汇总信息而不是详细事件
4. **限制时间**：使用 `-d` 选项设置合理的监控时间，避免生成过多数据

## 故障排除

### 常见问题

1. **程序无法退出**
   - 现版本已修复信号处理问题，支持 Ctrl+C 正常退出
   - 会在指定时间后自动强制退出

2. **权限不足**
   ```bash
   # 需要 root 权限运行
   sudo ./workqueue-snoop
   ```

3. **编译错误**
   ```bash
   # 确保安装了必要的开发包
   sudo apt-get install libbpf-dev bpftool
   ```

4. **输出过多**
   ```bash
   # 使用过滤选项减少输出
   sudo ./workqueue-snoop -w events -d 10
   ```

## 内核版本兼容性

- **推荐版本**：Linux 5.4+
- **最低版本**：Linux 4.18
- **已测试版本**：Ubuntu 20.04+, CentOS 8+, Debian 10+

## 相关工具

- `trace-cmd` - 通用内核跟踪工具
- `perf` - 性能分析工具  
- `bpftrace` - 动态跟踪语言
- `top` - 进程监控工具 