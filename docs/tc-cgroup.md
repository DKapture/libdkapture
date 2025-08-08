# tc-cgroup - Cgroup流量控制工具

## 概述

`tc-cgroup` 是一个基于eBPF的cgroup流量控制工具，用于对Linux cgroup中的进程网络流量进行精确的带宽限制。该工具利用内核的cgroup socket buffer (cgroup_skb) eBPF程序类型，在数据包进入或离开cgroup时进行实时监控和流量整形。

## 功能特性

- **精确流量控制**：基于令牌桶算法实现精确的带宽限制
- **双向控制**：支持egress（出站）和ingress（入站）流量控制
- **灵活配置**：支持多种带宽单位（K/M/G）和时间刻度配置
- **实时监控**：通过ring buffer实时报告流量统计信息
- **低开销**：内核态处理，对系统性能影响最小

## 技术原理

### eBPF程序架构

该工具使用两个主要的eBPF程序：

1. **cgroup_skb_egress**：处理出站流量
2. **cgroup_skb_ingress**：处理入站流量

### 令牌桶算法

采用令牌桶算法实现流量控制：

- **令牌生成**：根据配置的速率持续生成令牌
- **令牌消耗**：每个数据包消耗对应字节数的令牌
- **突发容忍**：通过时间刻度参数控制突发流量的容忍度
- **精确控制**：令牌不足时直接丢弃数据包



## 使用方法

### 基本语法

```bash
sudo ./tc-cgroup [选项]
```

### 命令行选项

| 选项 | 长选项 | 参数 | 说明 |
|------|--------|------|------|
| `-c` | `--cgroup` | `<路径>` | **必需**：cgroup路径 |
| `-r` | `--rate` | `<速率>` | 带宽限制（支持K/M/G后缀） |
| `-d` | `--direction` | `<方向>` | 控制方向（egress/ingress） |
| `-t` | `--timescale` | `<秒数>` | 时间刻度（控制突发容忍度） |
| `-h` | `--help` | - | 显示帮助信息 |

### 参数说明

#### 带宽限制 (-r, --rate)

支持多种单位：
- 纯数字：字节/秒
- K后缀：KB/秒
- M后缀：MB/秒  
- G后缀：GB/秒

示例：
```bash
-r 1000000    # 1MB/s
-r 1M         # 1MB/s
-r 100K       # 100KB/s
```

#### 控制方向 (-d, --direction)

- `egress`：控制出站流量（进程发送的数据）
- `ingress`：控制入站流量（进程接收的数据）

#### 时间刻度 (-t, --timescale)

控制令牌桶的突发容忍度：
- `1`：1秒刻度，严格限制，低突发容忍
- `60`：1分钟刻度，允许短期突发
- `3600`：1小时刻度，允许长期突发

### 使用示例

#### 示例1：限制cgroup出站流量

```bash
# 限制 /sys/fs/cgroup/net_cls/myapp 的进程出站流量为 10MB/s
sudo ./tc-cgroup -c /sys/fs/cgroup/net_cls/myapp -r 10M -d egress
```

#### 示例2：限制入站流量，允许短期突发

```bash
# 限制入站流量为 5MB/s，允许1分钟内的突发
sudo ./tc-cgroup -c /sys/fs/cgroup/net_cls/webserver -r 5M -d ingress -t 60
```


## 输出说明

### 实时监控输出

程序运行时会显示实时的流量监控信息：

```
Tracked process: PID 1234 [SEND] 1500 bytes
Tracked process: PID 1234 [DROP] 500 bytes
Tracked process: PID 5678 [SEND] 2000 bytes
```

- `[SEND]`：数据包被允许通过
- `[DROP]`：数据包因超出限制被丢弃
- `[MATCH]`：数据包匹配规则但无流量

### 配置信息输出

启动时会显示当前配置：

```
Setting rate limit: 10485760 B/s (10.0 MB/s)
Setting time scale: 60 seconds
Cgroup path: /sys/fs/cgroup/net_cls/myapp
Match direction: EGRESS (outgoing)
Rate limit: 10485760 B/s (10.0 MB/s)
Time scale: 60 seconds (max bucket capacity: 600.0 MB)
```

## 技术细节

### cgroup集成

该工具通过以下方式与cgroup集成：

1. **cgroup路径**：指定要控制的cgroup路径
2. **BPF程序挂载**：将eBPF程序挂载到cgroup的socket buffer
3. **进程监控**：监控cgroup内所有进程的网络活动

### 流量控制机制

1. **数据包拦截**：eBPF程序拦截所有网络数据包
2. **令牌检查**：检查当前令牌是否足够
3. **决策执行**：
   - 令牌充足：允许通过，扣除令牌
   - 令牌不足：丢弃数据包
4. **事件报告**：通过ring buffer报告处理结果

### 性能考虑

- **内核态处理**：所有流量控制逻辑在内核态执行
- **零拷贝**：使用ring buffer进行高效的事件传递
- **最小开销**：只在需要时进行令牌计算

## 故障排除

### 常见问题

#### 1. 权限错误

```
Error: This program must be run with root privileges
```

**解决方案**：使用sudo运行程序

#### 2. cgroup路径错误

```
Failed to open cgroup: /invalid/path (No such file or directory)
```

**解决方案**：确保cgroup路径存在且可访问

#### 3. BPF程序加载失败

```
Failed to open and load BPF skeleton: Operation not permitted
```

**解决方案**：
- 确保内核支持eBPF
- 检查/proc/sys/kernel/bpf_verifier_log设置
- 确保有足够的内存锁定权限

#### 4. 流量控制不生效

**可能原因**：
- cgroup路径不正确
- 进程不在指定的cgroup中
- 方向设置错误


