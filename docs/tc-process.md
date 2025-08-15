# tc-process

## 功能描述

`tc-process` 是一个基于 eBPF 的进程级网络限速与网络元组观测工具。它通过 Netfilter 钩子对目标进程的网络数据进行统计与整形（令牌桶），并结合若干 kprobe 建立 socket 与进程的关联关系，同时通过环形缓冲区向用户态输出结构化事件，便于观测。

## 主要特性

- 按进程限速：基于令牌桶（Token Bucket）在内核路径进行速率控制
- 按方向匹配：支持发送（egress）或接收（ingress）方向
- 协议解析：支持 IPv4 的 TCP/UDP，解析本地 IP、端口、协议号
- 进程归属：通过 socket 与进程映射，尽可能准确地将包归属到 PID
- 实时可观测：通过 ringbuf 输出事件（映射、解析、放行/丢弃、IP:端口学习）

## 构建

```bash
cd filter
make tc-process
```

依赖：libbpf、clang/LLVM、bpftool、内核头文件（详见 `filter/Makefile`）。

## 使用方法

```bash
sudo ./filter/tc-process -h
```

常用参数：
- `-p, --pid <pid>`：需要限速的目标进程 PID（必选）
- `-r, --rate <rate>`：带宽限制，支持 K/M/G 后缀（如 `100K`、`1M`、`2G`）
- `-d, --direction <egress|ingress>`：匹配方向；egress=发送，ingress=接收
- `-t, --timescale <seconds>`：时间刻度（秒），调节突发容忍度（令牌桶窗口）
- `-h, --help`：显示帮助

示例：
```bash
# 将 PID 1234 的发送方向限速到 1 MiB/s，时间刻度 60s（允许一定突发）
sudo ./filter/tc-process -p 1234 -r 1M -d egress -t 60

# 将 PID 5678 的接收方向限速到 100 KiB/s，时间刻度 1s（严格限速）
sudo ./filter/tc-process -p 5678 -r 100K -d ingress -t 1
```

## 工作原理

- 用户态将规则写入 BPF 映射 `process_rules`（字段包含 `target_pid`、`rate_bps`、`gress`、`time_scale`）。
- BPF 程序挂载在 Netfilter 的 `NF_INET_LOCAL_IN/LOCAL_OUT`：
  - 解析 IPv4 的 TCP/UDP 头，提取本地 IP、端口、协议号
  - 通过 `sock_map`（socket*→进程）或 `tuple_map`（仅 UDP ingress 场景）找到所属进程
  - 对该 PID 在映射 `buckets` 中执行令牌桶检查，不足则丢包，足够则放行
  - 通过 `ringbuf` 向用户态发出事件，便于实时观测
- 若干 kprobe 用于在 socket 创建/收发等路径上维护 `sock_map`，确保归属 PID 尽量准确。

## 事件类型

- `PROCESS_MAP`：建立了 socket→进程 的映射
- `PACKET_PARSE`：解析到本地网络元组（IP、端口、协议）
- `SEND_DROP`：限速事件（发送/丢弃字节数与报文数）
- `IP_AND_PORT`：学习到本地 IP:Port（用于 UDP ingress 归因）

用户态会打印这些事件，并附带当前配置的 `time_scale` 以便理解限速窗口。


## 注意事项与限制

- 当前在 Netfilter 路径仅解析 IPv4 的 UDP/TCP。
- `do_accept` 的 kretprobe 因验证器限制已禁用；进程归因主要依赖其他 kprobe 与 UDP 的元组学习。
- 为避免 dynptr 与 probe_read 的栈帧冲突，解析函数标记为 `noinline`，并在解析前预读取 `sk` 指针。
- 需要 root 权限与内核对 BPF Netfilter/ringbuf 的支持。

## 相关文档

- `docs/net-traffic.md`：网络流量观测
- `docs/net-filter.md`：网络包过滤
