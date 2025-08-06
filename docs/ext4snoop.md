'# ext4snoop - EXT4 文件系统操作跟踪工具

## 概述

ext4snoop 是一个基于 eBPF 的工具，用于实时跟踪 ext4 文件系统的各种操作。它通过监听内核中的 ext4 tracepoint 来收集文件系统活动信息，可以帮助系统管理员和开发者理解文件系统的行为和性能特征。

## 功能特性

ext4snoop 可以跟踪以下 ext4 文件系统操作：

- **错误事件** (`ext4_error`) - 文件系统错误
- **写操作** (`ext4_write_begin/end`) - 文件写入开始和结束
- **块分配** (`ext4_allocate_blocks`) - 数据块分配
- **inode操作** (`ext4_free_inode`) - inode释放
- **文件同步** (`ext4_sync_file_enter`) - 文件同步操作
- **延迟写入** (`ext4_da_write_pages`) - 延迟分配写入页面
- **多块分配** (`ext4_mballoc_alloc`) - 多块分配器分配
- **日志操作** (`ext4_journal_start_sb`) - 日志事务开始
- **块释放** (`ext4_free_blocks`) - 数据块释放
- **文件截断** (`ext4_truncate_enter`) - 文件截断操作

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

# 编译 ext4snoop
make ext4snoop
```

编译成功后会生成以下文件：
- `ext4snoop` - 可执行文件
- `ext4snoop.bpf.o` - BPF 对象文件
- `ext4snoop.skel.h` - BPF skeleton 头文件

## 使用方法

### 基本语法

```bash
ext4snoop [选项]
```

### 命令行选项

| 选项 | 参数 | 描述 |
|------|------|------|
| `-h` | - | 显示帮助信息 |
| `-v` | - | 详细输出（调试模式） |
| `-t` | - | 包含时间戳 |
| `-p` | PID | 只跟踪指定进程ID |
| `-T` | TID | 只跟踪指定线程ID |
| `-c` | COMM | 只跟踪包含指定字符串的命令 |
| `-d` | DEV | 只跟踪指定设备 |
| `-D` | DURATION | 跟踪持续时间（秒） |

### 使用示例

#### 1. 基本跟踪
跟踪所有 ext4 文件系统操作：

```bash
sudo ./ext4snoop
```

#### 2. 带时间戳跟踪
包含时间戳信息：

```bash
sudo ./ext4snoop -t
```

#### 3. 跟踪特定进程
只跟踪 PID 为 1234 的进程：

```bash
sudo ./ext4snoop -p 1234
```

#### 4. 跟踪特定命令
只跟踪包含 "bash" 的命令：

```bash
sudo ./ext4snoop -c bash
```

#### 5. 跟踪特定设备
只跟踪 sda1 设备：

```bash
sudo ./ext4snoop -d sda1
```

#### 6. 限时跟踪
跟踪 60 秒后自动退出：

```bash
sudo ./ext4snoop -D 60
```

#### 7. 组合选项
带时间戳跟踪特定进程 30 秒：

```bash
sudo ./ext4snoop -t -p 1234 -D 30
```

## 输出格式

### 输出列说明

```
TIME(s)        COMM            PID     TID     EVENT          DEV       DETAILS
```

- **TIME(s)**: 时间戳（使用 -t 选项时显示）
- **COMM**: 进程命令名
- **PID**: 进程ID
- **TID**: 线程ID
- **EVENT**: 事件类型
- **DEV**: 设备信息
- **DETAILS**: 事件详细信息

### 事件类型说明

| 事件类型 | 描述 | 详细信息 |
|----------|------|----------|
| `ext4_error` | 文件系统错误 | function=函数名 line=行号 |
| `write_begin` | 写入开始 | ino=inode号 pos=位置 len=长度 |
| `write_end` | 写入结束 | ino=inode号 pos=位置 len=长度 copied=已复制 |
| `alloc_blocks` | 块分配 | ino=inode号 block=块号 len=长度 logical=逻辑块 |
| `free_inode` | inode释放 | ino=inode号 uid=用户ID gid=组ID blocks=块数 mode=模式 |
| `sync_enter` | 同步开始 | ino=inode号 parent=父inode datasync=数据同步标志 |
| `da_write_pages` | 延迟写入页面 | ino=inode号 first_page=首页 nr_to_write=写入页数 sync_mode=同步模式 |
| `mballoc_alloc` | 多块分配 | ino=inode号 result_group=结果组 result_start=结果起始 result_len=结果长度 |
| `journal_start` | 日志开始 | blocks=块数 rsv_blocks=保留块数 revoke_creds=撤销信用 type=类型 |
| `free_blocks` | 块释放 | ino=inode号 block=块号 count=数量 flags=标志 mode=模式 |
| `truncate_enter` | 截断开始 | ino=inode号 blocks=块数 |

### 示例输出

```
TIME(s)        COMM            PID     TID     EVENT          DEV       DETAILS
142.123456     unknown         0       0       write_begin             ino=12345 pos=0 len=4096
142.123467     unknown         0       0       alloc_blocks            ino=12345 block=1000 len=1 logical=0
142.123478     unknown         0       0       write_end               ino=12345 pos=0 len=4096 copied=4096
```

## 故障排除

### 常见问题

1. **权限不足**
   ```
   错误: Failed to load and verify BPF skeleton
   解决: 使用 sudo 运行程序
   ```

2. **内核版本不支持**
   ```
   错误: BPF program load failed
   解决: 确认内核版本 ≥ 4.18 且支持 eBPF
   ```

3. **缺少依赖**
   ```
   错误: Failed to open BPF skeleton
   解决: 安装 libbpf-dev 包
   ```

4. **无输出**
   - 确认系统使用 ext4 文件系统
   - 确认有文件系统活动
   - 检查过滤条件是否过于严格

### 调试模式

使用 `-v` 选项启用详细输出：

```bash
sudo ./ext4snoop -v
```

## 性能影响

ext4snoop 使用 eBPF 技术，具有以下特点：

- **低开销**: eBPF 程序在内核空间运行，开销极小
- **安全性**: BPF 验证器确保程序安全性
- **实时性**: 零拷贝环形缓冲区提供高性能数据传输

建议在生产环境中：
- 使用过滤选项减少数据量
- 避免长时间运行
- 监控系统性能指标

## 扩展开发

### 添加新的 tracepoint

要添加新的 ext4 tracepoint 支持：

1. 查看 tracepoint 格式：
   ```bash
   cat /sys/kernel/debug/tracing/events/ext4/新tracepoint/format
   ```

2. 在 `ext4snoop.bpf.c` 中添加：
   - 事件结构体
   - tracepoint 上下文结构体
   - 处理函数

3. 在 `ext4snoop.cpp` 中添加：
   - 用户空间事件结构体
   - 事件处理函数

### 自定义过滤

可以修改 BPF 程序添加自定义过滤逻辑，例如：
- 文件大小过滤
- 操作类型过滤
- 性能阈值过滤

## 相关工具

- **biosnoop**: 跟踪块 I/O 操作
- **filesnoop**: 跟踪文件打开操作
- **trace-file**: 跟踪文件操作

## 许可证

GPL 许可证

## 参考资料

- [ext4 文档](https://www.kernel.org/doc/html/latest/filesystems/ext4/index.html)
- [eBPF 文档](https://ebpf.io/)
- [bcc 工具集](https://github.com/iovisor/bcc) 