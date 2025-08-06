# spinlock_ob - 基于eBPF的锁性能分析工具

## 功能描述

本工具用于跟踪Linux内核中spin_lock的锁操作性能指标，主要功能包括：

- 测量锁获取等待时间（acquisition time）
- 统计锁持有时间（hold time）
- 支持纳秒级精度测量
- 提供按进程/线程过滤能力
- 支持符号级锁识别（内核符号或内存地址）
- 实时统计与周期性输出

## 参数说明

**过滤选项**:

| 参数 | 说明 |
|------|------|
| `-p/--pid PID` | 仅跟踪指定进程ID |
| `-t/--tid TID` | 仅跟踪指定线程ID |
| `-c/--caller FUNC` | 过滤调用函数前缀（如`pipe_`）|
| `-L/--lock LOCK` | 指定锁名称/内存地址（如`cgroup_mutex`）|

**输出控制**:

| 参数 | 说明 |
|------|------|
| `-n/--locks NR_LOCKS` | 显示前N个锁/线程（默认10）|
| `-s/--stacks NR_STACKS` | 每个锁显示堆栈条目数（默认4）|
| `-S/--sort SORT` | 排序字段（逗号分隔）:<br>`acq_max` `acq_total` `acq_count`<br>`hld_max` `hld_total` `hld_count`|

**运行控制**:

| 参数 | 说明 |
|------|------|
| `-d/--duration SEC` | 总运行时长（秒）|
| `-i/--interval SEC` | 统计输出间隔（秒）|
| `-R/--reset` | 每次输出后重置统计 |

**其他选项**:

| 参数 | 说明 |
|------|------|
| `-v/--verbose` | 显示调试信息 |
| `-T/--timestamp` | 输出时间戳 |
| `-P/--per-thread` | 按线程统计模式 |

## 字段说明

| 字段 | 描述 |
|------|------|
| `Caller` | 调用函数前缀）|
| `Avg Wait` | 平均等待时间 |
| `Max Wait` | 最大等待时间 |
| `Count` | 锁持有次数 |
| `Max Hold` | 单次最长持有时间（ns）|
| `Total Hold` | 总持有时间（ns）|
| `tid` | 线程ID |
| `pid` | 进程ID |

## 使用示例

**基础用法**:

```bash
# 系统级实时跟踪（Ctrl-C停止）
sudo ./spinlock_ob
Tracing spin lock events...  Hit Ctrl-C to end
^C

                               Caller  Avg Wait    Count   Max Wait   Total Wait
                      __schedule+0x9f 732011.2 h         7 5124078.5 h  5124078.5 h 
                      __schedule+0x9f 33710.8 h       152 5124078.5 h  5124044.5 h 
       newidle_balance.isra.101+0x23a 49269.7 h       104 5124078.5 h  5124044.5 h 
            __queue_delayed_work+0x5e 5124078.5 h         1 5124078.5 h  5124078.5 h 
                      __schedule+0x9f 854013.1 h         6 5124078.5 h  5124078.5 h 
                      __schedule+0x9f 1281019.6 h         4 5124078.5 h  5124078.5 h 
       _raw_spin_rq_lock_irqsave+0x1b 38526.1 h       133 5124078.5 h  5123976.0 h 
       _raw_spin_rq_lock_irqsave+0x1b 100471.8 h        51 5124078.5 h  5124061.5 h 
             tick_sched_do_timer+0x90 256203.9 h        20 5124078.5 h  5124078.5 h 
              __common_interrupt+0x3f 5124078.5 h         1 5124078.5 h  5124078.5 h 
                 handle_edge_irq+0x8c 5124078.5 h         1 5124078.5 h  5124078.5 h 
             tick_sched_do_timer+0x90 427005.1 h        12 5124078.5 h  5124061.5 h 
                  tick_irq_enter+0x60 96680.4 h        53 5124078.5 h  5124061.5 h 
                 drm_sched_main+0x2a1    3.3 us       11    23.7 us      35.8 us
                       tty_read+0x182    1.5 us       12     3.5 us      17.4 us
       _raw_spin_rq_lock_irqsave+0x1b    1.7 us        7     2.9 us      11.8 us
                  __sock_sendmsg+0xba    2.0 us        3     2.4 us       5.9 us
                    unix_release+0x34    1.9 us        4     2.2 us       7.7 us
                    do_sys_poll+0x24f    1.4 us        6     2.2 us       8.6 us
                  remove_vm_area+0x24    1.6 us        2     2.2 us       3.1 us
              unix_release_sock+0x1e4    2.0 us        2     2.2 us       4.0 us
       _raw_spin_rq_lock_irqsave+0x1b    1.0 us       13     2.2 us      13.3 us
             get_unused_fd_flags+0x29    1.5 us        2     2.1 us       3.1 us
                 set_next_entity+0xb6    1.9 us        2     2.1 us       3.7 us
            __queue_delayed_work+0x6c    1.6 us        5     2.1 us       8.2 us
         file_tty_write.isra.19+0x22e    1.2 us       12     2.0 us      14.6 us
                  __task_rq_lock+0x3b    2.0 us        1     2.0 us       2.0 us
```
