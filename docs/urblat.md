# urb请求延迟统计工具

## 功能描述

本工具通过eBPF技术实现USB请求块（URB）的延迟统计：

- 跟踪USB请求提交（usb_submit_urb）和完成（usb_free_urb）事件
- 计算USB请求从提交到完成的延迟时间
- 生成延迟时间直方图统计
- 支持设备过滤与cgroup过滤

## 参数说明

通过全局变量配置过滤规则：

| 变量名 | 类型 | 说明 |
|--------|------|-----|
| `filter_cg` | bool | 启用cgroup过滤（需配合cgroup_map使用）|
| `targ_per_disk` | bool | 按磁盘设备统计（暂未实现）|
| `targ_per_flag` | bool | 按请求标志统计（暂未实现）|
| `targ_dev` | u32  | 过滤指定设备号（major/minor组合）|
| `targ_ms` | bool | 以毫秒为单位统计（默认微秒）|

## 字段说明

- usecs：耗时范围
- count：调用次数
- distribution 直方图

## 使用示例

```bash
./urblat 
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
Tracing block device I/O... Hit Ctrl-C to end.
^C

     usecs               : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 1        |*                                       |
         4 -> 7          : 9        |***********                             |
         8 -> 15         : 3        |***                                     |
        16 -> 31         : 1        |*                                       |
        32 -> 63         : 21       |**************************              |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 1        |*                                       |
       256 -> 511        : 29       |************************************    |
       512 -> 1023       : 32       |****************************************|
      1024 -> 2047       : 26       |********************************        |
      2048 -> 4095       : 8        |**********                              |
      4096 -> 8191       : 10       |************                            |
```
