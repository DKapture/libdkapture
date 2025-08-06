## biotop

## 功能描述

biotop用于查询每进程、每设备在指定时间段内的IO使用情况。

## 参数说明

```bash
# ./observe/biotop -h
Usage: ./observe/biotop [option]
  To monitor the block io speed per process per disk.

Options:
  -p, --pid [pid]
        filter output by the pid

  -c, --comm [comm]
        filter output by the process comm.

  -d, --dev [dev]
        filter output by device number, format -d val, val is calculated by 'val=(major << 8 | minor)'

  -i, --interval [interval]
        statistic interval

  -h, --help 
        print this help message
```

- -p：过滤指定的pid。
- -c：过滤指定进程名。
- -d：过滤设备号，取值方式为 (MAJOR << 8 | MINOR)。
- -i：统计时间间隔。
- -h：打印此帮助信息。

## 字段说明

- PID：进程pid
- COMM：进程名
- D：IO方向，W指写入，R指读取
- DEV：设备号
- DISK：设备名
- IO：在指定时间段内，该进程产生的IO请求数量。
- Kbytes：在指定时间段内，该进程进行IO操作的字节数。
- AVGms：在指定时间段内，该进程每个IO请求的平均用时。

## 使用示例

```bash
# sudo ./observe/biotop -i 10
Tracing... Output every 10 secs. Hit Ctrl-C to end

PID     COMM             D   DEV   DISK       I/O  Kbytes  AVGms
0                        W   8:0   sda          6     200   0.44
655     jbd2/sda1-8      W   8:0   sda         23     296   0.99
238901  kworker/u32:4    W   8:0   sda         33     284   0.64
5378    IndexThread      W   8:0   sda          2       8   0.10
5378    ReceiveMessageT  W   8:0   sda          4      16   0.10
238901  kworker/u32:4    W 259:0   nvme0n1      1       4   0.28
3069    code             W   8:0   sda          5      40   0.14
```
