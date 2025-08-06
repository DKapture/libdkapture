# peek-fd

## 功能描述

可用于监视任意进程的任意文件描述符的数据IO内容。最经典的场景就是查看指定后台进程的标准输出数据，由于一般服务进程都会把标准输出、错误输出重定向到/dev/null，即看不到任何输出，而很多时候，一些调试信息都是通过标准输出、错误输出打印的，这就会导致错过很多调试信息，包括标准c库自带的调试信息的打印。利用本工具，我们可以很轻松的将指定进程的标准输出、错误输出等数据导出到特定文件当中。

## 使用方式

```bash
sudo ./observe/peek-fd -h
Usage: ./observe/peek-fd [option]
  Trace file descriptor IO data of a specific process on the system. Supports filtering by PID and FD.

Options:
  -p, --pid <pid>
        filter with pid

  -f, --fd <fd>
        watch the specific fd in the process of pid

  -r, --read [read]
        watch read data

  -w, --write [write]
        watch write data

  -o, --outfile [outfile]
        write data to a file

  -s, --sock [sock]
        output include fd of sockect type

  -h, --help 
        print this help message
```

- -p：设定需要过滤的进程的pid。
- -f：设定监视该进程中的指定描述符。
- -r：只监控数据读取的内容。
- -w：只监控数据写入的内容。
- -o：将监控到的内容写入到指定文件。
- -s：支持监控套接字描述符。
- -h：打印帮助文档。

## 局限性

- 需要root权限运行。
- 当目标进程使用普通read/write系统调用对文件描述符进行操作时，支持监视的单次操作的大小不能超过**1M**字节，否则无法打印。
- 当目标进程使用的是readv/writev系列的系统调用对文件描述进行操作时，本工具最大只能追踪**32**个内存段的读取/写入（超过的部分被丢弃)，并且每个内存段不能超过**1M**字节（超过时，该段的内容无法打印）。
- 当目标进程使用的是send/recv系统调用操作套接字文件描述符时，局限性同read/write系统调用。
- 当目标进程使用的sendmsg/recvmsg系统调用访问套接字文件描述符时，局限性同readv/writev。
- 当目标进程使用的sendmmsg/recvmmsg系统调用访问套接字文件描述符时，消息的个数不能超过**16**个，并且每个消息各自的局限性同sendmsg/recvmsg。

## 使用示例

利用nc工具创建服务端和客户端

```bash
$ nc -ltv 127.0.0.1 11111  # 服务端
Listening on localhost 11111
Connection received on localhost 43880
sssss
sssssss
nihao ya  there
ca1sdfhjasdkf
dfasdfasfsddddddddddddddddddd
sdddddddddddddddddd
999999999999999
```

```bash
$ nc -tv 127.0.0.1 11111 # 客户端
Connection to 127.0.0.1 11111 port [tcp/*] succeeded!
sssss
sssssss
nihao ya  there
1sdfhjasdkf
cadfasdfasfsddddddddddddddddddd
sdddddddddddddddddd
999999999999999
```

监听上述网络通信，先通过/proc/[pid]/fd，获取上述进程的pid和套接字文件描述符，这里时137825和3。。

```bash
$ sudo ./observe/peek-fd -p 137825 -f 3 -rw
sssss
sssssss
nihao ya  there
ca1sdfhjasdkf
dfasdfasfsddddddddddddddddddd
sdddddddddddddddddd
999999999999999
```
