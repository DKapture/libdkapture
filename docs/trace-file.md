# trace-file

## 功能描述

一个用于跟踪指定文件上发生的几乎所有事件的工具，被跟踪的文件必须存在。所有被跟踪的事件都来自用户空间，即通过系统调用操作，不包括来自内核的事件，例如通过用户编程的内核模块，但这不是绝对的，某些内核事件 API 可能仍然会被捕获，具体取决于实现情况。

文件是通过其内核对象进行跟踪的，而不是通过文件系统标签（路径），这在某些情况下很有趣，当一个文件在被跟踪时被删除，内核对象的引用仍然存在，我们仍然可以跟踪其上的后续事件，这些事件当然是由其他进程通过指向内核文件对象的文件描述符触发的。

## 使用方法

```bash
$ ./observe/trace-file -h
Usage: ./observe/trace-file [option]
  Trace all the events happening to a specified file, and print out the event details

Options:
  -p, --path <path>
        file path to trace

  -u, --uuid [uuid]
        when using the inode number of <path> as the filter,
        this option specify the uuid of filesystem to which
        the inode belong.
        you can get the uuid by running command 'blkid'

  -i, --inode <ino>
        use file inode as filter

  -h, --help 
        print this help message
```

- -p：指定需要跟踪的文件，路径必须是绝对路径。
- -u：指定目标文件所属的文件系统 UUID。
- -i：指定文件 inode 号。

## 事件列表

| 事件              | 描述           | 附加信息 |
| ----------------- | -------------- | -------- |
| open              | 文件打开事件   |          |
| close             | 文件关闭事件   |          |
| getxattr          | 获取扩展属性   |          |
| setxattr          | 设置扩展属性   |          |
| listxattr         | 列出扩展属性   |          |
| removexattr       | 删除扩展属性   |          |
| getacl            | 获取访问控制列表 |          |
| setacl            | 设置访问控制列表 |          |
| chown             | 更改文件所有者 |          |
| chmod             | 更改文件权限   |          |
| stat              | 获取文件状态   |          |
| mmap              | 内存映射       |          |
| flock             | 文件锁定       |          |
| fcntl             | 文件控制       |          |
| link              | 创建硬链接     |          |
| unlink            | 删除链接       |          |
| truncate          | 截断文件       |          |
| ioctl             | 输入输出控制   |          |
| rename            | 重命名文件     |          |
| fallocate         | 分配文件空间   |          |
| read              | 读取文件       |          |
| write             | 写入文件       |          |
| readv             | 向量读取       |          |
| writev            | 向量写入       |          |
| copy_file_range   | 复制文件范围   |          |
| sendfile          | 发送文件       |          |
| splice            | 拼接数据       |          |
| mknod             | 创建设备节点   |          |
| mkdir             | 创建目录       |          |
| rmdir             | 删除目录       |          |
| symlink           | 创建符号链接   |          |
| lseek             | 定位文件位置   |          |

## 输出示例

```
$ sudo ./observe/trace-file -p /usr/bin/ls
path: /usr/bin/ls
bpf load ok!!!
bpf attach ok!!!
watch events on file: /usr/bin/ls
(/usr/bin/ls), inode: [7865113]
uid:0 bash[2037379]: event: open, ino: 7865113, fmode: 494a801d, ret: 0(Success)
uid:0 ls[2037379]: event: mmap, addr(bpf): 0x55af01712000, len: 159744, prot: 1, flag: 1048578, pgoff: 0, ino: 7865113, ret: 94210131828736(addr)
uid:0 ls[2037379]: event: mmap, addr(bpf): 0x55af01716000, len: 90112, prot: 5, flag: 18, pgoff: 4, ino: 7865113, ret: 94210131845120(addr)
uid:0 ls[2037379]: event: mmap, addr(bpf): 0x55af0172c000, len: 40960, prot: 1, flag: 18, pgoff: 26, ino: 7865113, ret: 94210131935232(addr)
uid:0 ls[2037379]: event: mmap, addr(bpf): 0x55af01736000, len: 8192, prot: 3, flag: 18, pgoff: 35, ino: 7865113, ret: 94210131976192(addr)
uid:0 ls[2037379]: event: close, ino: 7865113
uid:1000 code[3093]: event: getattr, request_mask: 4095, query_flags: 256, ino: 7865113, ret: 0(Success)
uid:1000 code[3095]: event: getattr, request_mask: 4095, query_flags: 256, ino: 7865113, ret: 0(Success)
uid:1000 code[3092]: event: getattr, request_mask: 4095, query_flags: 256, ino: 7865113, ret: 0(Success)
```
