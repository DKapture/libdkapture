# lscgroup

## 功能描述

本bpf工具和系统工具lscgroup相似，但是要更加强大，运行性能更优，查询效率更高，可以查询更多cgroup细节信息。可以查询cgroup的唯一id，以及其父cgroup id，cgroup名称，子孙组数量，开启的资源控制器等等，具体请查看使用示例小节的字段说明。

## 使用方式

```bash
$ ./observe/lscgroup -h
Usage: ./observe/lscgroup [option]
  To query who are occupying the specified file.

Options:
  -n, --name [cgroup name]
        the directory name you use to create a new cgroup by calling 'mkdir'.

  -i, --id [cgroup id]
        the cgroup inode number, you can check this by call 'stat' syscall on a cgroup directory.

  -p, --parent_id [parent id]
        similar to id, but of parent.

  -l, --level [cgroup level]
        the cgroup rank level in the whole cgroup hierarchy tree. the level of root cgroup is 0, and it increases while going down through the tree

  -h, --help 
        print this help message
```

- -n：指定需要过滤的cgroup名字。
- -i：指定需要过滤的cgroup的id。
- -p：指定需要过滤的cgroup的父id。
- -l：指定过滤处于哪一层级的cgroup。
- -h：打印此帮助信息。

## 使用示例

```bash
$ sudo ./lscgroup | head -10
    ID parent  LVL  max-depth    DDT  dying-DDT    max-DDT   CSet D-kids t-kids T-kids  sub-ctl ctlr    flags name
-------------------------------------------------------------------------------------------------------------------
     1      0    0 2147483647    136         31 2147483647      1      4      0      0     021b 0f1b        0 
    26      1    1 2147483647      0          0 2147483647      1      0      0      0     0000 021b        0 init.scope
    67      1    1 2147483647      7          2 2147483647      0      1      0      0     021b 021b        0 machine.slice
 24843     67    2 2147483647      6          0 2147483647      0      1      0      0     001b 021b        0 machine-qemu\x2d1\x2dv25.scope
 24900  24843    3 2147483647      5          0 2147483647      0      0      5      5     0003 001b        0 libvirt
 24953  24900    4 2147483647      0          0 2147483647      1      0      0      0     0000 0003        0 emulator
 25024  24900    4 2147483647      0          0 2147483647      1      0      0      0     0000 0003        0 vcpu0
 25054  24900    4 2147483647      0          0 2147483647      1      0      0      0     0000 0003        0 vcpu1

$ sudo ./lscgroup -p 1
    ID parent  LVL  max-depth    DDT  dying-DDT    max-DDT   CSet D-kids t-kids T-kids  sub-ctl ctlr    flags name
-------------------------------------------------------------------------------------------------------------------
    26      1    1 2147483647      0          0 2147483647      1      0      0      0     0000 021b        0 init.scope
    67      1    1 2147483647      7          2 2147483647      0      1      0      0     021b 021b        0 machine.slice
   108      1    1 2147483647     57         11 2147483647      0     37      0      0     0210 021b        0 system.slice
   272      1    1 2147483647     59         17 2147483647      0      1      0      0     0212 021b        0 user.slice
   354      1    1 2147483647      0          0 2147483647      0      0      0      0     0000 021b        0 dev-hugepages.mount
   395      1    1 2147483647      0          0 2147483647      0      0      0      0     0000 021b        0 dev-mqueue.mount
```

字段说明：

- ID：当前cgroup的唯一id，本质也是inode编号，与cgroupfs下的对应目录的inode相同。值得注意的是，1号id表示的是cgroup根分组，1号分组的分组id显示为0，以此表示根分组没有父分组。
- parent：父分组id。
- LVL：全称level，即层级，cgroup分组是以目录（倒置）树的结构进行管理的，该字段则是用来指示当前cgroup所处在目录树中的第几层级。需要说明的是，根分组所属层级是第0级，越往下取值越大。
- max-depth：指示当前cgroup允许的最大层级，当新创建的cgroup位于的层级数大于这个值，将会创建失败。改置默认为2147483647，也就是不限制。
- DDT：全称descendants，表示该分组拥有的所有子孙分组的数量。
- dying-DDT：即正在消亡的子孙分组。
- max-DDT：即允许的最大子孙分组数，当当前cgroup分组拥有的子孙分组达到这个数时，将不允许新创建分组。默认2147483647，表不限制。
- CSet：表示当前分组拥有的非空子孙分组[^1]的数量。
- D-kids：全称populated-domain-kids，即域分组[^2]类型的非空子孙分组的数量。
- t-kids：全称populated-threaded-kids，即线程分组[^2]类型的非空子孙分组的数量。
- T-kids：全称threaded-kids，即线程分组类型的子孙分组的总数。
- sub-ctl：允许让子分组使用的资源控制器集合

[^1]: 非空分组的定义是，该分组下存在至少一个被管控的进程。
    
[^2]: 域分组、线程域分组以及线程分组的概念请参考cgruop的官方文档说明。
