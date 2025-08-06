# DKapture编程接口-V1.0

(本文长时间未维护，请参考API头文件`include/dkapture.h`)

## 1. 概览

1. 接口类：API头文件提供的是一个接口类，提供接口：对象创建，打开初始化，关闭释放资源，对象释放，数据读取。

   ```c++
   class DKapture
   {
   public:
       virtual int open(FILE *fp = stdout, LogLevel lvl=INFO) = 0;
       virtual unsigned long long lifetime(int ms) = 0;/
       virtual ssize_t read(DataType dt, pid_t pid, DataHdr *buf, size_t bsz) = 0;
       virtual ssize_t read(const char *path, DataHdr *buf, size_t bsz) = 0;
       virtual ssize_t read(std::vector<DataType> &mts, pid_t pid, DataHdr *buf, size_t bsz) = 0;
       virtual ssize_t read(std::vector<const char *> &paths, DataHdr *buf, size_t bsz) = 0;
       virtual ssize_t read(DataType dt, std::vector<pid_t> &pids, DataHdr *buf, size_t bsz) = 0;
       virtual int close(void) = 0;
       static DKapture *new_instance();
       virtual ~DKapture() {};
   };
   ```
2. 数据类型枚举：用于指示读取数据的类型，具体用法参考接口细节描述。
   枚举的命名具备已识别特征，例如proc节点信息读取枚举的命名与其路径相识。

   ```c++
   enum DKapture::DataType
   { // 后缀小写表示非标系统节点，而是定制功能
       PROC_BEGIN,
       PROC_PID_STAT,    // /proc/<pid>/stat
       PROC_PID_STATM,   // /proc/<pid>/statm
       PROC_PID_STATUS,  // /proc/<pid>/status
       PROC_PID_NET,     // /proc/<pid>/net
       PROC_PID_IO,      // /proc/<pid>/io
       PROC_PID_CMDLINE, // /proc/<pid>/cmdline
       PROC_PID_ENV,     // /proc/<pid>/environ
       PROC_PID_CWD,     // /proc/<pid>/cwd
       PROC_PID_ROOT,    // /proc/<pid>/root
       PROC_PID_EXE,     // /proc/<pid>/exe
       PROC_PID_MAPS,    // /proc/<pid>/maps
       PROC_PID_traffic, // /proc/<pid>/traffic
       PROC_PID_blockio, // /proc/<pid>/traffic
       PROC_END,
       // 待扩展
   };
   ```
3. 数据描述头部：read接口读取的数据均以该头部描述为开始返回。

   ```c++
   struct DataHdr
   {
       enum DataType type;
       int dsz;
       long reserve[8]; // for backward compatibility
       char data[];
   };
   ```

---

## 2. 接口说明

### 2.1 DKapture::new_instance

**1. 函数原型**

```c++
static DKapture * DKapture::new_instance();
```

**2. 功能描述**

用于创建新的dkapture接口实例对象，创建处理的指针对象，再不需要使用时，需要使用 `delete`释放。内部实现仍然是基于 `new`语义，并且会抛出异常。

---

### 2.2 DKapture::open

**1. 函数原型**

```c++
int DKapture::open(FILE *fp = stdout, LogLevel lvl=INFO)
```

**2. 功能描述**

初始化dkapture接口对象实例，主要包括申请共享内存资源，挂载BPF程序等等。

**3. 参数描述**

- fp：dkapture日志输出文件指针
- lvl：dkapture日志等级

**4. 返回值**

0：成功；<0：失败，返回值的绝对值即errno。

---

### 2.3. DKapture::lifetime

**1. 函数原型**

```c++
unsigned long long DKapture::lifetime(unsigned long long ms)
```

**2. 功能描述**

设置数据的有效时间，数据每次从内核完成读取更新到共享内存后，它对于当前接口对象，都具备ms毫秒的有效期，在该期间内，使用该接口实例，执行对该类型数据的读取操作，都是读取的内存缓存值。

值得说明的是，有效期属性是每接口对象属性，即不同接口实例可以使用不同有效期，但是数据的更新是系统级别全局的（因为在共享内存中），因此，如果a接口对象的数据有效期是10ms，它在0ms时刻触发了数据更新，这并不意味着它的有效期只能到10ms时刻，因为期间可能有其他接口对象触发了数据更新。这样设计的目的是，仅可能的按需减少系统调用。

**3. 参数描述**

- ms：数据有效期限，单位ms。设置成UINT64_MAX时，接口不会修改有效期，仅返回当前的有效期，设置成0时，表示不使用有效期，每次读取数据都会读取内核最新状态，效率较慢。

**4. 返回值**

返回当前有效期（ms==UINT64_MAX），或修改前的有效期（ms!=UINT64_MAX）。

---

### 2.4 DKapture::read

**1. 函数原型**

```c++
ssize_t DKapture::read(DataType dt, pid_t pid, DataHdr *buf, size_t bsz);
ssize_t DKapture::read(const char *path, DataHdr *buf, size_t bsz);
ssize_t DKapture::read(std::vector<DataType> &dts, pid_t pid, DataHdr *buf, size_t bsz);
ssize_t DKapture::read(DataType dt, std::vector<pid_t> &pids, DataHdr *buf, size_t bsz);
ssize_t DKapture::read(std::vector<const char *> &paths, DataHdr *buf, size_t bsz);
```

**2. 功能描述**

用于读取指定内核数据，不同重载对应不同的读取方式，读取过程中，内部实现会根据用户调用durability设定的数据有效期，自行过滤过多的io或触发数据更新。

**3. 参
2. 重载2：`ssize_t DKapture::read(const char *path, DataHdr *buf, size_t bsz);`
   与重载1类似，不同的是，重载1的dt和p数描述**

1. 重载1：`ssize_t DKapture::read(DataType dt, pid_t pid, DataHdr *buf, size_t bsz);`
   - dt：指定要读取的数据类型
   - pid：读取指定pid进程的信息，用于需要pid的数据类型，该参数可以用于设定读取目标pid进程的信息，设置为0时表示读取所有进程(强烈建议不要使用该接口读取所有进程信息，因为进程的数量是不确定的，因此接口需要buffer也会变化，建议使用重载6读取所有进程信息)；对于不需要pid的数据类型，该参数被忽略。
   - buf：用于存放返回的数据，返回的数据是一个或多个以 `DataHdr`开头的数据，`DataHdr::data`指向实际数据结构，不同类型对应不同数据结构定义，具体参考 `dkapture-api.h`头文件中的定义，可以通过数据类型快速找到数据结构体的定义，例如，如果数据类型是 `DataType::PROC_PID_STAT`，则它对应的实际数据结构体的定义为 `struct ProcPidStat {...}`，即将下划线分割全大写的枚举名改成驼峰名即可。
   - bsz：指定buf的大小，单位字节。id在重载2中通过字符串来传递：
   - path: 通过路径来指定需要读取的数据类型，例如（path=/proc/1/stat）与重载1的（dt=DataType::PROC_PID_STAT, pid=1）等价。
3. 重载3：`ssize_t DKapture::read(std::vector<DataType> &dts, pid_t pid, DataHdr *buf, size_t bsz);`
   与重载1类似，不同的是，`dts`可以同时指定多个数据类型。
4. 重载4：`ssize_t DKapture::read(DataType dt, std::vector<pid_t> &pids, DataHdr *buf, size_t bsz);`
   与重载1类似，不同的是，`pids`可以同时指定多个pid，以读取多个进程的指定数据类型。
5. 重载5：`ssize_t DKapture::read(std::vector<const char *> &paths, DataHdr *buf, size_t bsz);`
   与重载2类似，不同的是，`paths`可以同时指定多个路径。并且在功能上可以实现重载3和重载4的结合。
6. 重载6：`ssize_t read(DataType dt, DKCallback cb, void *ctx)`
   读取所有进程的指定信息，相对与之前接口pid传0的优化版本。该接口会同步调用回调接口 `cb`返回数据，注意回调接口的实现需要尽量简短，无锁、无阻塞。

**4. 返回值**

读取成功时，返回读取到的数据的大小；返回0时，表示数据已读取完毕；返回<0时，表示读取出错，buf内存可能被部分修改，返回值的绝对值即errno。

---

### 2.5 DKapture::close

**1. 函数原型**

```c++
int DKapture::close(void);
```

**2. 功能描述**

释放对象占用的共享内存和相关BPF资源。

**3. 返回值**

成功返回0；失败返回<0，返回值的绝对值即errno。

---


