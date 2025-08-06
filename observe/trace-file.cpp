/**
 * trace what has been done by whom to a specific file
 */
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uuid/uuid.h>

#include <vector>
#include <thread>
#include <atomic>
#include <string>

#include "Ucom.h"
#include "jhash.h"
#include "Usr-grp.h"

#include "trace-file.skel.h"

#undef XATTR_NAME_MAX
#define XATTR_NAME_MAX 256
#define XATTR_VALUE_MAX 1024

#define LOG_DUMP(type, log)             \
    {                                   \
        type *slog = (typeof(slog))log; \
        slog->dump();                   \
    }

static trace_file_bpf *obj;
static std::thread *rb_thread;

enum LogType
{
    LOG_NONE,
    LOG_OPEN,
    LOG_CLOSE,
    LOG_GETXATTR,
    LOG_SETXATTR,
    LOG_LISTXATTR,
    LOG_REMOVEXATTR,
    LOG_GETACL,
    LOG_SETACL,
    LOG_CHOWN,
    LOG_CHMOD,
    LOG_STAT,
    LOG_MMAP,
    LOG_FLOCK,
    LOG_FCNTL,
    LOG_LINK,
    LOG_UNLINK,
    LOG_TRUNCATE,
    LOG_IOCTL,
    LOG_RENAME,
    LOG_FALLOCATE,
    LOG_READ,
    LOG_WRITE,
    LOG_READV,
    LOG_WRITEV,
    LOG_COPY_FILE_RANGE,
    LOG_SENDFILE,
    LOG_SPLICE,
    LOG_MKNOD,
    LOG_MKDIR,
    LOG_RMDIR,
    LOG_SYMLINK,
    LOG_LSEEK,
};

struct BpfData
{
    uid_t uid;
    pid_t pid;
    char comm[16];
    enum LogType log_type;
    void dump(void)
    {
        printf("uid:%u %s[%d]: ", uid, comm, pid);
    }
} __attribute__((__packed__));

struct OpenLog : public BpfData
{
    unsigned long i_ino;
    long ret;
    unsigned int f_mode;
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: open, ino: %lu, fmode: %x, ret: %ld(%s)\n", i_ino, f_mode, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct CloseLog : public BpfData
{
    unsigned long i_ino;
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: close, ino: %lu\n", i_ino);
    }
} __attribute__((__packed__));

struct XattrLog : public BpfData
{
    unsigned long i_ino;
    union
    {
        u32 name_list;
        u32 name; // the name string offset to 'action' field
    };
    u32 value; // the value's offset to 'action' field
    size_t size;
    long ret;
    char action[]; // must be less than 4096 - sizeof(BpfData) - sizeof(XattrLog)
    void dump(void)
    {
        this->BpfData::dump();
        switch (log_type)
        {
        case LOG_LISTXATTR:
        {
            printf("event: %.*s, names: ", 16, action);
            char *nxt_name = action + name_list;
            if (ret > 0)
            {
                if (size == 0) // empty request
                {
                    printf("%s", nxt_name);
                }
                else
                {
                    size_t sz = ret;
                    while (sz > 0)
                    {
                        printf("%s", nxt_name);
                        size_t slen = strlen(nxt_name);
                        slen += 1; // including the tailing null char
                        nxt_name += slen;
                        if (sz < slen)
                        {
                            pr_error("\nbugs detected\n");
                            exit(-2);
                        }
                        sz -= slen;
                        if (sz)
                            printf(",");
                    }
                }
            }
            printf("(sz:%lu), ino: %lu, ret: %ld(%s)\n",
                   size, i_ino, ret, strerror(-ret));
            break;
        }
        case LOG_REMOVEXATTR:
        {
            printf("event: %.*s, name: %.*s, ino: %lu, ret: %ld(%s)\n",
                   16, action,
                   XATTR_NAME_MAX, action + name,
                   i_ino, ret, strerror(-ret));
            break;
        }
        default:
        {
            printf("event: %.*s, name: %.*s, value: %.*s(sz:%lu), ino: %lu, ret: %ld(%s)\n",
                   16, action,
                   XATTR_NAME_MAX, action + name,
                   XATTR_VALUE_MAX, action + value, size,
                   i_ino, ret, strerror(-ret));
            break;
        }
        }
    }
} __attribute__((__packed__));

struct AclEntry // posix acl entry
{
    short e_tag;
    unsigned short e_perm;
    u32 e_id;
} __attribute__((__packed__));

struct AclLog : public BpfData
{
    unsigned long i_ino;
    u32 name;      // the name string offset to 'action' field
    u32 acl_entry; // the acl entry's offset to 'action' field
    size_t count;
    long ret;
    char action[]; // must be less than 4096 - sizeof(BpfData) - sizeof(AclLog)
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, name: %.*s, ",
               16, action,
               XATTR_NAME_MAX, action + name);

        printf("acl: ");

        struct AclEntry *nxt_entry;
        nxt_entry = (typeof(nxt_entry))(action + acl_entry);
        for (size_t i = 0; i < count; i++)
        {
            switch (nxt_entry->e_tag)
            {
            case ACL_USER_OBJ:
                printf("user::");
                break;
            case ACL_GROUP_OBJ:
                printf("group::");
                break;
            case ACL_MASK:
                printf("mask::");
                break;
            case ACL_OTHER:
                printf("other::");
                break;
            case ACL_USER:
                printf("user:%s:", user_name(nxt_entry->e_id));
                break;
            case ACL_GROUP:
                printf("group:%s:", group_name(nxt_entry->e_id));
                break;
            default:
                BUG("acl tag error\n");
            }

            printf("%s|", mode_str(nxt_entry->e_perm));
            nxt_entry++;
        }
        printf(", ino: %lu, ret: %ld(%s)\n", i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct ChownLog : public BpfData
{
    unsigned long i_ino;
    u32 uid;
    u32 gid;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, onwer: %s(%d):%s(%d), ino: %lu, ret: %ld(%s)\n",
               16, action,
               user_name(uid), uid, group_name(gid), gid,
               i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct ChmodLog : public BpfData
{
    unsigned long i_ino;
    u16 mode;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, mode: %s%s%s, ino: %lu, ret: %ld(%s)\n",
               16, action,
               mode_str(mode >> 6),
               mode_str(mode >> 3),
               mode_str(mode),
               i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct StatLog : public BpfData
{
    unsigned long i_ino;
    u32 request_mask;
    u32 query_flags;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, request_mask: %u, query_flags: %u, ino: %lu, ret: %ld(%s)\n",
               16, action,
               request_mask,
               query_flags,
               i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct MmapLog : public BpfData
{
    unsigned long i_ino;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flag;
    unsigned long pgoff;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, addr(bpf): 0x%lx, len: %lu, prot: %lu, "
               "flag: %lu, pgoff: %lu, ino: %lu, ret: %ld(%s)\n",
               16, action,
               addr, len, prot, flag, pgoff,
               i_ino, ret, ret > 0 ? "addr" : strerror(-ret));
    }
} __attribute__((__packed__));

struct FlckLog : public BpfData
{
    unsigned long i_ino;
    long arg;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        const char *lck_str = NULL;
        switch (arg)
        {
        case F_RDLCK:
            lck_str = "F_RDLCK";
            break;
        case F_WRLCK:
            lck_str = "F_WRLCK";
            break;
        case F_UNLCK:
            lck_str = "F_UNLCK";
            break;
        }
        printf("event: %.*s, arg: 0x%lx(%s), ino: %lu, ret: %ld(%s)\n",
               16, action, arg, lck_str,
               i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct FcntlLog : public BpfData
{
    unsigned long i_ino;
    unsigned int cmd;
    unsigned long arg;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, cmd: %d, arg: %lx, ino: %lu, ret: %ld(%s)\n",
               16, action, cmd, arg,
               i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct LinkLog : public BpfData
{
    unsigned long i_ino;
    unsigned long i_ino_new;
    unsigned long dir_ino;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        switch (log_type)
        {
        case LOG_LINK:
            printf("event: %.*s, old inode: %lu, new inode: %lu, dir inode: %lu, ino: %lu, ret: %ld(%s)\n",
                   16, action, i_ino, i_ino_new, dir_ino,
                   i_ino, ret, strerror(-ret));
            break;
        case LOG_UNLINK:
            printf("event: %.*s, inode: %lu, dir inode: %lu, ret: %ld(%s)\n",
                   16, action, i_ino, dir_ino,
                   ret, strerror(-ret));
            break;
        default:
            break;
        }
    }
} __attribute__((__packed__));

struct TruncateLog : public BpfData
{
    unsigned long i_ino;
    unsigned long length;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, length: %lu, ino: %lu, ret: %ld(%s)\n",
               16, action, length, i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct IoctlLog : public BpfData
{
    unsigned long i_ino;
    unsigned int cmd;
    unsigned long arg;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, cmd: %d, arg: %lx, ino: %lu, ret(%ld): %s\n",
               16, action, cmd, arg, i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct RenameLog : public BpfData
{
    unsigned long i_ino;
    unsigned int old_name;
    unsigned int new_name;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, old name: %s, new name: %s, ino: %lu, ret: %ld(%s)\n",
               16, action,
               action + old_name,
               action + new_name,
               i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct FallocateLog : public BpfData
{
    unsigned long i_ino;
    int mode;
    unsigned long offset;
    unsigned long len;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, mode: %d, offset: %lu, "
               "len: %lu, ino: %lu, ret: %ld(%s)\n",
               16, action, mode, offset, len,
               i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct RwLog : public BpfData
{
    unsigned long i_ino;
    unsigned long count; // size of kernel buf
    unsigned long pos;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        switch (log_type)
        {
        case LOG_READ:
            printf("event: read, count: %lu, pos: %lu, "
                   "ino: %lu, ret: %ld(%s)\n",
                   count, pos, i_ino, ret,
                   ret < 0 ? strerror(-ret) : "bytes");
            break;
        case LOG_WRITE:
            printf("event: write, count: %lu, pos: %lu, "
                   "ino: %lu, ret: %ld(%s)\n",
                   count, pos, i_ino, ret,
                   ret < 0 ? strerror(-ret) : "bytes");
            break;
        default:
            break;
        }
    }
} __attribute__((__packed__));

struct RwvLog : public BpfData
{
    unsigned long i_ino;
    unsigned int sz_arr; // offset(againt 'action') of an array of reading size
    unsigned int count;  // count of 'size' in array
    unsigned long pos;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        std::string szs;
        size_t *psz = (size_t *)(action + sz_arr);
        for (size_t i = 0; i < count; i++)
        {
            szs += std::to_string(psz[i]);
            szs += "|";
        }
        szs.pop_back();
        switch (log_type)
        {
        case LOG_READV:
            printf("event: readv, count: %u, each size: %s, pos: %lu, "
                   "ino: %lu, ret: %ld(%s)\n",
                   count, szs.c_str(), pos, i_ino, ret,
                   ret < 0 ? strerror(-ret) : "bytes");
            break;
        case LOG_WRITEV:
            printf("event: writev, count: %u, each size: %s, pos: %lu, "
                   "ino: %lu, ret: %ld(%s)\n",
                   count, szs.c_str(), pos, i_ino, ret,
                   ret < 0 ? strerror(-ret) : "bytes");
            break;
        default:
            break;
        }
    }
} __attribute__((__packed__));

struct CopyLog : public BpfData
{
    unsigned long from_ino;
    unsigned long to_ino;
    unsigned long from_pos;
    unsigned long to_pos;
    unsigned long size;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        switch (log_type)
        {
        case LOG_COPY_FILE_RANGE:
        {
            printf("event: copy_file_range, from_ino: %lu, to_ino: %lu, "
                   "from_pos: %lu, to_pos: %lu, size: %lu, "
                   "ret: %ld(%s)\n",
                   from_ino, to_ino, from_pos, to_pos, size,
                   ret, ret < 0 ? strerror(-ret) : "bytes");
            break;
        }
        case LOG_SENDFILE:
        {
            printf("event: sendfile, from_ino: %lu, to_ino: %lu, "
                   "from_pos: %lu, to_pos: %lu, size: %lu, "
                   "ret: %ld(%s)\n",
                   from_ino, to_ino, from_pos, to_pos, size,
                   ret, ret < 0 ? strerror(-ret) : "bytes");
            break;
        }
        case LOG_SPLICE:
        {
            printf("event: splice, from_ino: %lu, to_ino: %lu, "
                   "from_pos: %lu, to_pos: %lu, size: %lu, "
                   "ret: %ld(%s)\n",
                   from_ino, to_ino, from_pos, to_pos, size,
                   ret, ret < 0 ? strerror(-ret) : "bytes");
            break;
        }
        default:
            break;
        }
    }
} __attribute__((__packed__));
struct DirLog : public BpfData
{
    unsigned long dir_ino;
    unsigned long ino;
    u16 mode;
    u32 dev;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        switch (log_type)
        {
        case LOG_MKNOD:
            printf("event: mknod, mode: %s%s%s, dev: %u, dir_ino: %lu, ino: %lu, ret: %ld(%s)\n",
                   mode_str(mode >> 6), mode_str(mode >> 3), mode_str(mode),
                   dev, dir_ino, ino, ret, strerror(-ret));
            break;
        case LOG_MKDIR:
            printf("event: mkdir, mode: %s%s%s, dir_ino: %lu, ino: %lu, ret: %ld(%s)\n",
                   mode_str(mode >> 6), mode_str(mode >> 3), mode_str(mode),
                   dir_ino, ino, ret, strerror(-ret));
            break;
        case LOG_RMDIR:
            printf("event: rmdir, dir_ino: %lu, ino: %lu, ret: %ld(%s)\n",
                   dir_ino, ino, ret, strerror(-ret));
            break;
        default:
            break;
        }
    }
} __attribute__((__packed__));

struct SymLinkLog : public BpfData
{
    unsigned long dir_ino;
    unsigned long ino; // new inode linked to old name
    unsigned int oldname;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, old name: %s, dir inode: %lu, ino: %lu, ret: %ld(%s)\n",
               16, action, action + oldname,
               dir_ino, ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

struct SeekLog : public BpfData
{
    unsigned long i_ino;
    loff_t offset;
    int whence;
    long ret;
    char action[];
    void dump(void)
    {
        this->BpfData::dump();
        printf("event: %.*s, offset: %ld, whence: %d, ino: %lu, ret: %ld(%s)\n",
               16, action, offset, whence, i_ino, ret, strerror(-ret));
    }
} __attribute__((__packed__));

#ifndef BUILTIN
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct BpfData *log = (const struct BpfData *)data;
    switch (log->log_type)
    {
    case LOG_OPEN:
        LOG_DUMP(struct OpenLog, log);
        break;
    case LOG_CLOSE:
        LOG_DUMP(struct CloseLog, log);
        break;
    case LOG_GETXATTR:
        fallthrough;
    case LOG_SETXATTR:
        fallthrough;
    case LOG_LISTXATTR:
        fallthrough;
    case LOG_REMOVEXATTR:
        LOG_DUMP(struct XattrLog, log);
        break;
    case LOG_GETACL:
    case LOG_SETACL:
        LOG_DUMP(struct AclLog, log);
        break;
    case LOG_CHOWN:
        LOG_DUMP(struct ChownLog, log);
        break;
    case LOG_CHMOD:
        LOG_DUMP(struct ChmodLog, log);
        break;
    case LOG_STAT:
        LOG_DUMP(struct StatLog, log);
        break;
    case LOG_MMAP:
        LOG_DUMP(struct MmapLog, log);
        break;
    case LOG_FLOCK:
        LOG_DUMP(struct FlckLog, log);
        break;
    case LOG_FCNTL:
        LOG_DUMP(struct FcntlLog, log);
        break;
    case LOG_LINK:
        LOG_DUMP(struct LinkLog, log);
        break;
    case LOG_UNLINK:
        LOG_DUMP(struct LinkLog, log);
        break;
    case LOG_TRUNCATE:
        LOG_DUMP(struct TruncateLog, log);
        break;
    case LOG_IOCTL:
        LOG_DUMP(struct IoctlLog, log);
        break;
    case LOG_RENAME:
        LOG_DUMP(struct RenameLog, log);
        break;
    case LOG_FALLOCATE:
        LOG_DUMP(struct FallocateLog, log);
        break;
    case LOG_READ:
        fallthrough;
    case LOG_WRITE:
        LOG_DUMP(struct RwLog, log);
        break;
    case LOG_READV:
        fallthrough;
    case LOG_WRITEV:
        LOG_DUMP(struct RwvLog, log);
        break;
    case LOG_COPY_FILE_RANGE:
        fallthrough;
    case LOG_SENDFILE:
        fallthrough;
    case LOG_SPLICE:
        LOG_DUMP(struct CopyLog, log);
        break;
    case LOG_MKNOD:
        fallthrough;
    case LOG_MKDIR:
        fallthrough;
    case LOG_RMDIR:
        LOG_DUMP(struct DirLog, log);
        break;
    case LOG_SYMLINK:
        LOG_DUMP(struct SymLinkLog, log);
        break;
    case LOG_LSEEK:
        LOG_DUMP(struct SeekLog, log);
        break;
    case LOG_NONE:
        BUG("LOG_NONE should not be handled\n");
        break;
    }
    return 0;
}
#endif

union Rule
{
    char path[PATH_MAX];
    struct
    {
        u64 not_inode; // used for judging whether it's inode filter
        u64 inode;
        uuid_t dev_uuid;
    };
} rule = {};

static int filter_fd;
static int log_map_fd;
static bool use_inode = false;
static struct ring_buffer *rb = NULL;
static std::atomic<bool> exit_flag(false);

static struct option lopts[] = {
    {"path", required_argument, 0, 'p'},
    {"uuid", required_argument, 0, 'u'},
    {"inode", no_argument, 0, 'i'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}};

// Structure for help messages
struct HelpMsg
{
    const char *argparam; // Argument parameter
    const char *msg;      // Help message
};

// Help messages
static HelpMsg help_msg[] = {
    {"<path>", "file path to trace\n"},
    {"[uuid]", "when using the inode number of <path> as the filter,\n"
               "\tthis option specify the uuid of filesystem to which\n"
               "\tthe inode belong.\n"
               "\tyou can get the uuid by running command 'blkid'\n"},
    {"<ino>", "use file inode as filter\n"},
    {"", "print this help message\n"},
};

// Function to print usage information
void Usage(const char *arg0)
{
    printf("Usage: %s [option]\n", arg0);
    printf("  Trace all the events happening to a specified file, and print out the event details\n\n");
    printf("Options:\n");
    for (int i = 0; lopts[i].name; i++)
    {
        printf("  -%c, --%s %s\n\t%s\n",
               lopts[i].val,
               lopts[i].name,
               help_msg[i].argparam,
               help_msg[i].msg);
    }
}

// Convert long options to short options string
std::string long_opt2short_opt(const option lopts[])
{
    std::string sopts = "";
    for (int i = 0; lopts[i].name; i++)
    {
        sopts += lopts[i].val; // Add short option character
        switch (lopts[i].has_arg)
        {
        case no_argument:
            break;
        case required_argument:
            sopts += ":"; // Required argument
            break;
        case optional_argument:
            sopts += "::"; // Optional argument
            break;
        default:
            DIE("Code internal bug!!!\n");
            abort();
        }
    }
    return sopts;
}

static uuid_t dev_uuid;
// Parse command line arguments
void parse_args(int argc, char **argv)
{
    int opt, opt_idx;
    char buf[PATH_MAX] = {0};
    memset(buf, 0, PATH_MAX);
    optind = 1;
    std::string sopts = long_opt2short_opt(lopts); // Convert long options to short options
    while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
    {
        switch (opt)
        {
        case 'p':
            if (use_inode)
            {
                printf("error: -p option cannot be used together with -i option\n");
                Usage(argv[0]);
                exit(-1);
            }
            strncpy(rule.path, optarg, PATH_MAX);
            rule.path[PATH_MAX - 1] = 0;
            // remove the tailing '/'
            if (rule.path[strlen(rule.path) - 1] == '/')
                rule.path[strlen(rule.path) - 1] = 0;
            DEBUG(0, "path: %s\n", optarg);
            break;
        case 'u':
            if (uuid_parse(optarg, dev_uuid) == -1)
            {
                printf("uuid format error: %s\n", optarg);
                exit(-1);
            }
            rule.not_inode = 0;
            break;
        case 'i':
            if (rule.path[0])
            {
                printf("error: -i option cannot be used together with -p option\n");
                Usage(argv[0]);
                exit(-1);
            }
            use_inode = true;
            break;
        case 'h': // Help
            Usage(argv[0]);
            exit(0);
            break;
        default: // Invalid option
            Usage(argv[0]);
            exit(-1);
            break;
        }
    }

    if (use_inode)
    {   // the memory data of dev_uuid must not be all zero
        if (0 == memcmp(dev_uuid, buf, sizeof(uuid_t)))
        {
            printf("error: -i option requires -u option to set uuid of filesystem\n");
            Usage(argv[0]);
            exit(-1);
        }
    }
    else if (dev_uuid[0])
    {
        printf("error: -u option must be applied with -i option\n");
        Usage(argv[0]);
        exit(-1);
    }
    else if (rule.path[0] == 0)
    {
        printf("use -p option to set target file path to monitor on\n");
        exit(0);
    }
}

static void ringbuf_worker(void)
{
    while (!exit_flag)
    {
        int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
        // Check for errors during polling
        if (err < 0 && err != -EINTR)
        {
            pr_error("error polling ring buffer: %d\n", err);
            sleep(5); // Sleep before retrying
        }
    }
}

void register_signal()
{
    struct sigaction sa;
    sa.sa_handler = [](int)
    {
        exit_flag = true;
        stop_trace();
    }; // Set exit flag on signal
    sa.sa_flags = 0;          // No special flags
    sigemptyset(&sa.sa_mask); // No additional signals to block
    // Register the signal handler for SIGINT
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

static int update_filter(int filter_fd)
{
    ssize_t rd_sz;
    int target_fd;

    int iter_fd = bpf_iter_create(bpf_link__fd(obj->links.find_file_inode));
    if (iter_fd < 0)
    {
        pr_error("error creating BPF iterator\n");
        return -1;
    }

    target_fd = open(rule.path, O_RDONLY);
    if (target_fd < 0)
    {
        pr_error("open err: %s: %s\n", rule.path, strerror(errno));
        return errno;
    }

    printf("watch events on file: %s\n", rule.path);

    if (use_inode)
    {
        struct stat statbuf;
        if (0 != fstat(target_fd, &statbuf))
        {
            pr_error("stat %s err: %s", rule.path, strerror(errno));
            close(iter_fd);
            return errno;
        }
        rule.not_inode = 0;
        rule.inode = statbuf.st_ino;
        memmove(rule.dev_uuid, dev_uuid, sizeof(uuid_t));
    }

    char *buf = (typeof(buf))malloc(4096);
    if (!buf)
    {
        pr_error("out of mem\n");
        close(iter_fd);
        return -ENOMEM;
    }

    while ((rd_sz = read(iter_fd, buf, 4096)) > 0)
    {
    }

    free(buf);
    // close(target_fd);    // no need to close
    close(iter_fd);
    return 0;
}

int trace_file_deinit(void)
{
    exit_flag = true;
    if (rb_thread)
    {
        rb_thread->join();
        delete rb_thread;
        rb_thread = NULL;
    }
    if (rb)
    {
        ring_buffer__free(rb);
        rb = nullptr;
    }
    if (obj)
    {
        trace_file_bpf::detach(obj);
        trace_file_bpf::destroy(obj);
        obj = nullptr;
    }
    return 0;
}

#ifdef BUILTIN
int trace_file_init(int argc, char **argv, int (*cb)(void *, const void *, size_t), void* ctx)
#else
int main(int argc, char **argv)
#endif
{
    u32 key = 0;
    parse_args(argc, argv);
    exit_flag = false;

#ifndef BUILTIN
    register_signal();
#endif

    obj = trace_file_bpf::open_and_load();
    if (!obj)
        return -1;
    DEBUG(0, "bpf load ok!!!\n");
    if (0 != trace_file_bpf::attach(obj))
        goto err_out;
    DEBUG(0, "bpf attach ok!!!\n");

    filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
    if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
    {
        pr_error("error: bpf_map_update_elem\n");
        goto err_out; // Handle error
    }

    if (update_filter(filter_fd) != 0)
        goto err_out;

    log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
#ifdef BUILTIN
    rb = ring_buffer__new(log_map_fd, (ring_buffer_sample_fn)cb, ctx, NULL);
#else
    rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
#endif
    if (!rb)
        goto err_out; // Handle error

    rb_thread = new (std::nothrow)std::thread(ringbuf_worker);
    if (!rb_thread)
        goto err_out; // Handle error

#ifdef BUILTIN
    return 0;
#endif
    follow_trace_pipe();

err_out:
    trace_file_deinit();
    return -1;
}
