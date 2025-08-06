#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <getopt.h>
#include <string>
#include <signal.h>
#include <pthread.h>

#include "peek-fd.skel.h"
#include "Ucom.h"

// Constants for read and write flags
#define FD_READ 1
#define FD_WRITE 2

// Structure to hold the rule for filtering
struct Rule
{
    pid_t pid; // Process ID to filter
    int fd;    // File descriptor to watch
    int rw;    // Read/Write flags
} rule = {
    .pid = -1,
    .fd = -1,
    .rw = 0 // Default to watch both read and write
};

// Structure to hold log data
struct BpfData
{
    ssize_t sz; // Size of the log
    char buf[]; // Buffer for the log data
};

// Global variables
static peek_fd_bpf *obj;       // BPF program object
static int log_map_fd;         // File descriptor for log map
struct ring_buffer *rb = NULL; // Ring buffer for log events
static int filter_fd;          // File descriptor for filter map
static pthread_t t1;           // Thread for processing ring buffer
static bool exit_flag = false; // Flag to signal exit
static bool enable_sock_trace;
// Command line options
static struct option lopts[] = {
    {"pid", required_argument, 0, 'p'},
    {"fd", required_argument, 0, 'f'},
    {"read", no_argument, 0, 'r'},
    {"write", no_argument, 0, 'w'},
    {"outfile", required_argument, 0, 'o'},
    {"sock", no_argument, 0, 's'},
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
    {"<pid>", "filter with pid\n"},
    {"<fd>", "watch the specific fd in the process of pid\n"},
    {"[read]", "watch read data\n"},
    {"[write]", "watch write data\n"},
    {"[outfile]", "write data to a file\n"},
    {"[sock]", "output include fd of sockect type\n"},
    {"", "print this help message\n"},
};

// Function to print usage information
void Usage(const char *arg0)
{
    printf("Usage: %s [option]\n", arg0);
    printf("  Trace file descriptor IO data of a specific process on the system. "
           "Supports filtering by PID and FD.\n\n");
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

// Parse command line arguments
void parse_args(int argc, char **argv)
{
    int opt, opt_idx;
    optind = 1;
    std::string sopts = long_opt2short_opt(lopts); // Convert long options to short options
    while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
    {
        switch (opt)
        {
        case 'p': // Process ID
            rule.pid = strtol(optarg, NULL, 10);
            break;
        case 'f': // File descriptor
            rule.fd = strtol(optarg, NULL, 10);
            break;
        case 'h': // Help
            Usage(argv[0]);
            exit(0);
            break;
        case 'r': // Read flag
            rule.rw |= FD_READ;
            break;
        case 'w': // Write flag
            rule.rw |= FD_WRITE;
            break;
        case 'o': // output file
            freopen(optarg, "w+", stdout);
            break;
        case 's':
            enable_sock_trace = true;
            break;
        default: // Invalid option
            Usage(argv[0]);
            exit(-1);
            break;
        }
    }
    // Ensure both PID and FD are specified
    if (rule.fd == -1 || rule.pid == -1)
    {
        printf("\nYou need to specify which process and which fd to \n"
               "watch on by the options -pid(-p) and -fd(-f)\n\n");
        exit(-1);
    }
    if (rule.rw == 0)
    {
        printf("\nYou need to specify at least one of option -r/-w\n\n");
        exit(-1);
    }
}

// Handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct BpfData *log = (const struct BpfData *)data; // Cast data to BpfData structure
    fwrite(log->buf, 1, log->sz, stdout);             // Write log buffer to stdout
    fflush(stdout);
    return 0;
}

// Worker thread for processing ring buffer
void *ringbuf_worker(void *)
{
    while (!exit_flag)
    {
        int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
        // Check for errors during polling
        if (err < 0 && err != -EINTR)
        {
            pr_error("Error polling ring buffer: %d\n", err);
            sleep(5); // Sleep before retrying
        }
    }
    return NULL;
}

// Register signal handler for graceful exit
void register_signal(void)
{
    struct sigaction sa;
    sa.sa_handler = [](int)
    { exit_flag = true; };    // Set exit flag on signal
    sa.sa_flags = 0;          // No special flags
    sigemptyset(&sa.sa_mask); // No additional signals to block
    // Register the signal handler for SIGINT
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

static void enable_read_trace(void)
{
    if (!(rule.rw & FD_READ))
        return;

    bpf_program__set_autoload(obj->progs.trace_sys_enter_read, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_readv, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_preadv, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_preadv2, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_read, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_readv, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_preadv, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_preadv2, true);

    if (!enable_sock_trace)
        return;

    bpf_program__set_autoload(obj->progs.trace_sys_enter_recvfrom, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_recvmsg, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_recvmmsg, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_recvfrom, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_recvmsg, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_recvmmsg, true);
}

static void enable_write_trace(void)
{
    if (!(rule.rw & FD_READ))
        return;

    bpf_program__set_autoload(obj->progs.trace_sys_enter_write, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_writev, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_pwritev, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_pwritev2, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_write, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_writev, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_pwritev, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_pwritev2, true);

    if (!enable_sock_trace)
        return;

    bpf_program__set_autoload(obj->progs.trace_sys_enter_sendto, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_sendmsg, true);
    bpf_program__set_autoload(obj->progs.trace_sys_enter_sendmmsg, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_sendto, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_sendmsg, true);
    bpf_program__set_autoload(obj->progs.trace_sys_exit_sendmmsg, true);
}

// Main function
int main(int argc, char *args[])
{
    parse_args(argc, args); // Parse command line arguments
    register_signal();      // Register signal handler

    int key = 0;               // Key for BPF map
    obj = peek_fd_bpf::open(); // Load BPF program
    if (!obj)
        exit(-1); // Exit if loading failed

    enable_read_trace();
    enable_write_trace();
    ; // Load BPF program
    if (peek_fd_bpf::load(obj))
        exit(-1); // Exit if loading failed

    if (0 != peek_fd_bpf::attach(obj))
        exit(-1); // Attach BPF program

    // Get file descriptor for filter map and update it with the rule
    filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
    if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
    {
        printf("Error: bpf_map_update_elem");
        goto err_out; // Handle error
    }

    // Create a ring buffer for logs
    log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
    rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
    if (!rb)
        goto err_out; // Handle error

    printf("start peeking\n");
    // Create a thread for processing the ring buffer
    pthread_create(&t1, NULL, ringbuf_worker, NULL);
    follow_trace_pipe();    // Read trace pipe
    pthread_join(t1, NULL); // Wait for the worker thread to finish
    printf("normally exit\n");

err_out:
    if (rb)
        ring_buffer__free(rb); // Free ring buffer if allocated
    peek_fd_bpf::detach(obj);  // Detach BPF program
    peek_fd_bpf::destroy(obj); // Clean up BPF program
    return 0;                  // Exit successfully
}