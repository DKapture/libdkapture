#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <argp.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <atomic>
#include <sys/syscall.h>

// libbpf headers
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Auto-generated BPF skeleton
#include "ps.skel.h"
// Task information structure that matches the one defined in ps.h
struct dcapture_task
{
    pid_t pid;
    char comm[16]; // TASK_COMM_LEN in kernel is 16
    int state;
    pid_t ppid;
    pid_t pgid;
    pid_t sid;
    int tty_nr;
    int tty_pgrp;
    unsigned int flags;
    unsigned long cmin_flt;
    unsigned long cmaj_flt;
    unsigned long min_flt;
    unsigned long maj_flt;
    unsigned long long utime;
    unsigned long long stime;
    unsigned long long cutime;
    unsigned long long cstime;
    int priority;
    int nice;
    int num_threads;
    unsigned long long start_time;
    unsigned long vsize;
    unsigned long rss;
    unsigned long rsslim;
    unsigned long start_code;
    unsigned long end_code;
    unsigned long start_stack;
    unsigned long kstkesp;
    unsigned long kstkeip;
    unsigned long signal;
    unsigned long blocked;
    unsigned long sigignore;
    unsigned long sigcatch;
    unsigned long wchan;
    int exit_signal;
    int processor;
    unsigned int rt_priority;
    unsigned int policy;
    unsigned long long delayacct_blkio_ticks;
    unsigned long guest_time;
    long cguest_time;
    unsigned long start_data;
    unsigned long end_data;
    unsigned long start_brk;
    unsigned long arg_start;
    unsigned long arg_end;
    unsigned long env_start;
    unsigned long env_end;
    int exit_code;
};

// Command line options configuration
static struct env
{
    bool verbose;
    bool show_header;
    bool wide_output;
    bool show_threads;
} env = {
    .verbose = false,
    .show_header = true,
    .wide_output = false,
    .show_threads = false,
};

static ps_bpf *obj;
static struct ring_buffer *rb = NULL;
static std::atomic<bool> exit_flag(false);

const char *argp_program_version = "ps 1.0";
const char *argp_program_bug_address = "your-email@example.com";

static const char argp_program_doc[] =
    "ps - Display process status information\n"
    "\n"
    "BPF version of standard ps command for displaying process information\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Display verbose output"},
    {"no-header", 'H', NULL, 0, "Don't display header"},
    {"wide", 'w', NULL, 0, "Don't truncate output"},
    {"threads", 'T', NULL, 0, "Display all threads"},
    {},
};

// libbpf print callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'v':
        env.verbose = true;
        break;
    case 'H':
        env.show_header = false;
        break;
    case 'w':
        env.wide_output = true;
        break;
    case 'T':
        env.show_threads = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

// Signal handler for clean termination
static void sig_handler(int sig)
{
    exit_flag = true;
}

static void register_signal()
{
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

// Convert clock ticks to human-readable time string
static std::string format_time(unsigned long long time)
{
    unsigned long minutes = time / (60 * sysconf(_SC_CLK_TCK));
    unsigned long seconds = time / sysconf(_SC_CLK_TCK) % 60;

    char buffer[32];
    sprintf(buffer, "%lu:%02lu", minutes, seconds);
    return std::string(buffer);
}

// Convert process state code to a readable character
static char get_state_char(int state)
{
    if (state == 0)
        return 'R'; // Running
    if (state & 1)
        return 'S'; // Interruptible sleep
    if (state & 2)
        return 'D'; // Uninterruptible sleep
    if (state & 4)
        return 'T'; // Stopped
    if (state & 16)
        return 'Z'; // Zombie
    if (state & 32)
        return 'X'; // Dead
    return '?';     // Unknown
}

// Process data received from BPF program
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct dcapture_task *task = static_cast<const struct dcapture_task *>(data);
    static bool header_printed = false;
    static int event_count = 0;

    // Print event info if verbose mode
    if (env.verbose)
    {
        std::cerr << "Received event #" << ++event_count << ", size: " << data_sz << " bytes" << std::endl;
    }

    // Print table header if needed and not yet printed
    if (env.show_header && !header_printed)
    {
        std::cout << std::setw(5) << "PID" << " "
                  << std::setw(5) << "PPID" << " "
                  << std::setw(5) << "PGID" << " ";

        if (env.verbose)
        {
            std::cout << std::setw(5) << "TTY" << " "
                      << std::setw(3) << "NI" << " "
                      << std::setw(6) << "THCNT" << " "
                      << std::setw(8) << "VSIZE" << " ";
        }

        std::cout << std::setw(1) << "S" << " "
                  << std::setw(8) << "%CPU" << " "
                  << std::setw(8) << "TIME" << " "
                  << "COMMAND" << std::endl;

        header_printed = true;
    }

    // Calculate CPU usage (simple approximation)
    unsigned long long total_time = task->utime + task->stime;
    double cpu_usage = 0.0; // Would require two sample points for actual CPU usage

    // Calculate memory usage (KB)
    unsigned long memory = task->vsize / 1024;

    // Convert CPU time to readable format (min:sec)
    std::string cpu_time = format_time(total_time);

    // Output process information
    std::cout << std::setw(5) << task->pid << " "
              << std::setw(5) << task->ppid << " "
              << std::setw(5) << task->pgid << " ";

    if (env.verbose)
    {
        std::cout << std::setw(5) << task->tty_nr << " "
                  << std::setw(3) << task->nice << " "
                  << std::setw(6) << task->num_threads << " "
                  << std::setw(8) << memory << " ";
    }

    std::cout << std::setw(1) << get_state_char(task->state) << " "
              << std::fixed << std::setprecision(1) << std::setw(8) << cpu_usage << " "
              << std::setw(8) << cpu_time << " "
              << task->comm << std::endl;

    return 0;
}

// Trigger the BPF iterator
void trigger_iterator()
{
    int iter_fd = -1;

    iter_fd = bpf_iter_create(bpf_link__fd(obj->links.dump_task));
    if (iter_fd < 0)
    {
        std::cerr << "Error creating BPF iterator\n";
        return;
    }
    char *buf = (char *)malloc(4096);
    if (!buf) {
        std::cerr << "Failed to allocate buffer memory\n";
        close(iter_fd);
        return;
    }
    while (read(iter_fd, buf, 4096) > 0)
    {
    }
    free(buf);

    close(iter_fd);
    iter_fd = -1;
}

int main(int argc, char **argv)
{
    int err;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    register_signal();
    libbpf_set_print(libbpf_print_fn);

    std::cerr << "Loading BPF program..." << std::endl;

    // Open BPF program
    obj = ps_bpf::open();
    if (!obj)
    {
        std::cerr << "Failed to open BPF program: " << errno << " (" << strerror(errno) << ")" << std::endl;
        return 1;
    }

    // Load BPF program
    if (ps_bpf::load(obj))
    {
        std::cerr << "Failed to load BPF program" << std::endl;
        ps_bpf::destroy(obj);
        return 1;
    }

    std::cerr << "BPF program loaded successfully, attaching..." << std::endl;

    // Attach BPF program
    if (ps_bpf::attach(obj))
    {
        std::cerr << "Failed to attach BPF program" << std::endl;
        ps_bpf::destroy(obj);
        return 1;
    }

    std::cerr << "BPF program attached successfully, setting up ringbuf..." << std::endl;

    // Set up ring buffer callback
    rb = ring_buffer__new(bpf_map__fd(obj->maps.output), handle_event, NULL, NULL);
    if (!rb)
    {
        std::cerr << "Failed to create ring buffer: " << errno << " (" << strerror(errno) << ")" << std::endl;
        ps_bpf::detach(obj);
        ps_bpf::destroy(obj);
        return 1;
    }

    // Trigger the iterator to collect process information
    std::cerr << "Attempting to trigger iterator program..." << std::endl;

    int iter_fd = -1;

    iter_fd = bpf_iter_create(bpf_link__fd(obj->links.dump_task));
    if (iter_fd < 0)
    {
        std::cerr << "Error creating BPF iterator\n";
        return 1;
    }
    char *buf = (char *)calloc(4096, 1);
    if (!buf) {
        std::cerr << "Failed to allocate buffer from heap\n";
        close(iter_fd);
        return 1;
    }
    read(iter_fd, buf, 4096);

    std::thread t([&iter_fd, &buf]()
                  {
        while (read(iter_fd, buf, sizeof(buf)) > 0);
        close(iter_fd);
        iter_fd = -1;
        exit_flag = true; });

    std::cerr << "Collecting process information..." << std::endl;

    // Process events from ring buffer until exit signal received
    while (!exit_flag)
    {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR)
        {
            std::cerr << "Error polling ring buffer: " << err << std::endl;
            break;
        }
        if (err == 0)
        {
            break;
        }
    }

    t.join();

    // Cleanup resources
    std::cerr << "Cleaning up resources..." << std::endl;
    ring_buffer__free(rb);
    ps_bpf::detach(obj);
    ps_bpf::destroy(obj);

    return 0;
}
