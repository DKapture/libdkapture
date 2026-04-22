// SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <thread>
#include <signal.h>
#include <unistd.h>
#include <unordered_map>
#include <sstream>
#include <cctype>
#include <stdint.h>
#include <inttypes.h>
#include <algorithm>
#include <sys/resource.h>

#include "com.h"
#include "lshw.skel.h"
#include <atomic>
#include "../so/ring-buffer.h"
#include <map>
#include <mutex>

struct DevEvent {
    uint32_t type; // 1=pci,2=usb,3=block
    uint32_t bus_id;
    uint32_t vendor;
    uint32_t device;
    uint32_t action; // 1=add,2=remove
    char name[32];
};

// forward declarations
static std::string read_file(const char *path);

// Simple in-memory device snapshot keyed by kobj name (sysfs basename)
class Devices {
public:
    struct Info {
        uint32_t type;
        uint32_t vendor;
        uint32_t device;
        std::string raw; // raw line from sysfs print or formatted info
    };

    void add_or_update(const std::string &name, const Info &info)
    {
        std::lock_guard<std::mutex> lg(mu_);
        map_[name] = info;
        printf("[devices] add/update %s -> %s\n", name.c_str(), info.raw.c_str());
    }

    void remove(const std::string &name)
    {
        std::lock_guard<std::mutex> lg(mu_);
        auto it = map_.find(name);
        if (it != map_.end()) {
            printf("[devices] remove %s -> %s\n", name.c_str(), it->second.raw.c_str());
            map_.erase(it);
        } else {
            printf("[devices] remove %s -> not found\n", name.c_str());
        }
    }

private:
    std::map<std::string, Info> map_;
    std::mutex mu_;
};

static Devices g_devices;
static std::atomic<bool> exit_flag(false);

static struct option lopts[]={
    {"help",no_argument,0, 'h'},
    {0,		0,				 0, 0  }
};

struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg;	  // Help message
};

static const HelpMsg help_msg[] = {
    {"", "Show this help"},
};

void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  list the system's hardware\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf(
			"  -%c, --%s %s\n\t%s\n",
			lopts[i].val,
			lopts[i].name,
			help_msg[i].argparam,
			help_msg[i].msg
		);
	}
}

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
            fprintf(stderr, "Code bug!!!\n");
            abort();
        }
    }
    return sopts;
}


void parse_args(int argc, char **argv)
{
    int opt, opt_idx;
    unsigned int bit_switch = 0;
    bool has_ip = false;
    std::string sopts = long_opt2short_opt(lopts);
    while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
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
}

void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; }; // Set exit flag on signal
	sa.sa_flags = 0;							   // No special flags
	sigemptyset(&sa.sa_mask); // No additional signals to block
	// Register the signal handler for SIGINT
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

// helper: read symlink and human size formatter must be available before
static std::string read_symlink(const char *path)
{
    char buf[512];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n < 0)
        return std::string();
    buf[n] = '\0';
    return std::string(buf);
}

// Simple human-friendly size (GiB) formatter
static std::string human_size_from_sectors(unsigned long long sectors, unsigned int sector_size)
{
    unsigned long long bytes = sectors * (unsigned long long)sector_size;
    const unsigned long long GiB = 1024ull * 1024ull * 1024ull;
    char buf[64];
    if (bytes >= GiB) {
        double v = (double)bytes / (double)GiB;
        snprintf(buf, sizeof(buf), "%.2fGiB", v);
    } else if (bytes >= 1024ull * 1024ull) {
        double v = (double)bytes / (1024.0 * 1024.0);
        snprintf(buf, sizeof(buf), "%.2fMiB", v);
    } else {
        snprintf(buf, sizeof(buf), "%lluB", bytes);
    }
    return std::string(buf);
}

static Devices::Info read_device_info_from_sysfs(uint32_t type, const char *name)
{
    Devices::Info info;
    info.type = type;
    char path[512];
    if (type == 1) { // PCI
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", name);
        std::string vendor = read_file(path);
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", name);
        std::string device = read_file(path);
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/class", name);
        std::string cls = read_file(path);
        // driver and module
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/driver", name);
        std::string driver_link = read_symlink(path);
        std::string module_name;
        if (!driver_link.empty()) {
            // driver_link is like "../../../../bus/pci/drivers/virtio-pci"
            size_t pos = driver_link.rfind('/');
            if (pos != std::string::npos) module_name = driver_link.substr(pos + 1);
        }
        info.raw = vendor + " " + device + " " + cls;
        if (!driver_link.empty()) info.raw += std::string(" driver=") + module_name;
        if (!vendor.empty()) info.vendor = strtoul(vendor.c_str(), NULL, 0);
        if (!device.empty()) info.device = strtoul(device.c_str(), NULL, 0);
    } else if (type == 2) { // USB
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", name);
        std::string vendor = read_file(path);
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", name);
        std::string product = read_file(path);
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/product", name);
        std::string prod = read_file(path);
        info.raw = vendor + " " + product + " " + prod;
        if (!vendor.empty()) info.vendor = strtoul(vendor.c_str(), NULL, 0);
        if (!product.empty()) info.device = strtoul(product.c_str(), NULL, 0);
    } else { // block/other
        snprintf(path, sizeof(path), "/sys/block/%s/dev", name);
        std::string dev = read_file(path);
        snprintf(path, sizeof(path), "/sys/block/%s/size", name);
        std::string size = read_file(path);
        // compute human size
        unsigned long long sectors = 0;
        if (!size.empty()) sectors = strtoull(size.c_str(), NULL, 10);
        unsigned int sector_size = 512;
        snprintf(path, sizeof(path), "/sys/block/%s/queue/physical_block_size", name);
        std::string ss = read_file(path);
        if (!ss.empty()) sector_size = atoi(ss.c_str());
        std::string hsize = human_size_from_sectors(sectors, sector_size);
        snprintf(path, sizeof(path), "/sys/block/%s/device/model", name);
        std::string model = read_file(path);
        // info.raw should contain the human-readable size only; model/rotational
        // are printed separately by the caller to avoid duplicate columns.
        info.raw = hsize;
    }
    return info;
}

static std::string read_file(const char *path)
{
    std::ifstream ifs(path);
    if (!ifs)
        return std::string();
    std::string s;
    std::getline(ifs, s);
    // trim trailing newline
    if (!s.empty() && s.back() == '\n')
        s.pop_back();
    return s;
}

// PCI IDs lookup
static std::unordered_map<uint16_t, std::string> pci_vendors;
static std::unordered_map<uint32_t, std::string> pci_devices; // key (vendor<<16 | device)

static void load_pci_ids()
{
    const char *paths[] = {"/usr/share/misc/pci.ids", "/usr/share/hwdata/pci.ids", NULL};
    for (const char **p = paths; *p; ++p) {
        std::ifstream ifs(*p);
        if (!ifs)
            continue;
        std::string line;
        uint16_t cur_vendor = 0;
        while (std::getline(ifs, line)) {
            if (line.empty() || line[0] == '#') continue;
            // vendor lines start at column 0, device lines are indented by a tab
            if (line[0] != '\t') {
                // vendor line: id SPACE name
                const char *s = line.c_str();
                const char *space = strchr(s, ' ');
                if (space) {
                    char idstr[16];
                    int n = space - s;
                    if (n > 0 && n < (int)sizeof(idstr)) {
                        memcpy(idstr, s, n);
                        idstr[n] = '\0';
                        unsigned int vid = 0;
                        if (sscanf(idstr, "%x", &vid) == 1) {
                            pci_vendors[(uint16_t)vid] = std::string(space + 1);
                            cur_vendor = (uint16_t)vid;
                        }
                    }
                }
            } else {
                // device line
                unsigned int did;
                const char *s = line.c_str() + 1;
                const char *space = strchr(s, '\t');
                if (!space) space = strchr(s, ' ');
                if (!space) continue;
                char idstr[16];
                int n = space - s;
                if (n <= 0 || n >= (int)sizeof(idstr)) continue;
                memcpy(idstr, s, n);
                idstr[n] = '\0';
                if (sscanf(idstr, "%x", &did) == 1) {
                    const char *pname = space + 1;
                    if (cur_vendor)
                        pci_devices[((uint32_t)cur_vendor << 16) | (uint32_t)did] = std::string(pname);
                }
            }
        }
        // stop after successfully loading one file
        if (!pci_vendors.empty()) return;
    }
}

static std::string pci_vendor_name(uint16_t vendor)
{
    auto it = pci_vendors.find(vendor);
    if (it != pci_vendors.end()) return it->second;
    char buf[16]; snprintf(buf, sizeof(buf), "0x%04x", vendor);
    return std::string(buf);
}

static std::string pci_device_name(uint16_t vendor, uint16_t device)
{
    uint32_t key = ((uint32_t)vendor << 16) | device;
    auto it = pci_devices.find(key);
    if (it != pci_devices.end()) return it->second;
    char buf[16]; snprintf(buf, sizeof(buf), "0x%04x", device);
    return std::string(buf);
}

// Map simple PCI class codes to human names (common ones)
static std::string pci_class_name(const std::string &class_hex)
{
    // class_hex expected like 0x010000
    unsigned int cls = 0;
    if (sscanf(class_hex.c_str(), "%x", &cls) != 1) return class_hex;
    unsigned int base = (cls >> 16) & 0xff;
    unsigned int sub = (cls >> 8) & 0xff;
    switch (base) {
    case 0x01:
        if (sub == 0x06) return "SATA controller";
        return "Mass storage controller";
    case 0x02:
        return "Network controller";
    case 0x03:
        return "Display controller";
    case 0x04:
        return "Multimedia controller";
    case 0x06:
        return "Bridge device";
    case 0x0c:
        return "Serial/USB controller";
    default:
        return class_hex;
    }
}

static int handle_dev_event(void *ctx, void *data, size_t data_sz)
{
    const DevEvent *e = (const DevEvent *)data;
    const char *t =(e->type == 1 ? "PCI" : (e->type == 2 ? "USB" : "BLOCK"));
    printf("[dev-event] %s action=%u name=%s vendor=0x%04x device=0x%04x\n",
           t, e->action, e->name, e->vendor, e->device);

    // Merge into snapshot: on add/update, re-read sysfs entry; on remove, delete
    if (e->action == 2) {
        g_devices.remove(std::string(e->name));
    } else {
        Devices::Info info = read_device_info_from_sysfs(e->type, e->name);
        g_devices.add_or_update(std::string(e->name), info);
    }

    return 0;
}

static void list_pci()
{
    const char *dir = "/sys/bus/pci/devices";
    DIR *d = opendir(dir);
    if (!d)
    {
        pr_error("open %s: %s\n", dir, strerror(errno));
        return;
    }
    // load pci.ids once
    load_pci_ids();
    // collect entries first
    struct PciEntry { 
        std::string bdf; 
        std::string vendor; 
        std::string device; 
        std::string cls; 
        std::string driver; 
        uint16_t vid; 
        uint16_t did;
     };
    std::vector<PciEntry> entries;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s/vendor", dir, ent->d_name);
        std::string vendor = read_file(path);
        snprintf(path, sizeof(path), "%s/%s/device", dir, ent->d_name);
        std::string device = read_file(path);
        snprintf(path, sizeof(path), "%s/%s/class", dir, ent->d_name);
        std::string cls = read_file(path);
        if (vendor.empty() && device.empty() && cls.empty()) continue;
        uint16_t vid = 0, did = 0;
        if (!vendor.empty()) sscanf(vendor.c_str(), "0x%hx", &vid);
        if (!device.empty()) sscanf(device.c_str(), "0x%hx", &did);
        // detect driver
        snprintf(path, sizeof(path), "%s/%s/driver", dir, ent->d_name);
        std::string driver_link = read_symlink(path);
        std::string driver;
        if (!driver_link.empty()) {
            size_t pos = driver_link.rfind('/');
            driver = (pos == std::string::npos) ? driver_link : driver_link.substr(pos + 1);
        }
        entries.push_back({std::string(ent->d_name), pci_vendor_name(vid), pci_device_name(vid,did), pci_class_name(cls), driver, vid, did});
    }
    closedir(d);

    // group by domain:bus (first 7 chars like 0000:00)
    std::map<std::string, std::vector<PciEntry>> groups;
    for (auto &e : entries) {
        std::string key;
        if (e.bdf.size() >= 7) key = e.bdf.substr(0,7); else key = "unknown";
        groups[key].push_back(e);
    }

    printf("PCI topology (grouped by domain:bus):\n");
    for (auto &g : groups) {
        printf("%s:\n", g.first.c_str());
        for (auto &e : g.second) {
            printf("  %-16s  %-20s  %-30s  %s%s\n", e.bdf.c_str(), e.vendor.c_str(), e.device.c_str(), e.cls.c_str(), e.driver.empty() ? "" : std::string("/" + e.driver).c_str());
        }
        printf("\n");
    }
}

static void list_usb()
{
    const char *dir = "/sys/bus/usb/devices";
    DIR *d = opendir(dir);
    if (!d)
    {
        pr_error("open %s: %s\n", dir, strerror(errno));
        return;
    }
    printf("\nUSB devices:\n");
    printf("%-16s %-8s %-8s %s\n", "Dev", "idVendor", "idProduct", "Product");
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (ent->d_name[0] == '.')
            continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s/idVendor", dir, ent->d_name);
        std::string vendor = read_file(path);
        if (vendor.empty())
            continue; // not a USB device node
        snprintf(path, sizeof(path), "%s/%s/idProduct", dir, ent->d_name);
        std::string product = read_file(path);
        snprintf(path, sizeof(path), "%s/%s/product", dir, ent->d_name);
        std::string prodname = read_file(path);
        printf("%-16s %-8s %-8s %s\n",
               ent->d_name,
               vendor.c_str(),
               product.c_str(),
               prodname.empty() ? "-" : prodname.c_str());
    }
    closedir(d);
}

static void list_block()
{
    const char *dir = "/sys/block";
    DIR *d = opendir(dir);
    if (!d)
    {
        pr_error("open %s: %s\n", dir, strerror(errno));
        return;
    }
    // build mount table from /proc/mounts
    std::unordered_map<std::string, std::pair<std::string,std::string>> mounts;
    {
        std::ifstream mfd("/proc/mounts");
        std::string line;
        while (std::getline(mfd, line)) {
            // device mountpoint fstype ...
            std::istringstream iss(line);
            std::string dev, mpoint, fstype;
            if (!(iss >> dev >> mpoint >> fstype)) continue;
            mounts[dev] = std::make_pair(mpoint, fstype);
        }
    }

    printf("\nBlock devices:\n");
    printf("%-10s %-14s %-12s %-6s %-20s %s\n", "Name", "Dev(Major:Minor)", "Size", "Type", "Model", "Serial/Partitions");
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (ent->d_name[0] == '.')
            continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s/dev", dir, ent->d_name);
        std::string dev = read_file(path);
        snprintf(path, sizeof(path), "%s/%s/size", dir, ent->d_name);
        std::string size = read_file(path);
        snprintf(path, sizeof(path), "%s/%s/device/model", dir, ent->d_name);
        std::string model = read_file(path);
        if (dev.empty() && size.empty() && model.empty())
            continue;
        // human size computed earlier in read_device_info_from_sysfs
        Devices::Info info = read_device_info_from_sysfs(3, ent->d_name);

        // serial
        snprintf(path, sizeof(path), "%s/%s/device/serial", dir, ent->d_name);
        std::string serial = read_file(path);

        // list partitions under /sys/block/<dev>
        std::string parts_str;
        DIR *d2 = opendir((std::string(dir) + "/" + ent->d_name).c_str());
        if (d2) {
            struct dirent *e2;
            while ((e2 = readdir(d2)) != NULL) {
                if (e2->d_name[0] == '.') continue;
                // partition names start with device name + digit, e.g., sda1
                if (strncmp(e2->d_name, ent->d_name, strlen(ent->d_name)) == 0 && isdigit((unsigned char)e2->d_name[strlen(ent->d_name)])) {
                    // find block device node
                    std::string devnode = std::string("/dev/") + e2->d_name;
                    auto it = mounts.find(devnode);
                    if (it != mounts.end()) {
                        parts_str += std::string(e2->d_name) + "(" + it->second.first + "," + it->second.second + ") ";
                    } else {
                        parts_str += std::string(e2->d_name) + " ";
                    }
                }
            }
            closedir(d2);
        }

        // detect type: rotational or non-rotational
        std::string type = "-";
        snprintf(path, sizeof(path), "%s/%s/queue/rotational", dir, ent->d_name);
        std::string rotational = read_file(path);
        if (!rotational.empty()) type = (rotational == "1") ? "HDD" : "SSD";

        // combine serial and partitions for safe c_str usage
        std::string serial_parts;
        if (!serial.empty()) {
            serial_parts = serial;
            if (!parts_str.empty()) serial_parts += " ";
            serial_parts += parts_str;
        } else {
            serial_parts = parts_str;
        }

        printf("%-10s %-14s %-12s %-6s %-20s %s\n", ent->d_name,
               dev.empty() ? "-" : dev.c_str(),
               info.raw.c_str(),
               type.c_str(),
               model.empty() ? "-" : model.c_str(),
               serial_parts.empty() ? "-" : serial_parts.c_str());
    }
    closedir(d);
}

static void list_net()
{
    const char *dir = "/sys/class/net";
    DIR *d = opendir(dir);
    if (!d) return;
    printf("\nNetwork interfaces:\n");
    printf("%-8s %-20s %-8s %-16s %s\n", "IF", "Driver", "Speed(Mb)", "MAC", "PCI Device");
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s/address", dir, ent->d_name);
        std::string mac = read_file(path);
        snprintf(path, sizeof(path), "%s/%s/speed", dir, ent->d_name);
        std::string speed = read_file(path);
        // driver
        snprintf(path, sizeof(path), "%s/%s/device/driver", dir, ent->d_name);
        std::string driver = read_symlink(path);
        std::string driver_name;
        if (!driver.empty()) {
            size_t pos = driver.rfind('/');
            driver_name = (pos == std::string::npos) ? driver : driver.substr(pos + 1);
        }
        // pci device name if any
        snprintf(path, sizeof(path), "%s/%s/device", dir, ent->d_name);
        std::string devlink = read_symlink(path);
        std::string pci_dev;
        if (!devlink.empty()) {
            // walk back to pcixxxxx/0000:00:03.0
            size_t pos = devlink.find("0000:");
            if (pos != std::string::npos) {
                // extract until next '/'
                size_t end = devlink.find('/', pos);
                pci_dev = devlink.substr(pos, end - pos);
            }
        }
        printf("%-8s %-20s %-8s %-16s %s\n", ent->d_name,
               driver_name.empty() ? "-" : driver_name.c_str(),
               speed.empty() ? "-" : speed.c_str(),
               mac.empty() ? "-" : mac.c_str(),
               pci_dev.empty() ? "-" : pci_dev.c_str());
    }
    closedir(d);
}

int main(int argc, char **argv)
{
    int ret = 0;
    struct lshw_bpf *obj = nullptr;

    parse_args(argc, argv);
    register_signal();

    /* Try to raise RLIMIT_MEMLOCK before loading BPF so libbpf can lock maps/programs.
     * If this fails (insufficient privileges) we'll still attempt to load BPF and
     * libbpf will emit a helpful message. */
    struct rlimit rl = {128 * 1024 * 1024, 128 * 1024 * 1024}; /* 128MB */
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        pr_warn("setrlimit(RLIMIT_MEMLOCK) failed: %s\n", strerror(errno));
    }

    obj = lshw_bpf::open_and_load();
    if (!obj)
    {
        pr_error("failed to open/load lshw bpf skeleton\n");
    }
    else
    {
        if (lshw_bpf::attach(obj) != 0)
        {
            pr_error("failed to attach lshw bpf\n");
        }
        else
        {
            int map_fd = bpf_map__fd(obj->maps.dev_events);
            if (map_fd >= 0)
            {
                struct ring_buffer *rb = ring_buffer__new(map_fd, handle_dev_event, NULL, NULL);
                if (!rb)
                {
                    pr_error("failed to create ring buffer\n");
                }
                else
                {
                    // Start a background thread to poll ring buffer similar to other tools
                    std::thread([rb]() {
                        while (true) {
                            int err = ring_buffer__poll(rb, 100);
                            if (err < 0) break;
                        }
                        ring_buffer__free(rb);
                    }).detach();
                }
            }
        }
    }

    // Full sysfs scan to build initial snapshot
    list_pci();
    list_usb();
    list_block();
    // Sleep until signal arrives. Using pause() would be fine, but use a loop
    // so that the program can be interrupted by signals and then perform cleanup.
    while (!exit_flag) {
        pause();
    }

    if (obj)
    {
        lshw_bpf::detach(obj);
        lshw_bpf::destroy(obj);
    }
    return ret;
}
