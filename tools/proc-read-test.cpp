#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <dirent.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>

class CalculateRunTime
{

public:
    struct timespec _start;
    void start()
    {
        clock_gettime(CLOCK_MONOTONIC, &_start);
    }

    long delta()
    {
        struct timespec _end;
        clock_gettime(CLOCK_MONOTONIC, &_end);
        return (_end.tv_sec - _start.tv_sec) * 1000000000 + (_end.tv_nsec - _start.tv_nsec);
    }
};

void read_proc_stat(const std::string &pid)
{
    std::string stat_path = "/proc/" + pid + "/stat";
    std::ifstream stat_file(stat_path);

    if (!stat_file.is_open())
    {
        printf("Failed to open: %s\n", stat_path.c_str());
        return;
    }

    std::string line;
    std::getline(stat_file, line);
    stat_file.close();

    std::istringstream iss(line);
    std::vector<std::string> fields;
    std::string field;

    // 将每个字段分割并存储到 vector 中
    while (iss >> field)
    {
        fields.push_back(field);
    }

    // 打印部分关键字段
    if (fields.size() >= 24)
    {
        // printf("PID: %s\n", fields[0].c_str()); // 进程 ID
    }
    else
    {
        // printf("Unexpected format in: %s\n", stat_path.c_str());
    }
}

void traverse_proc()
{
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
    {
        printf("Failed to open /proc directory\n");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != nullptr)
    {
        // 检查是否是数字目录（即 PID）
        if (entry->d_type == DT_DIR &&
            std::all_of(entry->d_name, entry->d_name + std::strlen(entry->d_name), ::isdigit))
        {
            std::string pid = std::string(entry->d_name);
            std::string task = "/proc/" + pid + "/task";
            DIR *task_dir = opendir(task.c_str());
            if (!task_dir)
            {
                printf("Failed to open %s directory\n", task.c_str());
                continue;
            }
            struct dirent *task_entry;
            while ((task_entry = readdir(task_dir)) != nullptr)
            {
                pid = std::string(task_entry->d_name);
                if (pid == ".." || pid == ".")
                {
                    continue; // 跳过 "." 和 ".." 目录
                }
                read_proc_stat(task_entry->d_name);
            }
            closedir(task_dir);
        }
    }

    closedir(proc_dir);
}

int main(int n, char *args[])
{
    int i = 0;
    if (n < 2)
    {
        printf("Usage: %s <number of iterations>\n", args[0]);
        return 1;
    }
    int loop = std::atoi(args[1]);
    while (i++ < loop)
    {
        printf("\33[H\33[2J\33[3J");
        CalculateRunTime runtime;
        runtime.start();
        traverse_proc();
        printf("delta: %d\n", runtime.delta());
    }
    return 0;
}