#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

void lock_file(int fd, int operation) {
    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = operation;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0; // Lock the whole file
    printf("&lock: %lx\n", &lock);

    if (fcntl(fd, F_SETLK, &lock) == -1) {
        std::cerr << "Failed to lock file: " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
}

void unlock_file(int fd) {
    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0; // Unlock the whole file

    if (fcntl(fd, F_SETLK, &lock) == -1) {
        std::cerr << "Failed to unlock file: " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(int n, char *args[]) {
    if (n < 2)
    {
        printf("err: please specify a file path\n");
        return -1;
    }
    const char *filename = args[1];
    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        std::cerr << "Failed to open file: " << strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    // 加锁文件
    lock_file(fd, F_WRLCK);

    // 写入文件
    std::ofstream file(filename, std::ios::app);
    if (!file.is_open()) {
        std::cerr << "Failed to open file stream" << std::endl;
        unlock_file(fd);
        close(fd);
        return EXIT_FAILURE;
    }

    file << "This is a test line.\n";
    file.close();

    // 解锁文件
    unlock_file(fd);

    close(fd);
    return EXIT_SUCCESS;
}