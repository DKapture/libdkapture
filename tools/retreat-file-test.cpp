#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstring>
#include <cerrno>

#define pause(fmt, args...)                                                    \
	{                                                                          \
		printf(fmt, ##args);                                                   \
		printf("\nPress any key to continue:");                                \
		getchar();                                                             \
	}

// 假设 retreat-file 模块提供了一个 IOCTL 命令来恢复文件

void test_retreat_file(const char *filename)
{
	// 打开文件
	int fd = open(filename, O_RDWR);
	if (fd == -1)
	{
		std::cerr << "Failed to open file: " << strerror(errno) << std::endl;
		return;
	}

	// 删除文件
	if (unlink(filename) == -1)
	{
		std::cerr << "Failed to delete file: " << strerror(errno) << std::endl;
		close(fd);
		return;
	}

	pause("%s is deleted, check that in another terminal", filename);

	// 打开 retreat-file 设备
	int retreat_fd = open("/dev/retreat-file", O_WRONLY);
	if (retreat_fd == -1)
	{
		std::cerr << "Failed to open retreat device: " << strerror(errno)
				  << std::endl;
		close(fd);
		return;
	}

	// 使用 write 恢复文件
	if (write(retreat_fd, filename, strlen(filename)) == -1)
	{
		std::cerr << "Failed to retreat file: " << strerror(errno) << std::endl;
	}
	else
	{
		std::cout << "File retreated: " << filename << std::endl;
	}

	// 关闭文件描述符
	close(fd);
	close(retreat_fd);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		std::cerr << "Usage: " << argv[0] << " <file to test>" << std::endl;
		return EXIT_FAILURE;
	}

	const char *filename = argv[1];
	test_retreat_file(filename);

	return EXIT_SUCCESS;
}