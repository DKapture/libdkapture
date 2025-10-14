// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <iostream>
#include <fstream>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

void lock_file(int fd, int operation)
{
	if (flock(fd, operation) == -1)
	{
		std::cerr << "Failed to lock file: " << strerror(errno) << std::endl;
		exit(EXIT_FAILURE);
	}
}

void unlock_file(int fd)
{
	if (flock(fd, LOCK_UN) == -1)
	{
		std::cerr << "Failed to unlock file: " << strerror(errno) << std::endl;
		exit(EXIT_FAILURE);
	}
}

int main(int n, char *args[])
{
	if (n < 2)
	{
		printf("err: please specify a file path\n");
		return -1;
	}
	const char *filename = args[1];
	int fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (fd == -1)
	{
		std::cerr << "Failed to open file: " << strerror(errno) << std::endl;
		return EXIT_FAILURE;
	}

	// 加锁文件
	lock_file(fd, LOCK_EX);

	// 写入文件
	std::ofstream file(filename, std::ios::app);
	if (!file.is_open())
	{
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