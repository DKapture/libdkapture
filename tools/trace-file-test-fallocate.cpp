// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

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

	off_t offset = 0;
	off_t len = 1024 * 1024; // 1 MB

	// 使用 fallocate 预分配文件空间
	if (fallocate(fd, 0, offset, len) == -1)
	{
		std::cerr << "Failed to allocate file space: " << strerror(errno)
				  << std::endl;
		close(fd);
		return EXIT_FAILURE;
	}

	std::cout << "Successfully allocated " << len << " bytes for file "
			  << filename << std::endl;

	close(fd);
	return EXIT_SUCCESS;
}