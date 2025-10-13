// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstring>

// 自定义的 ioctl 命令
#define EXAMPLE_IOCTL_CMD _IOR('E', 1, int)

int main(int n, char *args[])
{
	if (n < 2)
	{
		printf("err: please specify a file path\n");
		return -1;
	}
	const char *device = args[1];
	int fd = open(device, O_RDWR);
	if (fd == -1)
	{
		std::cerr << "Failed to open device: " << strerror(errno) << std::endl;
		return EXIT_FAILURE;
	}

	int value;
	int ret = ioctl(fd, EXAMPLE_IOCTL_CMD, &value);
	printf(
		"event: user-ioctl, cmd: %d, arg: %lx, ret: %d\n",
		EXAMPLE_IOCTL_CMD,
		&value,
		ret
	);
	fflush(stdout);
	if (ret == -1)
	{
		std::cerr << "Failed to execute ioctl: " << strerror(errno)
				  << std::endl;
		close(fd);
		return EXIT_FAILURE;
	}

	std::cout << "Ioctl command executed successfully, value: " << value
			  << std::endl;

	close(fd);
	return EXIT_SUCCESS;
}