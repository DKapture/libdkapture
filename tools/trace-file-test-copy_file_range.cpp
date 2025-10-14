// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>

void copy_file(const char *src_filename, const char *dst_filename)
{
	int src_fd = open(src_filename, O_RDONLY);
	if (src_fd == -1)
	{
		std::cerr << "Failed to open source file: " << strerror(errno)
				  << std::endl;
		return;
	}

	int dst_fd = open(dst_filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (dst_fd == -1)
	{
		std::cerr << "Failed to open destination file: " << strerror(errno)
				  << std::endl;
		close(src_fd);
		return;
	}

	off_t src_offset = 0;
	off_t dst_offset = 0;
	ssize_t bytes_copied;
	size_t len = 1024 * 1024; // 1 MB buffer size

	while (
		(bytes_copied =
			 copy_file_range(src_fd, &src_offset, dst_fd, &dst_offset, len, 0)
		) > 0
	)
	{
		std::cout << "Copied " << bytes_copied << " bytes from " << src_filename
				  << " to " << dst_filename << std::endl;
	}

	if (bytes_copied == -1)
	{
		std::cerr << "Failed to copy file: " << strerror(errno) << std::endl;
	}

	close(src_fd);
	close(dst_fd);
}

int main(int n, char *args[])
{
	if (n < 3)
	{
		printf("err: please specify a src file path and a dst file path\n");
		return -1;
	}
	const char *src_filename = args[1];
	const char *dst_filename = args[2];

	copy_file(src_filename, dst_filename);

	return 0;
}