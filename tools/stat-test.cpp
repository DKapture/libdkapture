// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <iostream>
#include <sys/stat.h>
#include <cstring>

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		std::cerr << "Usage: " << argv[0] << " <file_path>" << std::endl;
		return 1;
	}

	const char *file_path = argv[1];
	struct stat file_stat;

	// 调用 stat 系统调用获取文件信息
	if (stat(file_path, &file_stat) == -1)
	{
		std::cerr << "Error: Unable to stat file '" << file_path
				  << "': " << strerror(errno) << std::endl;
		return 1;
	}

	// 打印设备号和 inode 编号
	std::cout << "File: " << file_path << std::endl;
	std::cout << "Device ID: " << file_stat.st_dev << std::endl;
	std::cout << "Inode Number: " << file_stat.st_ino << std::endl;

	return 0;
}