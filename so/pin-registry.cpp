// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>

#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fstream>
#include <sstream>
#include <mutex>

#include "pin-registry.h"

static std::mutex s_mutex;

// 确保 registry 和锁文件存在，首次访问时自动创建
static void ensure_registry_files()
{
	const char *files[] = {
		PinRegistry::REGISTRY_FILE,
		PinRegistry::LOCK_FILE,
		nullptr
	};
	for (int i = 0; files[i]; i++) {
		int fd = open(files[i], O_CREAT | O_RDWR, 0644);
		if (fd >= 0) close(fd);
	}
}

int PinRegistry::lock_fd()
{
	ensure_registry_files();
	int fd = open(LOCK_FILE, O_RDWR);
	if (fd < 0) return -errno;
	if (flock(fd, LOCK_EX) != 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	return fd;
}

void PinRegistry::unlock_fd(int fd)
{
	if (fd >= 0) {
		flock(fd, LOCK_UN);
		close(fd);
	}
}

int PinRegistry::register_map(const char *name,
			       struct bpf_map *map,
			       const char *pin_path)
{
	if (!name || !map || !pin_path)
		return -EINVAL;

	ensure_registry_files();

	int err;
	if (access(pin_path, F_OK) != 0) {
		err = bpf_map__pin(map, pin_path);
		if (err) return err;
	}

	std::lock_guard<std::mutex> lock(s_mutex);

	int fd = lock_fd();
	if (fd < 0) return fd;

	auto entries = read_all();

	bool found = false;
	for (auto &e : entries) {
		if (e.first == name) {
			e.second = pin_path;
			found = true;
			break;
		}
	}
	if (!found)
		entries.push_back({name, pin_path});

	err = write_all(entries);
	unlock_fd(fd);
	return err;
}

std::string PinRegistry::lookup(const char *name)
{
	if (!name) return "";

	ensure_registry_files();

	std::lock_guard<std::mutex> lock(s_mutex);

	int fd = lock_fd();
	if (fd < 0) return "";

	auto entries = read_all();
	unlock_fd(fd);

	for (const auto &e : entries) {
		if (e.first == name)
			return e.second;
	}
	return "";
}

int PinRegistry::remove_entry(const char *name)
{
	if (!name) return -EINVAL;

	std::lock_guard<std::mutex> lock(s_mutex);

	int fd = lock_fd();
	if (fd < 0) return fd;

	auto entries = read_all();
	auto it = entries.begin();
	while (it != entries.end()) {
		if (it->first == name)
			it = entries.erase(it);
		else
			++it;
	}

	int err = write_all(entries);
	unlock_fd(fd);
	return err;
}

std::vector<std::pair<std::string, std::string>> PinRegistry::list()
{
	std::lock_guard<std::mutex> lock(s_mutex);

	int fd = lock_fd();
	if (fd < 0) return {};

	auto entries = read_all();
	unlock_fd(fd);
	return entries;
}

std::vector<std::pair<std::string, std::string>> PinRegistry::read_all()
{
	std::vector<std::pair<std::string, std::string>> entries;
	std::ifstream in(REGISTRY_FILE);
	if (!in) return entries;

	std::string line;
	while (std::getline(in, line)) {
		std::istringstream ss(line);
		std::string name, path;
		if (ss >> name >> path)
			entries.push_back({name, path});
	}
	return entries;
}

int PinRegistry::write_all(
	const std::vector<std::pair<std::string, std::string>> &entries)
{
	int fd = open(REGISTRY_FILE, O_WRONLY | O_TRUNC);
	if (fd < 0) return -errno;

	for (const auto &e : entries) {
		std::string line = e.first + " " + e.second + "\n";
		ssize_t n = write(fd, line.c_str(), line.size());
		if (n < 0) { int e = errno; close(fd); return -e; }
	}

	close(fd);
	return 0;
}
