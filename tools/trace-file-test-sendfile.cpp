#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <cerrno>
#include <sys/sendfile.h>

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
		std::cerr << "Failed to open destination file: "
			  << strerror(errno) << std::endl;
		close(src_fd);
		return;
	}

	off_t offset = 0;
	struct stat stat_buf;
	if (fstat(src_fd, &stat_buf) == -1)
	{
		std::cerr << "Failed to get file size: " << strerror(errno)
			  << std::endl;
		close(src_fd);
		close(dst_fd);
		return;
	}

	ssize_t bytes_copied =
		sendfile(dst_fd, src_fd, &offset, stat_buf.st_size);
	if (bytes_copied == -1)
	{
		std::cerr << "Failed to copy file: " << strerror(errno)
			  << std::endl;
	}
	else
	{
		std::cout << "Copied " << bytes_copied << " bytes from "
			  << src_filename << " to " << dst_filename
			  << std::endl;
	}

	close(src_fd);
	close(dst_fd);
}

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		std::cerr << "Usage: " << argv[0]
			  << " <source file> <destination file>" << std::endl;
		return EXIT_FAILURE;
	}

	const char *src_filename = argv[1];
	const char *dst_filename = argv[2];

	copy_file(src_filename, dst_filename);

	return EXIT_SUCCESS;
}