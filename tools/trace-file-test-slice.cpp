#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <sys/stat.h>
#include <sys/types.h>

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

	int pipe_fd[2];
	if (pipe(pipe_fd) == -1)
	{
		std::cerr << "Failed to create pipe: " << strerror(errno)
			  << std::endl;
		close(src_fd);
		close(dst_fd);
		return;
	}

	ssize_t bytes_copied;
	while ((bytes_copied = splice(src_fd, nullptr, pipe_fd[1], nullptr,
				      4096, 0)) > 0)
	{
		if (splice(pipe_fd[0], nullptr, dst_fd, nullptr, bytes_copied,
			   0) == -1)
		{
			std::cerr << "Failed to splice to destination file: "
				  << strerror(errno) << std::endl;
			close(src_fd);
			close(dst_fd);
			close(pipe_fd[0]);
			close(pipe_fd[1]);
			return;
		}
	}

	if (bytes_copied == -1)
	{
		std::cerr << "Failed to splice from source file: "
			  << strerror(errno) << std::endl;
	}
	else
	{
		std::cout << "File copied successfully from " << src_filename
			  << " to " << dst_filename << std::endl;
	}

	close(src_fd);
	close(dst_fd);
	close(pipe_fd[0]);
	close(pipe_fd[1]);
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