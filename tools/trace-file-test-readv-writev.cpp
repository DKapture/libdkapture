#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <cstring>
#include <cerrno>

void write_example(const char *filename)
{
	int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd == -1)
	{
		std::cerr << "Failed to open file for writing: "
			  << strerror(errno) << std::endl;
		return;
	}

	const char *buf1 = "Hello, ";
	const char *buf2 = "world!";
	struct iovec iov[2];
	iov[0].iov_base = (void *)buf1;
	iov[0].iov_len = strlen(buf1);
	iov[1].iov_base = (void *)buf2;
	iov[1].iov_len = strlen(buf2);

	ssize_t nwritten = writev(fd, iov, 2);
	if (nwritten == -1)
	{
		std::cerr << "Failed to write to file: " << strerror(errno)
			  << std::endl;
	}
	else
	{
		std::cout << "Wrote " << nwritten << " bytes to file "
			  << filename << std::endl;
	}

	close(fd);
}

void read_example(const char *filename)
{
	int fd = open(filename, O_RDONLY);
	if (fd == -1)
	{
		std::cerr << "Failed to open file for reading: "
			  << strerror(errno) << std::endl;
		return;
	}

	char buf1[8];
	char buf2[8];
	struct iovec iov[2];
	iov[0].iov_base = buf1;
	iov[0].iov_len = sizeof(buf1) - 1;
	iov[1].iov_base = buf2;
	iov[1].iov_len = sizeof(buf2) - 1;

	ssize_t nread = readv(fd, iov, 2);
	if (nread == -1)
	{
		std::cerr << "Failed to read from file: " << strerror(errno)
			  << std::endl;
	}
	else
	{
		buf1[iov[0].iov_len] = '\0';
		buf2[iov[1].iov_len] = '\0';
		std::cout << "Read " << nread << " bytes from file " << filename
			  << std::endl;
		std::cout << "Content: " << buf1 << buf2 << std::endl;
	}

	close(fd);
}

int main(int n, char *args[])
{
	if (n < 2)
	{
		printf("err: please specify a file path\n");
		return -1;
	}
	const char *filename = args[1];

	write_example(filename);
	read_example(filename);

	return 0;
}