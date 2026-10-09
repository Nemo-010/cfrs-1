/* An inbound client for the --listen path: connects to the virtual address and
 * sends a request. Used to prove a connection queued on the backing AF_UNIX
 * socket is actually delivered to a child's accept().
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: iclient PORT\n");
		return 2;
	}
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	printf("client socket fd=%d\n", fd);
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)atoi(argv[1]));
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);

	struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

	int r = connect(fd, (struct sockaddr *)&a, sizeof a);
	printf("client connect -> %d (%s)\n", r, r == 0 ? "ok" : strerror(errno));
	if (r != 0)
		return 1;
	const char *msg = "GET /inbound HTTP/1.0\r\nHost: x\r\n\r\n";
	ssize_t n = write(fd, msg, strlen(msg));
	printf("client wrote %zd\n", n);
	char buf[256];
	ssize_t got = read(fd, buf, sizeof buf - 1);
	if (got > 0) {
		buf[got] = '\0';
		char *nl = strchr(buf, '\n');
		if (nl)
			*nl = '\0';
		printf("client got: %s\n", buf);
	} else {
		printf("client read %zd (%s)\n", got, strerror(errno));
	}
	close(fd);
	return 0;
}