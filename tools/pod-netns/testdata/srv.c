/* A TCP-ish server fixture for --listen, using plain syscalls.
 *
 * It binds an address the cage refuses, then listens, then accepts once and
 * reports what the peer sent. That exercises the whole inbound path: the faked
 * bind, the listen, and the accept handing back a real connected descriptor.
 *
 * `accept` here is non-blocking by polling, because pod-netns answers EAGAIN
 * when nothing is queued. A server that blocked in accept() would spin against a
 * poll loop instead of hanging, which is what a non-blocking listener does
 * anyway.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: srv PORT\n");
		return 2;
	}
	int port = atoi(argv[1]);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	printf("socket fd=%d\n", fd);

	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);

	if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) {
		printf("bind: %s\n", strerror(errno));
		return 1;
	}
	printf("bind ok\n");

	if (listen(fd, 4) < 0) {
		printf("listen: %s\n", strerror(errno));
		return 1;
	}
	printf("listen ok\n");

	struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

	int c = -1;
	for (int i = 0; i < 150 && c < 0; i++) {
		c = accept(fd, NULL, NULL);
		if (c < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			usleep(100000);
		else if (c < 0 && (errno == EINTR))
			continue;
		else
			break;
	}
	if (c < 0) {
		printf("accept: %s\n", strerror(errno));
		return 1;
	}
	printf("accept ok fd=%d\n", c);

	char buf[256];
	memset(buf, 0, sizeof buf);
	ssize_t n = read(c, buf, sizeof buf - 1);
	printf("read %zd\n", n);
	if (n > 0) {
		buf[n] = '\0';
		char *nl = strchr(buf, '\n');
		if (nl)
			*nl = '\0';
		printf("peer said: %s\n", buf);
	}
	close(c);
	close(fd);
	return 0;
}