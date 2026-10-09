// Data-path fixture: proves the relay carries bytes in both directions.
//
// The child connects to a virtual AF_INET address that the cage refuses. Under
// pod-netns the connect is faked and the child's socket is a pre-inherited
// socketpair; the supervisor splices it to the AF_UNIX origin named by
// POD_NETNS_ORIGIN. The child sends a request and must receive the origin's
// reply, so this only passes if the relay actually moved bytes.
//
// Without pod-netns the same connect blocks forever in this cage, which is why
// every test using this fixture carries a timeout.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: relayer PORT\n");
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

	int r = connect(fd, (struct sockaddr *)&a, sizeof a);
	printf("connect -> %d (%s)\n", r, r == 0 ? "ok" : strerror(errno));
	if (r != 0)
		return 1;

	struct timeval tv = { .tv_sec = 20, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

	const char *req = "GET / HTTP/1.0\r\nHost: origin\r\n\r\n";
	ssize_t n = write(fd, req, strlen(req));
	printf("wrote %zd bytes\n", n);
	if (n < 0) {
		printf("write: %s\n", strerror(errno));
		return 1;
	}

	char buf[4096];
	ssize_t got = read(fd, buf, sizeof buf - 1);
	if (got <= 0) {
		printf("read %zd (%s): the relay carried nothing back\n", got,
		       strerror(errno));
		return 1;
	}
	buf[got] = '\0';
	if (strstr(buf, "HELLO")) {
		printf("got reply with HELLO\n");
	} else {
		char *nl = strchr(buf, '\n');
		if (nl)
			*nl = '\0';
		printf("first line: %s\n", buf);
	}
	printf("read %zd bytes\n", got);
	close(fd);
	return 0;
}