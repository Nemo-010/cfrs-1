/* An AF_UNIX client, to prove pod-netns passes non-INET sockets through.
 *
 * The relay can only carry AF_INET/SOCK_STREAM, because the pool is a set of
 * socketpairs and a datagram or unix socket has no place in it. If pod-netns
 * claimed an AF_UNIX socket it would hand the child a socketpair end where it
 * expected a filesystem socket, and the child's own local IPC would break with
 * nothing in any log to say why.
 *
 * So this connects to a real unix socket named on the command line. Passing it
 * through means the connection succeeds and the server sees the bytes; claiming
 * it means the connection fails.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: ucli PATH\n");
		return 2;
	}
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	printf("socket fd=%d\n", fd);

	struct sockaddr_un a;
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	strncpy(a.sun_path, argv[1], sizeof(a.sun_path) - 1);

	int r = connect(fd, (struct sockaddr *)&a, sizeof a);
	printf("connect -> %d (%s)\n", r, r == 0 ? "ok" : strerror(errno));
	if (r != 0)
		return 1;

	const char *msg = "ping";
	ssize_t n = write(fd, msg, strlen(msg));
	printf("wrote %zd bytes\n", n);
	char buf[16];
	ssize_t got = read(fd, buf, sizeof buf - 1);
	if (got > 0) {
		buf[got] = '\0';
		printf("reply: %s\n", buf);
	}
	close(fd);
	return 0;
}