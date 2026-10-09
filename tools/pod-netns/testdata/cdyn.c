/* A dynamically linked child, to show pod-netns needs no loader and behaves
 * the same for libc-linked programs as for the static Go fixture.
 *
 * Prints a stable token on success so the test can assert on it, and lets the
 * bind failure show through on the control run.
 *
 * The success token deliberately comes from bind() rather than from
 * getsockname(). It used to be printed by getsockname, which made the fixture's
 * idea of "bound" depend on a question pod-netns cannot answer in this cage:
 * reporting the bound address means writing into the child's own buffer, and
 * /proc/<pid>/mem is O_RDONLY-only without CAP_SYS_RESOURCE. So the kernel
 * reports the wildcard, the fixture took that as "not bound", and the test
 * failed while the bind was in fact succeeding. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: cdyn PORT\n");
		return 2;
	}
	int port = atoi(argv[1]);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("socket: failed\n");
		return 1;
	}

	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);

	if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) {
		printf("bind: %s\n", strerror(errno));
		return 1;
	}

	struct sockaddr_in got;
	socklen_t gl = sizeof got;
	if (getsockname(fd, (struct sockaddr *)&got, &gl) == 0) {
		/* Informational only. The bind was faked, so the kernel knows of no
		 * bound address and reports the wildcard; that is expected and must
		 * not be treated as a bind failure. */
		printf("getsockname says port %d on %s\n", ntohs(got.sin_port),
		       inet_ntoa(got.sin_addr));
	}
	printf("bind OK\n");
	listen(fd, 4);
	close(fd);
	return 0;
}
