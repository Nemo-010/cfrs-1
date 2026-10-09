/* Does pod-netns break a program's DNS?
 *
 * The child's fd is an AF_UNIX socketpair, so the kernel returns EOPNOTSUPP for
 * every IP-level setsockopt. Passing those through looks harmless and is not:
 * glibc's resolver sets options like IPV6_V6ONLY and ABORTS when one fails, so
 * every glibc program under pod-netns would fail to resolve anything, with the
 * failure surfacing as a name-resolution error rather than as anything to do with
 * a proxy.
 *
 * This is the fixture for the integration test
 * `setsockopt_on_a_claimed_socket_succeeds`, which asserts that both options
 * return 0 under pod-netns, matching the bare control. getaddrinfo() is probed
 * too, but its result reflects this host's resolver rather than the proxy, so it
 * is informational and the test does not assert on it.
 *
 * Build: cc -O1 -o testdata/dnsfix testdata/dnsfix.c
 */

#define _GNU_SOURCE
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Column widths are fixed so a test can match a whole line. The values must be
 * printed with %d rather than as a bool, because the distinction between 0 and
 * -1 is the entire point. */
int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	printf("socket -> %d\n", fd);
	if (fd < 0) {
		printf("socket: %s\n", strerror(errno));
		return 1;
	}

	int on = 0;
	int r = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
	printf("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0) -> %d (%s)\n",
	       r, r == 0 ? "ok" : strerror(errno));

	r = setsockopt(fd, IPPROTO_IP, IP_TOS, &on, sizeof on);
	printf("setsockopt(IPPROTO_IP, IP_TOS, 0)        -> %d (%s)\n",
	       r, r == 0 ? "ok" : strerror(errno));
	close(fd);

	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	int rc = getaddrinfo("example.com", "80", &hints, &res);
	printf("getaddrinfo(example.com) -> %d (%s)\n", rc,
	       rc == 0 ? "ok" : gai_strerror(rc));
	if (rc == 0 && res) {
		char buf[128] = {0};
		getnameinfo(res->ai_addr, res->ai_addrlen, buf, sizeof buf, NULL, 0,
			    NI_NUMERICHOST);
		printf("  resolved to %s\n", buf);
		freeaddrinfo(res);
	}
	return 0;
}