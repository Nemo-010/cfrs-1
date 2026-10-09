/* setsockopt on a claimed socket: the difference that breaks a resolver.
 *
 * pod-netns answers the child's `socket(AF_INET, SOCK_STREAM)` with the number of
 * an `AF_UNIX` socketpair end. That descriptor is the right shape for carrying
 * bytes and the wrong shape for everything else: the kernel returns EOPNOTSUPP
 * for every IP-level socket option.
 *
 * That matters more than it looks. glibc's resolver sets options like
 * IPV6_V6ONLY and **aborts** when one fails, so a program whose setsockopt calls
 * reach the kernel would fail to resolve any name at all. The symptom is a
 * name-resolution error, which points at DNS rather than at a proxy, and it
 * appears on every glibc program rather than only on proxied ones.
 *
 * pod-netns answers setsockopt with 0 for a socket it handed out. This probe
 * shows what happens without that, and what the bare answer is, so the test in
 * tests/integration.rs has something to compare against.
 *
 * Build: cc -O1 -o sockopt sockopt.c
 * Run:   ./sockopt bare
 *        ./sockopt sockpair    what the child sees when the option is passed through
 *        ./sockopt faked       what the child sees when the supervisor answers 0
 */

#define _GNU_SOURCE
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/* faked: the supervisor intercepts setsockopt and answers 0. A standalone
 * program cannot install the interception, so this mode prints the answer the
 * supervisor gives rather than observing it. The integration test
 * `setsockopt_on_a_claimed_socket_succeeds` is what actually observes it. */
static void try_option(const char *label, int level, int optname, int fd)
{
	int val = 0;
	errno = 0;
	int r = setsockopt(fd, level, optname, &val, sizeof val);
	/* errno is only meaningful when r < 0, and printing strerror(0) after a
	 * success reads as a failure to anyone skimming the output. */
	printf("  %-34s -> %d (%s)\n", label, r, r == 0 ? "ok" : strerror(errno));
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *mode = argc > 1 ? argv[1] : "bare";

	if (!strcmp(mode, "faked")) {
		printf("mode: the answer the supervisor gives for a claimed socket\n");
		printf("  setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0) -> 0 (ok)\n");
		printf("  setsockopt(IPPROTO_IP, IP_TOS, 0)        -> 0 (ok)\n");
		printf("  a glibc resolver continues past these instead of aborting\n");
		printf("  (observed by the integration test, not by this probe)\n");
		return 0;
	}

	if (!strcmp(mode, "sockpair")) {
		/* Reproduce exactly what the child is handed: an AF_UNIX socketpair
		 * end, with the options passed through to the kernel. */
		int sv[2];
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
			printf("socketpair: %s\n", strerror(errno));
			return 1;
		}
		printf("mode: the child's fd is an AF_UNIX socketpair, options passed through\n");
		try_option("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY)", IPPROTO_IPV6, IPV6_V6ONLY, sv[0]);
		try_option("setsockopt(IPPROTO_IP, IP_TOS)", IPPROTO_IP, IP_TOS, sv[0]);
		close(sv[0]);
		close(sv[1]);
		return 0;
	}

	printf("mode: a real AF_INET socket, no interception (the control)\n");
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("socket: %s\n", strerror(errno));
		return 1;
	}
	/* Note the two rows are NOT equivalent under the three modes, and that is
	 * the point. On a real AF_INET socket, IP_TOS succeeds and IPV6_V6ONLY
	 * fails with EAFNOSUPPORT, because the socket has no IPv6 to restrict. On
	 * the AF_UNIX socketpair the child is handed, BOTH fail, with
	 * EOPNOTSUPP. So the regression a resolver sees is IP_TOS: 0 becomes
	 * EOPNOTSUPP, and glibc's resolver aborts on it. */
	try_option("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY)", IPPROTO_IPV6, IPV6_V6ONLY, fd);
	try_option("setsockopt(IPPROTO_IP, IP_TOS)", IPPROTO_IP, IP_TOS, fd);
	close(fd);

	/* And the thing that actually depends on it. The result here reflects this
	 * host's resolver, not the proxy, so it is informational only: what matters
	 * is that a resolver which sees EOPNOTSUPP aborts rather than falling back. */
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	int rc = getaddrinfo("example.com", "80", &hints, &res);
	printf("  getaddrinfo(example.com) -> %d (%s)\n", rc,
	       rc == 0 ? "ok" : gai_strerror(rc));
	if (rc == 0 && res)
		freeaddrinfo(res);
	return 0;
}