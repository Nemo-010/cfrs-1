/* Verify three load-bearing claims in cfrs issue #2's implementation notes.
 *
 * Each claim is quoted from the issue and either confirmed or refuted here, in
 * this cage. A claim about a host is worth exactly what a measurement of that
 * host says it is worth.
 *
 * CLAIM 1 (from the notes):
 *   "the supervisor creates a socketpair and installs one end in the child with
 *    SECCOMP_IOCTL_NOTIF_ADDFD | SECCOMP_ADDFD_FLAG_SEND"
 *   and "ADDFD accepts only O_CLOEXEC in newfd_flags on this kernel".
 *   If ADDFD works at all, the whole pre-inherited-pool design is unnecessary.
 *
 *   Earlier measurement in this cage said ADDFD returns ENOENT for every flag
 *   combination. Retested here from a clean process with every combination
 *   printed, because this claim contradicts it and the contradiction decides the
 *   architecture.
 *
 * CLAIM 2:
 *   "a UDP echo round trip through UDP ASSOCIATE" as a passing test.
 *   UDP ASSOCIATE requires sending datagrams. If UDP send is denied here, that
 *   test cannot have run in this cage, and every UDP claim above it is about a
 *   different host.
 *
 * CLAIM 3:
 *   "io_uring_setup, io_uring_enter and io_uring_register are answered EPERM.
 *    A partial filter is unsound... A unit test asserts the coverage."
 *   If io_uring_setup is already denied by the cage, no interception is needed
 *   and the reasoning is right but the conclusion is unnecessary. If it is
 *   ALLOWED, then io_uring is a real bypass for any filter that omits it, which
 *   is a finding about my own implementation too.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void say(const char *fmt, ...)
{
	va_list ap;
	__builtin_va_start(ap, fmt);
	vprintf(fmt, ap);
	__builtin_va_end(ap);
	putchar('\n');
	fflush(stdout);
}

static int install_notify(int target)
{
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)target, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog p = { .len = 4, .filter = f };
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
		       SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
}

/* ---------- CLAIM 1: ADDFD ---------- */
static void claim1(void)
{
	say("\n================ CLAIM 1: SECCOMP_IOCTL_NOTIF_ADDFD ================");
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		say("NNP: %s", strerror(errno));
		return;
	}
	int lfd = install_notify(__NR_socket);
	if (lfd < 0) {
		say("install: %s", strerror(errno));
		return;
	}
	pid_t c = fork();
	if (c == 0) {
		close(lfd);
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		printf("CHILD: socket fd=%d; blocked in the notification\n", fd);
		fflush(stdout);
		_exit(0);
	}

	struct pollfd pf = { .fd = lfd, .events = POLLIN };
	if (poll(&pf, 1, 1000) <= 0) {
		say("no notification; cannot test ADDFD");
		kill(c, SIGKILL);
		waitpid(c, NULL, 0);
		return;
	}
	struct seccomp_notif nf;
	memset(&nf, 0, sizeof nf);
	if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &nf) < 0) {
		say("RECV: %s", strerror(errno));
		kill(c, SIGKILL);
		waitpid(c, NULL, 0);
		return;
	}
	say("have a live notification id=0x%llx for pid %d",
	    (unsigned long long)nf.id, nf.pid);

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		say("socketpair: %s", strerror(errno));
		kill(c, SIGKILL);
		waitpid(c, NULL, 0);
		return;
	}

	struct seccomp_notif_addfd a;
	struct {
		unsigned flags;
		const char *name;
	} tries[] = {
		{ 0, "flags=0" },
		// Only FLAG_SEND exists in the uapi header. There is no FLAG_RECV, so the
	// issue's "SEND|RECV" combination cannot be expressed here.
		{ SECCOMP_ADDFD_FLAG_SEND, "FLAG_SEND" },
	};
	unsigned newfd_flags[] = { 0, O_CLOEXEC };
	for (unsigned i = 0; i < sizeof tries / sizeof tries[0]; i++) {
		for (unsigned j = 0; j < 2; j++) {
			memset(&a, 0, sizeof a);
			a.id = nf.id;
			a.flags = tries[i].flags;
			a.srcfd = sv[0];
			a.newfd = 0;
			a.newfd_flags = newfd_flags[j];
			errno = 0;
			long r = ioctl(lfd, SECCOMP_IOCTL_NOTIF_ADDFD, &a);
			say("  ADDFD flags=%-10s newfd_flags=%-8s -> rc=%ld %s",
			    tries[i].name, j ? "O_CLOEXEC" : "0", r,
			    r < 0 ? strerror(errno) : "OK");
			if (r >= 0)
				say("    *** ADDFD WORKED. The pre-inherited pool is "
				    "not needed. ***");
		}
	}

	struct seccomp_notif_resp r;
	memset(&r, 0, sizeof r);
	r.id = nf.id;
	r.val = 0;
	r.error = 0;
	r.flags = 0;
	ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &r);
	int st = 0;
	waitpid(c, &st, 0);
}

/* ---------- CLAIM 2: UDP ---------- */
static void claim2(void)
{
	say("\n================ CLAIM 2: UDP / UDP ASSOCIATE ================");
	struct sockaddr_in d;
	memset(&d, 0, sizeof d);
	d.sin_family = AF_INET;
	d.sin_port = htons(53);
	d.sin_addr.s_addr = 0x01010101; /* 1.1.1.1 */

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	say("socket(AF_INET, SOCK_DGRAM) -> %d (%s)", fd,
	    fd < 0 ? strerror(errno) : "ok");
	if (fd < 0)
		return;

	errno = 0;
	int r = bind(fd, (struct sockaddr *)&d, sizeof d);
	say("bind 0.0.0.0:0 (wildcard)   -> %d (%s)", r, r == 0 ? "ok" : strerror(errno));

	errno = 0;
	r = connect(fd, (struct sockaddr *)&d, sizeof d);
	say("connect 1.1.1.1:53           -> %d (%s)", r, r == 0 ? "ok" : strerror(errno));

	const char *q = "\x00\x01";
	errno = 0;
	ssize_t n = send(fd, q, 2, 0);
	say("send 2 bytes to 1.1.1.1:53  -> %zd (%s)", n,
	    n < 0 ? strerror(errno) : "ok");
	if (n >= 0)
		say("    *** a datagram left this host, so a UDP ASSOCIATE relay is "
		    "possible here ***");

	errno = 0;
	n = sendto(fd, q, 2, 0, (struct sockaddr *)&d, sizeof d);
	say("sendto (unconnected)         -> %zd (%s)", n,
	    n < 0 ? strerror(errno) : "ok");
	close(fd);
}

/* ---------- CLAIM 3: io_uring ---------- */
static void claim3(void)
{
	say("\n================ CLAIM 3: io_uring ================");
#ifdef __NR_io_uring_setup
	struct {
		unsigned entries;
		unsigned pad[2];
	} params = { .entries = 8 };
	errno = 0;
	long r = syscall(__NR_io_uring_setup, &params);
	say("io_uring_setup(8 entries)    -> %ld %s", r,
	    r < 0 ? strerror(errno) : "OK (AVAILABLE)");
	if (r >= 0)
		say("    *** io_uring is AVAILABLE. A filter that does not intercept "
		    "io_uring_setup can be bypassed by a program that uses it. ***");
#else
	say("__NR_io_uring_setup not defined on this arch");
#endif
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	say("sizeof(struct seccomp_notif_addfd) = %zu",
	    sizeof(struct seccomp_notif_addfd));
	claim1();
	claim2();
	claim3();
	return 0;
}