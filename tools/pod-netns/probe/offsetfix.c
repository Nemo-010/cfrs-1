/* The BPF miss offset, measured rather than reasoned about.
 *
 * pod-netns builds one comparison per target syscall, then a RET USER_NOTIF and a
 * RET ALLOW. For the j-th of n comparisons, sitting at f[j]:
 *
 *   match -> f[n+1] (RET USER_NOTIF)   jt = n - j
 *   miss  -> f[j+1] (next comparison)  jf = 0
 *   miss  -> f[n+2] (RET ALLOW)        jf = 1, on the LAST comparison only
 *
 * An earlier version used `jf = n - j + 1`, which is not "a miss goes to ALLOW":
 * it skips every remaining comparison and lands on ALLOW. The effect is silent
 * and narrow, which is what made it survive: only TARGETS[0] is ever intercepted,
 * and every other target in the list is dead code. It survived in the tests
 * because every fixture binds first, so the working path and the broken path were
 * the same path.
 *
 * Reading the offsets is exactly how that bug got introduced twice, so this
 * measures. It runs every syscall at every position of every chain length and
 * reports what actually notified. Each cell is its own process, because only one
 * USER_NOTIF listener is allowed per task.
 *
 * Build: cc -O1 -o offsetfix offsetfix.c
 * Run:   ./offsetfix old    expect 8 of 36 cells, a clean position-0 diagonal
 *        ./offsetfix new    expect 36 of 36
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
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

/* A pool of real network syscalls, so a chain of any length can be built and
 * every entry is one the child can actually be made to issue. */
static const int POOL[] = {
	__NR_bind, __NR_listen, __NR_getsockname, __NR_connect,
	__NR_getpeername, __NR_setsockopt, __NR_getsockopt, __NR_recvfrom
};
#define POOL_N ((int)(sizeof POOL / sizeof POOL[0]))

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

static const char *nm(int nr)
{
	switch (nr) {
	case __NR_bind: return "bind";
	case __NR_listen: return "listen";
	case __NR_getsockname: return "getsockname";
	case __NR_connect: return "connect";
	case __NR_getpeername: return "getpeername";
	case __NR_setsockopt: return "setsockopt";
	case __NR_getsockopt: return "getsockopt";
	default: return "recvfrom";
	}
}

/* variant 0 reproduces the shipped bug; variant 1 is the correct builder. */
static int install(int *chain, int n, int variant)
{
	struct sock_filter f[64];
	int i = 0;
	f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					      offsetof(struct seccomp_data, nr));
	for (int j = 1; j <= n; j++) {
		unsigned char jf = (variant == 0) ? (unsigned char)(n - j + 1)
						 : (j == n ? 1 : 0);
		f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						      (unsigned)chain[j - 1],
						      (unsigned char)(n - j), jf);
	}
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	struct sock_fprog p = { .len = (unsigned short)i, .filter = f };
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
		       SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
}

static void child_call(int pos)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a, got;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons(26006);
	a.sin_addr.s_addr = 0x7f000001;
	socklen_t gl = sizeof got;
	int one = 1;
	char buf[64];

	switch (pos) {
	case 0: bind(fd, (struct sockaddr *)&a, sizeof a); break;
	case 1: listen(fd, 4); break;
	case 2: getsockname(fd, (struct sockaddr *)&got, &gl); break;
	case 3: connect(fd, (struct sockaddr *)&a, sizeof a); break;
	case 4: getpeername(fd, (struct sockaddr *)&got, &gl); break;
	case 5: setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one); break;
	case 6: getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, &gl); break;
	default: recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&got, &gl); break;
	}
	_exit(0);
}

/* One cell, in its own process. Returns 1 if the wanted syscall notified. */
static int cell(int n, int pos, int variant)
{
	int chain[8];
	for (int k = 0; k < n; k++)
		chain[k] = POOL[k];
	int want = POOL[pos];

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		return 0;
	int lfd = install(chain, n, variant);
	if (lfd < 0)
		return 0;
	pid_t c = fork();
	if (c == 0) {
		close(lfd);
		child_call(pos);
	}
	int got = 0;
	for (int k = 0; k < 3; k++) {
		struct pollfd pf = { .fd = lfd, .events = POLLIN };
		if (poll(&pf, 1, 400) <= 0)
			break;
		struct seccomp_notif nf;
		/* Zeroed FRESH every call. The kernel rejects a struct with any field
		 * set, and EINVAL is indistinguishable from a spent listener, so a
		 * reused struct would manufacture a fake ceiling of one notification. */
		memset(&nf, 0, sizeof nf);
		errno = 0;
		if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &nf) < 0)
			break;
		if ((int)nf.data.nr == want)
			got = 1;
		struct seccomp_notif_resp r;
		memset(&r, 0, sizeof r);
		r.id = nf.id;
		r.val = 0;
		r.error = 0;
		r.flags = 0;
		ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &r);
	}
	int st = 0;
	waitpid(c, &st, 0);
	return got;
}

static void matrix(int variant)
{
	say("\n===== %s =====", variant == 0
		? "OLD: jf = n-j+1 (the shipped bug)"
		: "NEW: jf = 0, except 1 on the last comparison");
	printf("n\\p  ");
	for (int p = 0; p < POOL_N; p++)
		printf("%-12s", nm(POOL[p]));
	printf("\n");
	int total = 0, fired = 0;
	for (int n = 1; n <= POOL_N; n++) {
		printf("%-5d ", n);
		for (int p = 0; p < n; p++) {
			pid_t c = fork();
			if (c == 0)
				_exit(cell(n, p, variant) ? 0 : 1);
			int st = 0;
			waitpid(c, &st, 0);
			int r = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
			total++;
			if (r == 0)
				fired++;
			printf("%-12s", r == 0 ? "NOTIFY" : "----");
			fflush(stdout);
		}
		printf("\n");
	}
	say("TOTAL notified %d of %d cells", fired, total);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 1 && argv[1][0] == 'o')
		matrix(0);
	else if (argc > 1 && argv[1][0] == 'm')
		matrix(1); /* the first fix attempt, jf = 1 everywhere */
	else
		matrix(1);
	return 0;
}