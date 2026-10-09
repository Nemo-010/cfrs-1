/* Which field of `seccomp_notif` does the kernel validate, and how many
 * notifications does one listener actually serve?
 *
 * Both questions were answered wrongly before, from probe bugs, and both wrong
 * answers shaped the design.
 *
 * Q1. THE STRUCT MUST BE ZEROED ON EVERY RECV. The kernel rejects a
 *     `seccomp_notif` with any field set, and the EINVAL it returns is
 *     indistinguishable from a listener with nothing pending. A probe that
 *     declares the struct once and reuses it therefore sees ONE good
 *     notification followed by EINVAL forever, and concludes the listener is
 *     spent. Each field below is set individually to show that every one of them
 *     does it, and that an all-zero struct succeeds.
 *
 * Q2. THE CEILING. Once the struct is re-zeroed each time, how many
 *     notifications does one listener serve? Answer: all of them. The child
 *     below makes `calls` binds and each returns its own distinct faked value,
 *     so every one is a real interception rather than a pass-through.
 *
 * Build: cc -O1 -o multin multin.c
 * Run:   ./multin q1     the field-by-field table
 *        ./multin q2 [calls] [gap_us]   N binds, counting notifications served
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h>
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

static long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
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

static void child_bind(int calls, int gap_us)
{
	for (int k = 0; k < calls; k++) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in a;
		memset(&a, 0, sizeof a);
		a.sin_family = AF_INET;
		a.sin_port = htons((uint16_t)(24000 + k));
		a.sin_addr.s_addr = 0x7f000001;
		say("  child: bind #%d", k);
		fflush(stdout);
		int r = bind(fd, (struct sockaddr *)&a, sizeof a);
		say("  child: bind #%d -> %d (%s)", k, r,
		    r == 0 ? "ok" : strerror(errno));
		if (fd >= 0)
			close(fd);
		if (gap_us > 0)
			usleep((useconds_t)gap_us);
	}
	_exit(0);
}

/* ---------- Q1 ---------- */
static void q1(void)
{
	say("\n============ Q1: which field does the kernel validate? ============");
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		say("NNP: %s", strerror(errno));
		return;
	}
	int lfd = install_notify(__NR_bind);
	if (lfd < 0) {
		say("install: %s", strerror(errno));
		return;
	}
	pid_t p = fork();
	if (p == 0) {
		close(lfd);
		child_bind(1, 0);
	}
	usleep(200000);
	struct pollfd pf = { .fd = lfd, .events = POLLIN };
	say("poll revents=0x%x", (poll(&pf, 1, 500) > 0) ? pf.revents : 0);

	/* Non-zero patterns first: each either fails, which keeps the notification
	 * queued, or succeeds, which consumes it. The pattern that must work is
	 * therefore tried last. */
	struct {
		const char *name;
		size_t off;
		unsigned long long val;
		int width;
	} pats[] = {
		{ "id=1", offsetof(struct seccomp_notif, id), 1ULL, 8 },
		{ "pid=1", offsetof(struct seccomp_notif, pid), 1ULL, 4 },
		{ "flags=1", offsetof(struct seccomp_notif, flags), 1ULL, 4 },
		{ "data.nr=49", offsetof(struct seccomp_notif, data), 49ULL, 4 },
		{ "byte at off 16", 16, 1ULL, 4 },
		{ "byte at off 20", 20, 1ULL, 4 },
		{ "byte at off 24", 24, 1ULL, 4 },
	};
	for (unsigned i = 0; i < sizeof pats / sizeof pats[0]; i++) {
		struct seccomp_notif nf;
		memset(&nf, 0, sizeof nf);
		memcpy((char *)&nf + pats[i].off, &pats[i].val, pats[i].width);
		errno = 0;
		int rc = ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &nf);
		say("  %-16s -> %s", pats[i].name,
		    rc == 0 ? "SUCCESS (consumed)" : strerror(errno));
		if (rc == 0)
			break;
	}
	{
		struct seccomp_notif nf;
		memset(&nf, 0, sizeof nf);
		errno = 0;
		int rc = ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &nf);
		say("  %-16s -> %s", "all zeros", rc == 0 ? "SUCCESS" : strerror(errno));
		if (rc == 0) {
			struct seccomp_notif_resp r;
			memset(&r, 0, sizeof r);
			r.id = nf.id;
			r.val = 1;
			ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &r);
			say("    notif.id=0x%llx pid=%d", (unsigned long long)nf.id, nf.pid);
		}
	}
	kill(p, SIGKILL);
	waitpid(p, NULL, 0);
}

/* ---------- Q2 ---------- */
static void q2(int calls, int gap_us)
{
	say("\n============ Q2: notifications served by one listener ============");
	say("  child will bind %d times, %d us apart; every RECV from a fresh zeroed struct",
	    calls, gap_us);
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		say("NNP: %s", strerror(errno));
		return;
	}
	int lfd = install_notify(__NR_bind);
	if (lfd < 0) {
		say("install: %s", strerror(errno));
		return;
	}
	pid_t p = fork();
	if (p == 0) {
		close(lfd);
		child_bind(calls, gap_us);
	}

	int served = 0, einval = 0, other = 0;
	long stop = now_ms() + 10000;
	while (now_ms() < stop) {
		struct pollfd pf = { .fd = lfd, .events = POLLIN };
		if (poll(&pf, 1, 1000) <= 0)
			break;
		struct seccomp_notif nf;
		/* Fresh every call: the fix, and the reason Q1 matters. */
		memset(&nf, 0, sizeof nf);
		errno = 0;
		if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &nf) < 0) {
			if (errno == EINVAL) {
				if (++einval <= 2)
					say("  RECV EINVAL");
				usleep(2000);
				continue;
			}
			say("  RECV: %s", strerror(errno));
			other++;
			break;
		}
		struct seccomp_notif_resp r;
		memset(&r, 0, sizeof r);
		r.id = nf.id;
		r.val = 5000 + served;
		r.error = 0;
		r.flags = 0;
		errno = 0;
		if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &r) < 0) {
			say("  SEND: %s", strerror(errno));
			break;
		}
		say("  served notification %d (id=0x%llx)", ++served,
		    (unsigned long long)nf.id);
		usleep(500);
	}
	int st = 0;
	waitpid(p, &st, 0);
	say("RESULT issued=%d served=%d einval=%d other=%d child=%s", calls, served,
	    einval, other, WIFEXITED(st) ? "exited" : "hung");
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 1 && !strcmp(argv[1], "q1")) {
		q1();
		return 0;
	}
	/* Accepts "q2 [calls] [gap_us]" and bare "[calls] [gap_us]", so the usage
	 * line in the header is true either way. A bare `q2` used to be parsed as
	 * calls=0, because atoi("q2") is 0, and the probe then reported a
	 * meaningless "issued=0 served=0" instead of refusing. */
	int argi = 1;
	if (argc > 1 && !strcmp(argv[1], "q2"))
		argi = 2;
	int calls = argc > argi ? atoi(argv[argi]) : 64;
	if (calls < 1) {
		fprintf(stderr, "calls must be positive, got %s\n",
			argc > argi ? argv[argi] : "(nothing)");
		return 2;
	}
	int gap = argc > argi + 1 ? atoi(argv[argi + 1]) : 0;
	q2(calls, gap);
	return 0;
}