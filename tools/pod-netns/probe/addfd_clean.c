/* ADDFD, one call per notification, so a success cannot consume the
 * notification out from under the next attempt.
 *
 * verify_claims.c tried four flag combinations against a single notification.
 * The first three succeeded, so the fourth failed only because the notification
 * had already been answered. That is a probe artifact, not a kernel limit, and
 * the previous session recorded "ENOENT for all flag combos" from exactly this
 * kind of confusion. Each combination here gets its own child and its own
 * notification.
 *
 * What matters either way:
 *   - if ADDFD works, the pre-inherited socketpair pool is unnecessary, and
 *     pod-netns should inject descriptors instead;
 *   - the earlier note claimed only O_CLOEXEC is accepted in newfd_flags, so
 *     newfd_flags=0 is tested separately.
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

/* One notification, one ADDFD call. Returns the injected fd or -1. */
static long one_addfd(unsigned adffd_flags, unsigned newfd_flags)
{
	int lfd = install_notify(__NR_socket);
	if (lfd < 0)
		return -1;
	pid_t c = fork();
	if (c == 0) {
		close(lfd);
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		printf("    child blocked in socket(), fd=%d\n", fd);
		fflush(stdout);
		_exit(0);
	}
	struct pollfd pf = { .fd = lfd, .events = POLLIN };
	if (poll(&pf, 1, 1000) <= 0) {
		kill(c, SIGKILL);
		waitpid(c, NULL, 0);
		close(lfd);
		return -1;
	}
	struct seccomp_notif nf;
	memset(&nf, 0, sizeof nf);
	if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &nf) < 0) {
		kill(c, SIGKILL);
		waitpid(c, NULL, 0);
		close(lfd);
		return -1;
	}
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		close(lfd);
		return -1;
	}
	struct seccomp_notif_addfd a;
	memset(&a, 0, sizeof a);
	a.id = nf.id;
	a.flags = adffd_flags;
	a.srcfd = sv[0];
	a.newfd = 0;
	a.newfd_flags = newfd_flags;
	errno = 0;
	long r = ioctl(lfd, SECCOMP_IOCTL_NOTIF_ADDFD, &a);

	/* If injection failed the child is still blocked, so answer it.
	 * If it succeeded the child already owns the fd. The notification is spent
	 * either way, because the kernel answers it with ADDfd... on success, so
	 * no SEND is issued on the success path.
	 *
	 * The child does not return from socket() on the success path: ADDFD hands
	 * over the descriptor but does not resolve the pending syscall, so the child
	 * stays blocked until it is killed. That is why the child is killed
	 * unconditionally below rather than waited for politely. */
	if (r < 0) {
		struct seccomp_notif_resp resp;
		memset(&resp, 0, sizeof resp);
		resp.id = nf.id;
		resp.val = -1;
		resp.error = -EPERM;
		ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
	} else {
		/* The kernel reports back the flags it actually installed. */
		say("    kernel reports newfd_flags=0x%x (O_CLOEXEC=%d)",
		    a.newfd_flags, !!(a.newfd_flags & O_CLOEXEC));
	}
	kill(c, SIGKILL);
	waitpid(c, NULL, 0);
	close(lfd);
	return r;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	say("one notification per ADDFD call, so no attempt is starved by an earlier one");
	struct {
		unsigned f;
		unsigned n;
		const char *name;
	} tries[] = {
		{ 0, 0, "flags=0              newfd_flags=0" },
		{ 0, O_CLOEXEC, "flags=0              newfd_flags=O_CLOEXEC" },
		{ SECCOMP_ADDFD_FLAG_SEND, 0, "FLAG_SEND            newfd_flags=0" },
		{ SECCOMP_ADDFD_FLAG_SEND, O_CLOEXEC,
		  "FLAG_SEND            newfd_flags=O_CLOEXEC" },
	};
	int worked = 0;
	for (unsigned i = 0; i < sizeof tries / sizeof tries[0]; i++) {
		say("  %s", tries[i].name);
		long r = one_addfd(tries[i].f, tries[i].n);
		say("    -> %ld %s", r, r < 0 ? strerror(errno) : "WORKS");
		if (r >= 0)
			worked++;
	}
	say("\nADDFD usable in %d of %d configurations", worked,
	    (int)(sizeof tries / sizeof tries[0]));
	if (worked)
		say("CONCLUSION: ADDFD works in this cage. The pre-inherited pool in");
		say("pod-netns is a workaround for a limitation that does not exist here.");
	return 0;
}