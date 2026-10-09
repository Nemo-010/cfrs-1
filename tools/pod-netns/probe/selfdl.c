/* A process whose own `connect` notifies never returns from it.
 *
 * This is why pod-netns installs the seccomp filter into the CHILD, from a
 * pre-exec hook, rather than into the supervisor.
 *
 * A seccomp filter installed in the supervisor is in scope for every thread the
 * tool creates. The supervisor makes its own socket calls: it dials the upstream,
 * and the backing AF_UNIX listener for --listen. Those calls then raise
 * notifications, and the only listener is the supervisor thread that is itself
 * blocked inside the call. Nothing can answer it, so the tool deadlocks with the
 * child frozen inside its own connect(). Passing the notification through does
 * not help, because a thread blocked in a syscall cannot reach its own listener.
 *
 * The fix is structural: install into the child, then hand the listener back over
 * SCM_RIGHTS. The supervisor's threads are never filtered and can dial freely.
 *
 * The probe shows the failure directly. A single thread, no threads to lose
 * track of, installs a filter that notifies on connect() and then calls connect()
 * with nobody servicing the listener. If this program hangs, the deadlock is
 * real and unavoidable, and any design that dials from the notifying thread is
 * wrong.
 *
 * Build: cc -O1 -o selfdl selfdl.c
 * Run:   timeout 10 ./selfdl          # exits 124 if it self-deadlocks
 */

#define _GNU_SOURCE
#include <stdio.h>
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
#include <sys/un.h>
#include <sys/wait.h>
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

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *path = argc > 1 ? argv[1] : "/tmp/pod-netns-selfdl.sock";

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		say("NNP: %s", strerror(errno));
		return 1;
	}
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)__NR_connect, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog p = { .len = 4, .filter = f };
	int lfd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			  SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
	if (lfd < 0) {
		say("install: %s", strerror(errno));
		return 1;
	}
	say("filter installed: this process's own connect() will notify");

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	say("socket -> %d (socket() is NOT in the filter, so it passed through)", fd);

	struct sockaddr_un a;
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	strncpy(a.sun_path, path, sizeof(a.sun_path) - 1);

	say("calling connect() now. Nobody is servicing the listener, and the only");
	say("listener is this thread, which is about to block. Expect a hang.");
	errno = 0;
	int r = connect(fd, (struct sockaddr *)&a, sizeof a);
	say("connect -> %d (%s)", r, r == 0 ? "ok" : strerror(errno));
	say("if this line printed, the self-deadlock did NOT happen and the reason");
	say("pod-netns installs into the child is something else.");
	return 0;
}