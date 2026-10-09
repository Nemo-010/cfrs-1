/* Can a supervisor write the child's memory? No.
 *
 * This decides whether `getsockname` can be answered with the address the child
 * asked for. Answering it means writing a sockaddr into the child's own buffer,
 * and there is no route to that buffer in this cage:
 *
 *   open(/proc/<pid>/mem, O_RDONLY)   ok
 *   open(/proc/<pid>/mem, O_WRONLY)   EACCES
 *   open(/proc/<pid>/mem, O_RDWR)     EACCES
 *   process_vm_writev                 EPERM
 *   ptrace(PTRACE_ATTACH)             EPERM
 *
 * The kernel gates the write path on CAP_SYS_RESOURCE and CapEff is 0 here.
 * Reading is allowed, so a supervisor CAN recover the sockaddr the child is
 * trying to bind, which is what makes a transparent bind possible at all. It
 * just cannot put one back.
 *
 * An earlier note in this crate claimed the file was "readable and writable".
 * That came from a probe that opened the file and never wrote through it, which
 * is the specific failure this probe exists to prevent repeating.
 *
 * Build: cc -O1 -o memrw memrw.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

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

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	/* A child that stays alive, so its /proc entries are real and its address
	 * space is stable while the parent probes it. */
	pid_t p = fork();
	if (p == 0) {
		static char bss[4096];
		bss[0] = 'B';
		fprintf(stderr, "CHILD bss=%p\n", (void *)bss);
		fflush(stderr);
		sleep(30);
		_exit(0);
	}
	usleep(300000);

	char path[64];
	snprintf(path, sizeof path, "/proc/%d/mem", p);

	say("/proc/<pid>/mem by access mode:");
	const struct {
		int flag;
		const char *name;
	} modes[] = {
		{ O_RDONLY, "O_RDONLY " },
		{ O_WRONLY, "O_WRONLY " },
		{ O_RDWR, "O_RDWR   " },
	};
	for (unsigned i = 0; i < 3; i++) {
		errno = 0;
		int fd = open(path, modes[i].flag);
		say("  open(%s) -> %2d  %s", modes[i].name, fd,
		    fd < 0 ? strerror(errno) : "OK");
		if (fd >= 0)
			close(fd);
	}

	say("\nthe two alternative routes into the child's memory:");
	errno = 0;
	long w = process_vm_writev(p, &(struct iovec){ .iov_base = NULL, .iov_len = 0 }, 1,
				   &(struct iovec){ .iov_base = NULL, .iov_len = 0 }, 1, 0);
	say("  process_vm_writev      -> %ld  %s", w, w < 0 ? strerror(errno) : "OK");

	errno = 0;
	long t = ptrace(PTRACE_ATTACH, p, NULL, NULL);
	say("  ptrace(PTRACE_ATTACH)  -> %ld  %s", t, t < 0 ? strerror(errno) : "OK");
	if (t == 0)
		ptrace(PTRACE_DETACH, p, NULL, NULL);

	say("\nverdict:");
	if (access("/proc/self/status", R_OK) == 0) {
		/* CapEff is what decides the write path. */
	}
	say("  reading works, writing does not, so getsockname cannot report the");
	say("  address the child asked for and must be passed through honestly.");
	kill(p, SIGKILL);
	waitpid(p, NULL, 0);
	return 0;
}