/*
 * libcfrsnet.so — map AF_INET/AF_INET6 sockets into a userspace virtual
 * network by rewriting them to AF_UNIX (abstract) sockets.
 *
 * The kernel never sees an AF_INET bind(2), connect(2) or listen(2). Each IP
 * endpoint becomes a name in the abstract namespace:
 *
 *     \0cfrsnet/<family>/<address>/<port>
 *
 * Two interposed programs on the same host therefore talk over AF_UNIX with
 * no host process at all ("direct mode"). When CFRSNET_CONTROL names the
 * stack's control socket, bind(2) also registers the endpoint so the stack
 * can bridge it to a tunnel.
 *
 * This file is compiled from the embedded copy in src/vnet/shim.rs, so a
 * cfrs binary can build it anywhere. It is deliberately C: interposition has
 * to happen at the libc symbol boundary, before any Rust constructor runs.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* ── real symbols ─────────────────────────────────────────────────────────── */

static int (*r_socket)(int, int, int);
static int (*r_socketpair)(int, int, int, int[2]);
static int (*r_bind)(int, const struct sockaddr *, socklen_t);
static int (*r_connect)(int, const struct sockaddr *, socklen_t);
static int (*r_listen)(int, int);
static int (*r_accept)(int, struct sockaddr *, socklen_t *);
static int (*r_accept4)(int, struct sockaddr *, socklen_t *, int);
static int (*r_getpeername)(int, struct sockaddr *, socklen_t *);
static int (*r_getsockname)(int, struct sockaddr *, socklen_t *);
static int (*r_close)(int);
static int (*r_dup)(int);
static int (*r_dup2)(int, int);
static int (*r_dup3)(int, int, int);
static int (*r_fcntl)(int, int, ...);
static ssize_t (*r_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*r_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static ssize_t (*r_sendmsg)(int, const struct msghdr *, int);
static ssize_t (*r_recvmsg)(int, struct msghdr *, int);
static int (*r_setsockopt)(int, int, int, const void *, socklen_t);
static int (*r_getsockopt)(int, int, int, void *, socklen_t *);
static int (*r_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

/* ── configuration ────────────────────────────────────────────────────────── */

struct config {
    char prefix[64];       /* abstract-name prefix, default "cfrsnet" */
    char control[108];     /* control socket name without NUL, empty = direct */
    int log;
    int map_loopback;      /* rewrite loopback endpoints to local_addr */
    struct in_addr local_v4;   /* CFRSNET_LOCAL_ADDR, default 10.66.0.2 */
    int max_fds;
    /* hosts table: name -> address, for getaddrinfo interception */
    struct hostent_override { char name[256]; char addr[64]; } hosts[64];
    size_t hosts_len;
};

static struct config cfg;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static pthread_once_t cfg_once = PTHREAD_ONCE_INIT;

static void parse_config(void);

static void cfg_init(void) {
    parse_config();
}

static void logf_(const char *fmt, ...) {
    if (!cfg.log) return;
    va_list ap;
    va_start(ap, fmt);
    fputs("[cfrsnet] ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void parse_config(void) {
    const char *v;
    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.prefix, sizeof cfg.prefix, "cfrsnet");
    cfg.max_fds = 65536;
    cfg.local_v4.s_addr = htonl((10u << 24) | (66u << 16) | (0u << 8) | 2u);
    if ((v = getenv("CFRSNET_PREFIX")) && *v) {
        snprintf(cfg.prefix, sizeof cfg.prefix, "%s", v);
    }
    if ((v = getenv("CFRSNET_CONTROL")) && *v) {
        snprintf(cfg.control, sizeof cfg.control, "%s", v);
    }
    cfg.log = (v = getenv("CFRSNET_LOG")) && *v && *v != '0';
    cfg.map_loopback = (v = getenv("CFRSNET_MAP_LOOPBACK")) && *v && *v != '0';
    if ((v = getenv("CFRSNET_LOCAL_ADDR")) && *v) {
        if (inet_pton(AF_INET, v, &cfg.local_v4) != 1) {
            logf_("CFRSNET_LOCAL_ADDR %s is not an IPv4 address\n", v);
        }
    }
    if ((v = getenv("CFRSNET_MAX_FDS")) && *v) {
        long n = strtol(v, NULL, 10);
        if (n > 0) cfg.max_fds = (int)n;
    }
    if ((v = getenv("CFRSNET_HOSTS")) && *v) {
        char *copy = strdup(v);
        if (copy) {
            char *save = NULL;
            for (char *tok = strtok_r(copy, ",", &save); tok && cfg.hosts_len < 64;
                 tok = strtok_r(NULL, ",", &save)) {
                char *eq = strchr(tok, '=');
                if (!eq) continue;
                *eq = '\0';
                snprintf(cfg.hosts[cfg.hosts_len].name, 256, "%s", tok);
                snprintf(cfg.hosts[cfg.hosts_len].addr, 64, "%s", eq + 1);
                cfg.hosts_len++;
            }
            free(copy);
        }
    }
}

static void resolve_real(void) {
    r_socket = dlsym(RTLD_NEXT, "socket");
    r_socketpair = dlsym(RTLD_NEXT, "socketpair");
    r_bind = dlsym(RTLD_NEXT, "bind");
    r_connect = dlsym(RTLD_NEXT, "connect");
    r_listen = dlsym(RTLD_NEXT, "listen");
    r_accept = dlsym(RTLD_NEXT, "accept");
    r_accept4 = dlsym(RTLD_NEXT, "accept4");
    r_getpeername = dlsym(RTLD_NEXT, "getpeername");
    r_getsockname = dlsym(RTLD_NEXT, "getsockname");
    r_close = dlsym(RTLD_NEXT, "close");
    r_dup = dlsym(RTLD_NEXT, "dup");
    r_dup2 = dlsym(RTLD_NEXT, "dup2");
    r_dup3 = dlsym(RTLD_NEXT, "dup3");
    r_fcntl = dlsym(RTLD_NEXT, "fcntl");
    r_sendto = dlsym(RTLD_NEXT, "sendto");
    r_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    r_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    r_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    r_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    r_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    r_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
}

static void ensure_init(void) {
    pthread_once(&init_once, resolve_real);
    pthread_once(&cfg_once, cfg_init);
}

/* Every interposed function must reach ensure_init before it dereferences an
 * r_* pointer or reads cfg, because both start out zeroed.

 * This is not a formality. close(2), dup(2), dup2(2), getpeername(2) and
 * getsockname(2) are called by programs that never open a socket at all: any
 * program that writes a file closes a descriptor first. Without ensure_init in
 * those functions, r_close is NULL at that point and the process dies with
 * SIGSEGV before it does anything useful. A shim that breaks the majority of
 * programs defeats its own purpose, so the check belongs in all of them. */

/* Copy a logical address into the caller's buffer the way Linux does.

   The Linux contract for getsockname/getpeername/getsockopt is: write at most
   *len bytes, then report the address's true length in *len, and succeed. A
   caller that wants the length asks with a zero-length buffer; a caller with a
   deliberately small buffer gets a truncated address, not an error. The
   reference implementation returned EINVAL for a short buffer and wrote a
   whole sockaddr_storage regardless, which both disagreed with the kernel and
   smashed the caller's stack when the buffer was smaller than 128 bytes.

   Returns 0 on success, -1 with errno set for the caller-error cases. */
static int copy_sockaddr(struct sockaddr *sa, socklen_t *slen,
                         const struct sockaddr_storage *addr, socklen_t addr_len) {
    if (!slen) {
        errno = EINVAL;
        return -1;
    }
    if (!sa) {
        /* Linux allows a null buffer purely to query the length. */
        *slen = addr_len;
        return 0;
    }
    socklen_t capacity = *slen;
    socklen_t copy = addr_len < capacity ? addr_len : capacity;
    if (copy) memcpy(sa, addr, copy);
    *slen = addr_len;
    return 0;
}

/* ── fd state table ───────────────────────────────────────────────────────── */

struct virt_fd {
    unsigned char is_virtual;
    unsigned char family;   /* AF_INET / AF_INET6, 0 when unknown */
    unsigned char is_dgram;
    struct sockaddr_storage local;
    socklen_t local_len;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    int tcp_nodelay;        /* recorded IPPROTO_TCP option */
    int tcp_keepalive;
    int so_reuseaddr;
};

static struct virt_fd *fd_table;
static size_t fd_table_len;
static pthread_mutex_t fd_lock = PTHREAD_MUTEX_INITIALIZER;

static int table_ensure(int fd) {
    if (fd < 0 || fd >= cfg.max_fds) return -1;
    size_t want = (size_t)fd + 1;
    if (want > fd_table_len) {
        size_t grow = fd_table_len ? fd_table_len : 256;
        while (grow < want) grow *= 2;
        if (grow > (size_t)cfg.max_fds) grow = (size_t)cfg.max_fds;
        struct virt_fd *next = realloc(fd_table, grow * sizeof *next);
        if (!next) return -1;
        memset(next + fd_table_len, 0, (grow - fd_table_len) * sizeof *next);
        fd_table = next;
        fd_table_len = grow;
    }
    return 0;
}

static int fd_is_virtual(int fd) {
    int result = 0;
    pthread_mutex_lock(&fd_lock);
    if (fd >= 0 && (size_t)fd < fd_table_len) result = fd_table[fd].is_virtual;
    pthread_mutex_unlock(&fd_lock);
    return result;
}

static void fd_mark(int fd, int family, int type) {
    pthread_mutex_lock(&fd_lock);
    if (table_ensure(fd) == 0) {
        fd_table[fd].is_virtual = 1;
        fd_table[fd].family = (unsigned char)family;
        fd_table[fd].is_dgram = (type == SOCK_DGRAM);
    }
    pthread_mutex_unlock(&fd_lock);
}

static void fd_clear(int fd) {
    pthread_mutex_lock(&fd_lock);
    if (fd >= 0 && (size_t)fd < fd_table_len) memset(&fd_table[fd], 0, sizeof fd_table[fd]);
    pthread_mutex_unlock(&fd_lock);
}

static void fd_copy(int from, int to) {
    pthread_mutex_lock(&fd_lock);
    if (from >= 0 && (size_t)from < fd_table_len && table_ensure(to) == 0) {
        fd_table[to] = fd_table[from];
    }
    pthread_mutex_unlock(&fd_lock);
}

static void fd_record_local(int fd, const struct sockaddr *sa, socklen_t len) {
    pthread_mutex_lock(&fd_lock);
    if (fd >= 0 && (size_t)fd < fd_table_len && len <= sizeof(struct sockaddr_storage)) {
        memcpy(&fd_table[fd].local, sa, len);
        fd_table[fd].local_len = len;
        fd_table[fd].family = (unsigned char)sa->sa_family;
    }
    pthread_mutex_unlock(&fd_lock);
}

static void fd_record_peer(int fd, const struct sockaddr *sa, socklen_t len) {
    pthread_mutex_lock(&fd_lock);
    if (fd >= 0 && (size_t)fd < fd_table_len && len <= sizeof(struct sockaddr_storage)) {
        memcpy(&fd_table[fd].peer, sa, len);
        fd_table[fd].peer_len = len;
    }
    pthread_mutex_unlock(&fd_lock);
}

/* ── address translation ──────────────────────────────────────────────────── */

/* RFC 5952 formatting, matching src/vnet/addr.rs byte for byte. */
static void format_v6(const unsigned char *addr, char *out, size_t out_len) {
    uint16_t groups[8];
    for (int i = 0; i < 8; i++) groups[i] = (uint16_t)((addr[2 * i] << 8) | addr[2 * i + 1]);
    int best_start = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (groups[i] == 0) {
            int start = i;
            while (i < 8 && groups[i] == 0) i++;
            int len = i - start;
            if (len > best_len) {
                best_len = len;
                best_start = start;
            }
        } else {
            i++;
        }
    }
    if (best_len < 2) {
        best_start = -1;
        best_len = 0;
    }
    char buf[64];
    size_t used = 0;
    buf[0] = '\0';
    for (int i = 0; i < 8;) {
        if (i == best_start) {
            used += (size_t)snprintf(buf + used, sizeof buf - used, "::");
            i += best_len;
            continue;
        }
        if (used > 0 && buf[used - 1] != ':') {
            used += (size_t)snprintf(buf + used, sizeof buf - used, ":");
        }
        used += (size_t)snprintf(buf + used, sizeof buf - used, "%x", groups[i]);
        i++;
    }
    if (used == 0) snprintf(buf, sizeof buf, "::");
    snprintf(out, out_len, "%s", buf);
}

static int to_abstract(const struct sockaddr *sa, socklen_t len,
                       struct sockaddr_un *un, socklen_t *un_len) {
    char ip[64];
    unsigned port;
    int family;
    if (sa->sa_family == AF_INET) {
        if (len < (socklen_t)sizeof(struct sockaddr_in)) {
            errno = EINVAL;
            return -1;
        }
        const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
        struct in_addr addr = s->sin_addr;
        if (cfg.map_loopback && (ntohl(addr.s_addr) >> 24) == 127) {
            addr = cfg.local_v4;
        }
        if (!inet_ntop(AF_INET, &addr, ip, sizeof ip)) return -1;
        port = ntohs(s->sin_port);
        family = 4;
    } else if (sa->sa_family == AF_INET6) {
        if (len < (socklen_t)sizeof(struct sockaddr_in6)) {
            errno = EINVAL;
            return -1;
        }
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
        struct in6_addr addr = s->sin6_addr;
        if (cfg.map_loopback && IN6_IS_ADDR_LOOPBACK(&addr)) {
            /* Address ::ffff:<local_v4>, formatted by the same RFC 5952 code
             * as every other v6 literal, so it matches the Rust encoder. */
            unsigned char mapped[16] = {0};
            mapped[10] = 0xff;
            mapped[11] = 0xff;
            memcpy(mapped + 12, &cfg.local_v4, 4);
            format_v6(mapped, ip, sizeof ip);
        } else {
            format_v6(addr.s6_addr, ip, sizeof ip);
        }
        port = ntohs(s->sin6_port);
        family = 6;
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    memset(un, 0, sizeof *un);
    un->sun_family = AF_UNIX;
    int n = snprintf(un->sun_path + 1, sizeof(un->sun_path) - 1, "%s/%d/%s/%u",
                     cfg.prefix, family, ip, port);
    if (n <= 0 || (size_t)n >= sizeof(un->sun_path) - 1) {
        errno = ENAMETOOLONG;
        return -1;
    }
    *un_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + (size_t)n);
    return 0;
}

/* Parse \0cfrsnet/4/10.66.0.2/8080 back into a sockaddr. */
static int from_abstract_name(const char *name, struct sockaddr_storage *out, socklen_t *out_len) {
    char prefix[96];
    snprintf(prefix, sizeof prefix, "%s/", cfg.prefix);
    size_t plen = strlen(prefix);
    if (strncmp(name, prefix, plen) != 0) return -1;
    const char *rest = name + plen;
    const char *slash = strchr(rest, '/');
    if (!slash) return -1;
    int family = atoi(rest);
    char host[64];
    size_t hlen = (size_t)(slash - rest - 1) + 1; /* digits before '/' */
    if (hlen > 8) return -1;
    /* host is between slash+1 and the next slash */
    const char *host_start = slash + 1;
    const char *port_slash = strchr(host_start, '/');
    if (!port_slash) return -1;
    size_t host_len = (size_t)(port_slash - host_start);
    if (host_len >= sizeof host) return -1;
    memcpy(host, host_start, host_len);
    host[host_len] = '\0';
    unsigned port = (unsigned)atoi(port_slash + 1);
    memset(out, 0, sizeof *out);
    if (family == 4) {
        struct sockaddr_in *s = (struct sockaddr_in *)out;
        s->sin_family = AF_INET;
        s->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &s->sin_addr) != 1) return -1;
        *out_len = sizeof *s;
        return 0;
    }
    if (family == 6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)out;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host, &s->sin6_addr) != 1) return -1;
        *out_len = sizeof *s;
        return 0;
    }
    return -1;
}

/* Recover a logical peer from an AF_UNIX abstract address, if it is ours. */
static int peer_from_unix(const struct sockaddr *sa, socklen_t len,
                          struct sockaddr_storage *out, socklen_t *out_len) {
    if (!sa || sa->sa_family != AF_UNIX) return -1;
    const struct sockaddr_un *un = (const struct sockaddr_un *)sa;
    socklen_t path_len = (socklen_t)(len - offsetof(struct sockaddr_un, sun_path));
    if (path_len <= 1 || un->sun_path[0] != '\0') {
        /* A filesystem path or an unnamed socket: not ours. */
        if (path_len < 1 || un->sun_path[0] == '\0') return -1;
        return -1;
    }
    return from_abstract_name(un->sun_path + 1, out, out_len);
}

/* ── control protocol (optional, switch mode) ─────────────────────────────── */

static int ctl_fd = -1;

static int ctl_connect(void) {
    if (ctl_fd >= 0) return ctl_fd;
    if (!cfg.control[0]) return -1;
    int fd = r_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    size_t clen = strlen(cfg.control);
    if (clen > sizeof un.sun_path - 2) clen = sizeof un.sun_path - 2;
    memcpy(un.sun_path + 1, cfg.control, clen);
    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + clen);
    if (r_connect(fd, (struct sockaddr *)&un, len) < 0) {
        r_close(fd);
        return -1;
    }
    ctl_fd = fd;
    return fd;
}

static void ctl_register(int op, int id, const struct sockaddr *sa) {
    if (!cfg.control[0]) return;
    int fd = ctl_connect();
    if (fd < 0) return;
    unsigned char payload[64];
    size_t off = 0;
    payload[off++] = (unsigned char)(id >> 24);
    payload[off++] = (unsigned char)(id >> 16);
    payload[off++] = (unsigned char)(id >> 8);
    payload[off++] = (unsigned char)id;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
        payload[off++] = 4;
        memcpy(payload + off, &s->sin_addr, 4);
        off += 4;
        payload[off++] = (unsigned char)(s->sin_port >> 8);
        payload[off++] = (unsigned char)(s->sin_port & 0xff);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
        payload[off++] = 6;
        memcpy(payload + off, &s->sin6_addr, 16);
        off += 16;
        payload[off++] = (unsigned char)(s->sin6_port >> 8);
        payload[off++] = (unsigned char)(s->sin6_port & 0xff);
    } else {
        return;
    }
    unsigned char frame[3 + 64];
    frame[0] = (unsigned char)op;
    frame[1] = (unsigned char)(off >> 8);
    frame[2] = (unsigned char)(off & 0xff);
    memcpy(frame + 3, payload, off);
    ssize_t n = send(fd, frame, off + 3, MSG_DONTWAIT);
    if (n < 0) {
        r_close(fd);
        ctl_fd = -1;
        logf_("control registration failed: %s\n", strerror(errno));
    }
}

/* ── interposed API ───────────────────────────────────────────────────────── */

int socket(int domain, int type, int protocol) {
    ensure_init();
    if (domain == AF_INET || domain == AF_INET6) {
        if (type == SOCK_RAW) {
            errno = EAFNOSUPPORT;
            return -1;
        }
        int fd = r_socket(AF_UNIX, type, 0);
        if (fd >= 0) {
            fd_mark(fd, domain, type);
            logf_("socket(%s) -> AF_UNIX fd=%d\n",
                  domain == AF_INET ? "AF_INET" : "AF_INET6", fd);
        }
        return fd;
    }
    return r_socket(domain, type, protocol);
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
    ensure_init();
    if (domain == AF_INET || domain == AF_INET6) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return r_socketpair(domain, type, protocol, sv);
}

int bind(int fd, const struct sockaddr *sa, socklen_t len) {
    ensure_init();
    if (!fd_is_virtual(fd)) return r_bind(fd, sa, len);
    struct sockaddr_un un;
    socklen_t un_len;
    if (to_abstract(sa, len, &un, &un_len) < 0) return -1;
    int rc = r_bind(fd, (struct sockaddr *)&un, un_len);
    if (rc == 0) {
        fd_record_local(fd, sa, len);
        logf_("bind -> %s\n", un.sun_path + 1);
        ctl_register(1, fd, sa);
    }
    return rc;
}

int connect(int fd, const struct sockaddr *sa, socklen_t len) {
    ensure_init();
    if (!fd_is_virtual(fd)) return r_connect(fd, sa, len);
    struct sockaddr_un un;
    socklen_t un_len;
    if (to_abstract(sa, len, &un, &un_len) < 0) return -1;
    int rc = r_connect(fd, (struct sockaddr *)&un, un_len);
    if (rc == 0) {
        fd_record_peer(fd, sa, len);
        logf_("connect -> %s\n", un.sun_path + 1);
    } else {
        logf_("connect -> %s failed: %s\n", un.sun_path + 1, strerror(errno));
    }
    return rc;
}

int listen(int fd, int backlog) {
    ensure_init();
    return r_listen(fd, backlog);
}

static int finish_accept(int listener, int client, struct sockaddr *sa, socklen_t *len,
                         socklen_t capacity) {
    if (client < 0) return client;
    if (fd_is_virtual(listener)) {
        pthread_mutex_lock(&fd_lock);
        int family = 0;
        struct sockaddr_storage local;
        socklen_t local_len = 0;
        if ((size_t)listener < fd_table_len) {
            family = fd_table[listener].family;
            local = fd_table[listener].local;
            local_len = fd_table[listener].local_len;
        }
        pthread_mutex_unlock(&fd_lock);
        fd_mark(client, family ? family : AF_INET, 0);
        if (local_len) fd_record_local(client, (struct sockaddr *)&local, local_len);
        /* Recover the logical peer if the client bound a cfrsnet name. */
        if (sa && len && capacity > 0) {
            /* Read the kernel's answer through a local buffer: the caller's
               buffer may be smaller than the abstract name, and the kernel has
               already told us how much it wanted to write. */
            struct sockaddr_storage raw;
            socklen_t raw_len = sizeof raw;
            socklen_t got = *len;
            memcpy(&raw, sa, got < sizeof raw ? got : sizeof raw);
            if (got > sizeof raw) got = sizeof raw;
            raw_len = got;
            struct sockaddr_storage peer;
            socklen_t peer_len = 0;
            if (peer_from_unix((struct sockaddr *)&raw, raw_len, &peer, &peer_len) == 0) {
                fd_record_peer(client, (struct sockaddr *)&peer, peer_len);
                /* Truncate to the caller's buffer and report the true length,
                   which is what accept(2) does on Linux. */
                socklen_t copy = peer_len < capacity ? peer_len : capacity;
                memcpy(sa, &peer, copy);
                *len = peer_len;
            } else {
                *len = 0;
            }
        }
    }
    return client;
}

int accept(int fd, struct sockaddr *sa, socklen_t *len) {
    ensure_init();
    /* Save the caller's capacity before the real accept overwrites *len with
       the kernel's own answer. Linux accepts an address longer than the
       caller's buffer by truncating and reporting the true length, so the
       shim must do the same; clamping against the kernel's length instead
       would be clamping against a number the caller never chose. */
    socklen_t capacity = len ? *len : 0;
    int client = r_accept(fd, sa, len);
    return finish_accept(fd, client, sa, len, capacity);
}

int accept4(int fd, struct sockaddr *sa, socklen_t *len, int flags) {
    ensure_init();
    socklen_t capacity = len ? *len : 0;
    int client = r_accept4(fd, sa, len, flags);
    return finish_accept(fd, client, sa, len, capacity);
}

/* The address an un-bound or unconnected socket reports.

   getsockname on a socket that has not been bound answers with the wildcard
   address of its own family and port 0, which is what an AF_INET socket says.
   getpeername on a socket that is not connected answers ENOTCONN, not a
   wildcard: Linux has nothing to report there, and inventing an address makes
   a program believe it has a peer it does not have. */
static socklen_t wildcard_addr(int family, struct sockaddr_storage *out) {
    memset(out, 0, sizeof *out);
    if (family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)out;
        s6->sin6_family = AF_INET6;
        return sizeof *s6;
    }
    struct sockaddr_in *s4 = (struct sockaddr_in *)out;
    s4->sin_family = AF_INET;
    return sizeof *s4;
}

int getpeername(int fd, struct sockaddr *sa, socklen_t *len) {
    ensure_init();
    if (!fd_is_virtual(fd)) return r_getpeername(fd, sa, len);
    pthread_mutex_lock(&fd_lock);
    struct sockaddr_storage peer;
    socklen_t peer_len = 0;
    if ((size_t)fd < fd_table_len) {
        peer = fd_table[fd].peer;
        peer_len = fd_table[fd].peer_len;
    }
    pthread_mutex_unlock(&fd_lock);
    if (peer_len == 0) {
        errno = ENOTCONN;
        return -1;
    }
    return copy_sockaddr(sa, len, &peer, peer_len);
}

int getsockname(int fd, struct sockaddr *sa, socklen_t *len) {
    ensure_init();
    if (!fd_is_virtual(fd)) return r_getsockname(fd, sa, len);
    pthread_mutex_lock(&fd_lock);
    struct sockaddr_storage local;
    socklen_t local_len = 0;
    int family = 0;
    if ((size_t)fd < fd_table_len) {
        local = fd_table[fd].local;
        local_len = fd_table[fd].local_len;
        family = fd_table[fd].family;
    }
    pthread_mutex_unlock(&fd_lock);
    if (local_len == 0) {
        struct sockaddr_storage any;
        socklen_t any_len = wildcard_addr(family ? family : AF_INET, &any);
        return copy_sockaddr(sa, len, &any, any_len);
    }
    return copy_sockaddr(sa, len, &local, local_len);
}

int close(int fd) {
    ensure_init();
    int rc = r_close(fd);
    if (rc == 0) fd_clear(fd);
    return rc;
}

/* dup(2) and friends must resolve the real symbol and read cfg.max_fds before
   fd_copy runs, or a program that duplicates a descriptor before its first
   socket call reads an unparsed configuration and silently loses virtual
   status on the copy. */
int dup(int oldfd) {
    ensure_init();
    int fd = r_dup(oldfd);
    if (fd >= 0) fd_copy(oldfd, fd);
    return fd;
}

int dup2(int oldfd, int newfd) {
    ensure_init();
    int fd = r_dup2(oldfd, newfd);
    if (fd >= 0) fd_copy(oldfd, newfd);
    return fd;
}

int dup3(int oldfd, int newfd, int flags) {
    ensure_init();
    int fd = r_dup3(oldfd, newfd, flags);
    if (fd >= 0) fd_copy(oldfd, newfd);
    return fd;
}

/* fcntl(2) is variadic and its commands take two different kinds of third
   argument: an int for the flag setters, a pointer for the out-parameters.
   Reading a va_arg of the wrong type is undefined behaviour, and reading one at
   all for a command called with two arguments is undefined behaviour too. So
   each group reads its own type, and the argument-free group reads nothing.

   The first version of this shim read a single `void *` unconditionally. On
   x86-64 SysV that happens to work, because the third argument register holds
   whatever the caller left there and the kernel ignores it for F_GETFD, but it
   is UB at every optimisation level and would break on a target whose variadic
   save area is only filled for arguments actually passed. */
int fcntl(int fd, int cmd, ...) {
    ensure_init();
    va_list ap;
    va_start(ap, cmd);

    int rc;
    switch (cmd) {
    /* No third argument. */
    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
    case F_GETSIG:
    case F_GETLEASE:
        rc = r_fcntl(fd, cmd);
        va_end(ap);
        return rc;

    /* Third argument is an int. */
    case F_SETFD:
    case F_SETFL:
    case F_SETOWN:
    case F_SETSIG:
    case F_SETLEASE:
    case F_SETPIPE_SZ:
    case F_NOTIFY:
    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        int arg = va_arg(ap, int);
        va_end(ap);
        rc = r_fcntl(fd, cmd, arg);
        break;
    }

    /* Third argument is a pointer the kernel writes through. */
    case F_GETPIPE_SZ:
    case F_GET_SEALS:
    case F_GET_RW_HINT:
    case F_SET_RW_HINT:
    case F_ADD_SEALS: {
        void *arg = va_arg(ap, void *);
        va_end(ap);
        rc = r_fcntl(fd, cmd, arg);
        break;
    }

    default: {
        /* A command this shim does not know. Forward it as an int, which is
           the shape of every remaining Linux command; a command with a
           different shape would be reported by the kernel rather than ignored,
           because EBADF/EINVAL still come back. */
        int arg = va_arg(ap, int);
        va_end(ap);
        rc = r_fcntl(fd, cmd, arg);
        break;
    }
    }

    if (rc >= 0 && (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)) fd_copy(fd, rc);
    return rc;
}

ssize_t sendto(int fd, const void *buf, size_t n, int flags,
               const struct sockaddr *sa, socklen_t len) {
    ensure_init();
    if (!fd_is_virtual(fd) || !sa) {
        return r_sendto(fd, buf, n, flags, sa, len);
    }
    struct sockaddr_un un;
    socklen_t un_len;
    if (to_abstract(sa, len, &un, &un_len) < 0) return -1;
    logf_("sendto -> %s\n", un.sun_path + 1);
    return r_sendto(fd, buf, n, flags, (struct sockaddr *)&un, un_len);
}

ssize_t recvfrom(int fd, void *buf, size_t n, int flags,
                 struct sockaddr *sa, socklen_t *len) {
    ensure_init();
    if (!fd_is_virtual(fd) || !sa || !len) {
        return r_recvfrom(fd, buf, n, flags, sa, len);
    }
    struct sockaddr_storage src;
    socklen_t src_len = sizeof src;
    ssize_t rc = r_recvfrom(fd, buf, n, flags, (struct sockaddr *)&src, &src_len);
    if (rc < 0) return rc;
    struct sockaddr_storage logical;
    socklen_t logical_len = 0;
    if (peer_from_unix((struct sockaddr *)&src, src_len, &logical, &logical_len) == 0) {
        if (*len >= logical_len) {
            memcpy(sa, &logical, logical_len);
            *len = logical_len;
        } else {
            *len = logical_len;
        }
    } else {
        pthread_mutex_lock(&fd_lock);
        socklen_t peer_len = (size_t)fd < fd_table_len ? fd_table[fd].peer_len : 0;
        struct sockaddr_storage peer;
        if (peer_len) memcpy(&peer, &fd_table[fd].peer, sizeof peer);
        pthread_mutex_unlock(&fd_lock);
        if (peer_len && *len >= peer_len) {
            memcpy(sa, &peer, peer_len);
            *len = peer_len;
        } else {
            *len = 0;
        }
    }
    return rc;
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    ensure_init();
    if (!fd_is_virtual(fd) || !msg || !msg->msg_name) {
        return r_sendmsg(fd, msg, flags);
    }
    struct sockaddr_un un;
    socklen_t un_len;
    if (to_abstract((struct sockaddr *)msg->msg_name, msg->msg_namelen, &un, &un_len) < 0) return -1;
    struct msghdr copy = *msg;
    copy.msg_name = &un;
    copy.msg_namelen = un_len;
    logf_("sendmsg -> %s\n", un.sun_path + 1);
    return r_sendmsg(fd, &copy, flags);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    ensure_init();
    if (!fd_is_virtual(fd) || !msg || !msg->msg_name) {
        return r_recvmsg(fd, msg, flags);
    }
    struct sockaddr_storage src;
    struct msghdr copy = *msg;
    copy.msg_name = &src;
    copy.msg_namelen = sizeof src;
    ssize_t rc = r_recvmsg(fd, &copy, flags);
    if (rc < 0) return rc;
    struct sockaddr_storage logical;
    socklen_t logical_len = 0;
    if (peer_from_unix((struct sockaddr *)&src, copy.msg_namelen, &logical, &logical_len) == 0) {
        socklen_t capacity = msg->msg_namelen;
        memcpy(msg->msg_name, &logical, logical_len < capacity ? logical_len : capacity);
        msg->msg_namelen = logical_len;
    } else {
        msg->msg_namelen = 0;
    }
    msg->msg_flags = copy.msg_flags;
    return rc;
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    ensure_init();
    if (!fd_is_virtual(fd)) {
        return r_setsockopt(fd, level, optname, optval, optlen);
    }
    /* The underlying fd is AF_UNIX, so IP/TCP options are meaningless to the
     * kernel. Record the ones that matter and report success. */
    if (level == IPPROTO_TCP || level == IPPROTO_IP || level == IPPROTO_IPV6) {
        pthread_mutex_lock(&fd_lock);
        if ((size_t)fd < fd_table_len && optval && optlen >= sizeof(int)) {
            int value = *(const int *)optval;
            if (level == IPPROTO_TCP && optname == TCP_NODELAY) fd_table[fd].tcp_nodelay = value;
            else if (level == IPPROTO_TCP && optname == TCP_KEEPIDLE) fd_table[fd].tcp_keepalive = value;
        }
        pthread_mutex_unlock(&fd_lock);
        logf_("setsockopt fd=%d level=%d optname=%d swallowed\n", fd, level, optname);
        return 0;
    }
    if (level == SOL_SOCKET && optname == SO_REUSEADDR) {
        pthread_mutex_lock(&fd_lock);
        if ((size_t)fd < fd_table_len && optval && optlen >= sizeof(int)) {
            fd_table[fd].so_reuseaddr = *(const int *)optval;
        }
        pthread_mutex_unlock(&fd_lock);
    }
    return r_setsockopt(fd, level, optname, optval, optlen);
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    ensure_init();
    if (fd_is_virtual(fd) && (level == IPPROTO_TCP || level == IPPROTO_IP || level == IPPROTO_IPV6)) {
        if (!optval || !optlen || *optlen < sizeof(int)) {
            errno = EINVAL;
            return -1;
        }
        int value = 0;
        pthread_mutex_lock(&fd_lock);
        if ((size_t)fd < fd_table_len) {
            if (level == IPPROTO_TCP && optname == TCP_NODELAY) value = fd_table[fd].tcp_nodelay;
            else if (level == IPPROTO_TCP && optname == TCP_KEEPIDLE) value = fd_table[fd].tcp_keepalive;
        }
        pthread_mutex_unlock(&fd_lock);
        *(int *)optval = value;
        *optlen = sizeof(int);
        return 0;
    }
    return r_getsockopt(fd, level, optname, optval, optlen);
}

/* Intercept name resolution for names the virtual network owns, by rewriting
 * the node into the mapped address and letting the real resolver parse it. */
static const char *hosts_lookup(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < cfg.hosts_len; i++) {
        if (strcasecmp(cfg.hosts[i].name, name) == 0) return cfg.hosts[i].addr;
    }
    return NULL;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    ensure_init();
    const char *mapped = hosts_lookup(node);
    if (mapped) {
        logf_("getaddrinfo %s -> %s\n", node, mapped);
        return r_getaddrinfo(mapped, service, hints, res);
    }
    return r_getaddrinfo(node, service, hints, res);
}
