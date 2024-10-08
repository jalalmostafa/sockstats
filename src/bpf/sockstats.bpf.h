#ifndef SOCKSTATS_BPF_H
#define SOCKSTATS_BPF_H

#define SOCKSTATS_NFDBITS (8 * sizeof(unsigned long))
#define SOCKSTATS_NFDBITS_MASK (SOCKSTATS_NFDBITS - 1)
#define SOCKSTATS_LENGTH (1024 / SOCKSTATS_NFDBITS)

#define MAX_PROCESSES 256
#define MAX_SOCKETS SOCKSTATS_NFDBITS

#define FIRST_ARG(ctx) (ctx->args[0])
#define FD(ctx) (FIRST_ARG(ctx))

#define REGSOCK 1

enum sockstats_syscall {
    SOCKSTATS_SYSCALL_SOCKET,
    SOCKSTATS_SYSCALL_BIND,
    SOCKSTATS_SYSCALL_LISTEN,
    SOCKSTATS_SYSCALL_CONNECT,
    SOCKSTATS_SYSCALL_ACCEPT,
    SOCKSTATS_SYSCALL_ACCEPT4,
    SOCKSTATS_SYSCALL_RECVFROM,
    SOCKSTATS_SYSCALL_RECVMSG,
    SOCKSTATS_SYSCALL_RECVMMSG,
    SOCKSTATS_SYSCALL_SENDTO,
    SOCKSTATS_SYSCALL_SENDMSG,
    SOCKSTATS_SYSCALL_SENDMMSG,
    SOCKSTATS_SYSCALL_SETSOCKOPT,
    SOCKSTATS_SYSCALL_GETSOCKOPT,
    SOCKSTATS_SYSCALL_GETPEERNAME,
    SOCKSTATS_SYSCALL_GETSOCKNAME,
    SOCKSTATS_SYSCALL_SHUTDOWN,
    SOCKSTATS_SYSCALL_READ,
    SOCKSTATS_SYSCALL_READV,
    SOCKSTATS_SYSCALL_WRITE,
    SOCKSTATS_SYSCALL_WRITEV,
    SOCKSTATS_SYSCALL_CLOSE,
    SOCKSTATS_SYSCALL_POLL,
    SOCKSTATS_SYSCALL_PPOLL,
    SOCKSTATS_SYSCALL_SELECT,
    SOCKSTATS_SYSCALL_PSELECT,
    SOCKSTATS_SYSCALL_EPOLL_CREATE,
    SOCKSTATS_SYSCALL_EPOLL_CREATE1,
    SOCKSTATS_SYSCALL_EPOLL_CTL,
    SOCKSTATS_SYSCALL_EPOLL_WAIT,
    SOCKSTATS_SYSCALL_EPOLL_PWAIT,
    SOCKSTATS_SYSCALL_EPOLL_PWAIT2,
    SOCKSTATS_SYSCALL_MAX
};

typedef enum sockstats_syscall sockstats_syscall_t;

const char* syscall_strings[] = {
    [SOCKSTATS_SYSCALL_SOCKET] = "socket",
    [SOCKSTATS_SYSCALL_BIND] = "bind",
    [SOCKSTATS_SYSCALL_LISTEN] = "listen",
    [SOCKSTATS_SYSCALL_CONNECT] = "connect",
    [SOCKSTATS_SYSCALL_ACCEPT] = "accept",
    [SOCKSTATS_SYSCALL_ACCEPT4] = "accept4",
    [SOCKSTATS_SYSCALL_RECVFROM] = "recvfrom",
    [SOCKSTATS_SYSCALL_RECVMSG] = "recvmsg",
    [SOCKSTATS_SYSCALL_RECVMMSG] = "recvmmsg",
    [SOCKSTATS_SYSCALL_SENDTO] = "sendto",
    [SOCKSTATS_SYSCALL_SENDMSG] = "sendmsg",
    [SOCKSTATS_SYSCALL_SENDMMSG] = "sendmmsg",
    [SOCKSTATS_SYSCALL_SETSOCKOPT] = "setsockopt",
    [SOCKSTATS_SYSCALL_GETSOCKOPT] = "getsockopt",
    [SOCKSTATS_SYSCALL_GETPEERNAME] = "getpeername",
    [SOCKSTATS_SYSCALL_GETSOCKNAME] = "getsockname",
    [SOCKSTATS_SYSCALL_SHUTDOWN] = "shutdown",
    [SOCKSTATS_SYSCALL_READ] = "read",
    [SOCKSTATS_SYSCALL_READV] = "readv",
    [SOCKSTATS_SYSCALL_WRITE] = "write",
    [SOCKSTATS_SYSCALL_WRITEV] = "writev",
    [SOCKSTATS_SYSCALL_CLOSE] = "close",
    [SOCKSTATS_SYSCALL_POLL] = "poll",
    [SOCKSTATS_SYSCALL_PPOLL] = "ppoll",
    [SOCKSTATS_SYSCALL_SELECT] = "select",
    [SOCKSTATS_SYSCALL_PSELECT] = "pselect",
    [SOCKSTATS_SYSCALL_EPOLL_CREATE] = "epoll_create",
    [SOCKSTATS_SYSCALL_EPOLL_CREATE1] = "epoll_create1",
    [SOCKSTATS_SYSCALL_EPOLL_CTL] = "epoll_ctl",
    [SOCKSTATS_SYSCALL_EPOLL_WAIT] = "epoll_wait",
    [SOCKSTATS_SYSCALL_EPOLL_PWAIT] = "epoll_pwait",
    [SOCKSTATS_SYSCALL_EPOLL_PWAIT2] = "epoll_pwait2",
};

static inline const char* syscallstr(sockstats_syscall_t syscall)
{
    if (syscall < SOCKSTATS_SYSCALL_MAX)
        return syscall_strings[syscall];
    return NULL;
}

struct syscalls {
    __u32 counters[SOCKSTATS_SYSCALL_MAX];
};

#endif
