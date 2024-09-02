#include "vmlinux.h"

#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "sockstats.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u32 target_pid = 0;

// TODO: also collect stats per syscall
// TODO: increase MAX_SOCKETS...

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, __u32);
} processes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, __u32);
    __type(value, __u32);
} sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, __u32);
    __type(value, __u32);
} reg_sockets SEC(".maps");

int is_socket(int fd)
{
    __u32* value = bpf_map_lookup_elem(&reg_sockets, &fd);
    if (value == NULL || *value != REGSOCK)
        return 0;

    return 1;
}

int tp_syscall_process(__u32 fd)
{
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tgid = pidtgid >> 32;
    __u32 pid = pidtgid & 0xFFFFFFFF;

    if (tgid != target_pid || !is_socket(fd))
        return 0;

    void* map = bpf_map_lookup_elem(&sockets, &fd);
    if (map == NULL) {
        bpf_printk("Inner map is null on FD=%d\n", fd);
        return 0;
    }

    __u32 ncounter = 1;
    __u32* counter = bpf_map_lookup_elem(map, &pid);
    if (counter == NULL) {
        if (bpf_map_update_elem(map, &pid, &ncounter, 0) < 0)
            bpf_printk("Failed setting counter on FD=%d \n", fd);
    } else
        __sync_fetch_and_add(counter, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(struct trace_event_raw_sys_exit* ctx)
{
    int reg = REGSOCK;
    int fd = ctx->ret;

    if (fd < 0 || bpf_map_update_elem(&reg_sockets, &fd, &reg, BPF_ANY) < 0) {
        bpf_printk("Invalid FD=%d or cannot be registered\n", fd);
        return 0;
    }

    return tp_syscall_process(fd);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_listen")
int tracepoint__syscalls__sys_enter_listen(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint__syscalls__sys_enter_recvfrom(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint__syscalls__sys_enter_recvmsg(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int tracepoint__syscalls__sys_enter_recvmmsg(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint__syscalls__sys_enter_sendmsg(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tracepoint__syscalls__sys_enter_sendmmsg(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int tracepoint__syscalls__sys_enter_getsockopt(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int tracepoint__syscalls__sys_enter_setsockopt(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int tracepoint__syscalls__sys_enter_getpeername(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int tracepoint__syscalls__sys_enter_getsockname(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int tracepoint__syscalls__sys_enter_shutdown(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint__syscalls__sys_enter_readv(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint__syscalls__sys_enter_writev(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter* ctx)
{
    return tp_syscall_process(FD(ctx));
}
