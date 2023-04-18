#include <net/sock.h>
#include <net/inet_sock.h>

#define SOCK_PASS 1
#define SOCK_EPERM 0

#define PROC_EXECNAME_MAX 32

struct in6_addr_u64 {
  __u64 addr_hi;
  __u64 addr_lo;
};

struct execname {
    char execname[PROC_EXECNAME_MAX];
};

BPF_HASH(blacklist_ip, __u32, __u64);
// BPF_HASH_OF_MAPS(blacklist_exec, __u32, "blacklist_ip", 100);
// kprobe pushes to sockfile pid to this map
BPF_HASH(sockfile_pname, struct file *, __u32);

static unsigned int bpf_strcpy(char *dst, char *src) {
    int MAX_CPY_LEN = 24;

    int i = 0;
    #pragma clang loop unroll(full)
    while (i < MAX_CPY_LEN) {
        dst[i] = src[i];
        if (src[i] == '\0') return i - 1;
        i++;
    }
    dst[i] = '\0';
    return i - 1;
}

static bool bpf_strcmp(char *s1, char *s2) {
    int MAX_STR_LEN = 24;

    int i = 0;
    #pragma clang loop unroll(full)
    while (i < MAX_STR_LEN) {
        if (s1[i] != s2[i]) return false;
        if (s1[i] == '\0') return true;
        i++;
    }

    return true;

}

// Socket filter BPF program
int sock_filter(struct __sk_buff *bpf_skb) {
    struct sk_buff skb;

    // Base addresses for __sk_buff and sk_buff are the same, so reading
    // sk_buff from kernel mem
    int succ = bpf_probe_read_kernel(&skb, (__u32)sizeof(struct sk_buff), bpf_skb);
    if (succ != 0) return SOCK_PASS;

    // Read sock object from kernel
    struct sock *sk = skb.sk;

    // Read port
    __u64 dport;
    succ = bpf_probe_read_kernel(&dport, (__u32)sizeof(__u64), &sk->sk_dport);
    if (succ != 0) return SOCK_PASS;

    dport = htons(dport);

    // Read socket object
    struct socket *sock;
    succ = bpf_probe_read_kernel(&sock, (__u32)sizeof(struct socket*), &sk->sk_socket);
    if (succ != 0) return SOCK_PASS;

    // Read file object for socket file
    struct file *file;
    succ = bpf_probe_read_kernel(&file, (__u32)sizeof(struct file*), &sock->file);
    if (succ != 0) return SOCK_PASS;

    // Read fowner
    struct fown_struct f_owner;
    succ = bpf_probe_read_kernel(&f_owner, (__u32)sizeof(struct fown_struct), &file->f_owner);
    if (succ != 0) return SOCK_PASS;


    if (bpf_skb->sk == 0) return SOCK_PASS;

    // Get IP and port fields. Take care of endianness
    __u32 port = htons(bpf_skb->sk->dst_port);
    __u64 ip = htonl(bpf_skb->sk->dst_ip4);

    // Lookup for current process name and check if the process name has a filter
    __u32 *e = sockfile_pname.lookup(&file);
    if (e == NULL) return SOCK_PASS;

    __u32 ee = *e;

    bpf_trace_printk("[SOCK] Found %d", ip);
    // Check if IP exists in blacklist
    // void *blacklist_ip_for_this_execname = blacklist_exec.lookup(&ee);
    // if (blacklist_ip_for_this_execname == NULL) return SOCK_PASS;

    __u64 *blacklisted_ip = blacklist_ip.lookup(&ee);// (__u64 *) bpf_map_lookup_elem(blacklist_ip, &ee);
    if (blacklisted_ip == NULL) return SOCK_PASS;

    if (*blacklisted_ip == ip) {
        bpf_trace_printk("Blocked blacklisted ip: %d for process: %s", *blacklisted_ip, ee);
        return SOCK_EPERM;
    }

    return SOCK_PASS;
}


// Get executable file name that calls sock_alloc_file and push to map
int kprobe_map_sockfile_pname(struct pt_regs *ctx) {
    // Get task struct
    struct task_struct *t = (struct task_struct *) bpf_get_current_task();

    // Get return value (file pointer) from pt regs
    struct file *file = (struct file *) PT_REGS_RC(ctx);

    __u32 uexec = (__u32) t->comm;
    // bpf_trace_printk("[KPROBE] %d", uexec);
    // Push execname to map
    sockfile_pname.update(&file, &uexec);
    return 0;
}
