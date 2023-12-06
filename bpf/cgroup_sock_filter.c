#include <net/sock.h>
#include <net/inet_sock.h>

#define SOCK_PASS 1
#define SOCK_EPERM 0

#define PROC_EXECNAME_MAX 16
#define EXECNAMES_COUNT_MAX 10
#define IP_COUNT_PER_EXECNAME_MAX 10
#define PORT_COUNT_PER_IP_MAX 5
#define TOTSIZE ( EXECNAMES_COUNT_MAX * IP_COUNT_PER_EXECNAME_MAX * PORT_COUNT_PER_IP_MAX )

/**
 * 
 * This BPF file consists of 2 programs
 *  - A PROG_TYPE_CGROUP_SKB to forward or drop packets based on allow list
 *  - A kretprobe to map a process to socket file struct
 * 
 * PROG_TYPE_CGROUP_SKB is used to forward or drop packets through the ip_finish_output() function.
 * A BPF handler function attached to CGROUP_SKB is expected to return 1 (SOCK_PASS) to forward.
 * Any other return value will result in an EPERM propagating an EPERM to ip_finish_output(). This
 * BPF program, however does not get process context and cannot access process comm.
 * 
 * Kretprobe pushes a map between process comm and file struct. This file struct can be accessed
 * through the sock object in the CGROUP_SKB BPF program. So this map helps CGROUP_SKB to access
 * process comm.
 * 
 * */

struct in6_addr_u64 {
    __u64 addr_hi;
    __u64 addr_lo;
};

// 16 byte process executable name (comm)
struct Execname {
    __u64 execname_hi;
    __u64 execname_lo;
};

// Array of execnames
BPF_ARRAY(blacklist_execname, struct Execname, TOTSIZE);
// Array of ips
BPF_ARRAY(blacklist_ip, __u32, TOTSIZE);
// Array of CIDRs
BPF_ARRAY(blacklist_cidr_for_ip, __u32, TOTSIZE);
// Array of ports
BPF_ARRAY(blacklist_port_for_ip, __u32, TOTSIZE);

// kprobe pushes to sockfile execname to this map
BPF_HASH(sockfile_pname, struct file *, struct Execname);

static unsigned int bpf_strcpy(char *dst, char *src) {
    int MAX_CPY_LEN = PROC_EXECNAME_MAX;

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
    int MAX_STR_LEN = PROC_EXECNAME_MAX;

    int i = 0;
    #pragma clang loop unroll(full)
    while (i < MAX_STR_LEN) {
        if (s1[i] != s2[i]) return false;
        if (s1[i] == '\0') return true;
        i++;
    }

    return true;

}

static bool ip_in_net(__u32 candidate_ip, __u32 net_ip, __u32 cidr4_mask) {
    return ((candidate_ip >> (32 - cidr4_mask)) == (net_ip >> (32 - cidr4_mask)));
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
    __u32 ip = htonl(bpf_skb->sk->dst_ip4);

    // Lookup for current process name and check if the process name has a filter
    struct Execname *e = sockfile_pname.lookup(&file);
    if (e == NULL) return SOCK_PASS;


    // Check for match in arrays
    int i = 0;
    #pragma clang loop unroll(full)
    while (i < TOTSIZE) {
        int idx = i;
        struct Execname *candidate_exec = (struct Execname *) blacklist_execname.lookup(&idx);
        if (candidate_exec == NULL) { i++; continue; }

        if (candidate_exec->execname_hi == e->execname_hi && candidate_exec->execname_lo == e->execname_lo){
            // Found execname, check ip4 cidr
            __u32 *bl_ip = blacklist_ip.lookup(&idx);
            __u32 *cidr4_mask = blacklist_cidr_for_ip.lookup(&idx);
            if (bl_ip == NULL || cidr4_mask == NULL) { i++; continue; }

            if (ip_in_net(ip, *bl_ip, *cidr4_mask)) {
                // IP found, check port
                __u32 *bl_port = blacklist_port_for_ip.lookup(&idx);
                if (bl_port == NULL) { i++; continue; }

                if (*bl_port == port) {
                    // Matched
                    bpf_trace_printk("BLOCKED for %s%s connection to %d", &candidate_exec->execname_hi, &candidate_exec->execname_lo, ip);
                    return SOCK_EPERM;
                }
            }
        }
        i++;
    }

    return SOCK_PASS;
}


// Get executable file name that calls sock_alloc_file and push to map
int kprobe_map_sockfile_pname(struct pt_regs *ctx) {
    // Get return value (file pointer) from pt regs
    struct file *file = (struct file *) PT_REGS_RC(ctx);

    // struct Execname execname;
    struct Execname execname;
    execname.execname_lo = 0;
    execname.execname_hi = 0;

    // get comm from the task struct of current program
    bpf_get_current_comm((char *)&execname, PROC_EXECNAME_MAX);
    // bpf_trace_printk("[KPROBE] %d", sizeof(struct Execname));
    // Push execname to map
    sockfile_pname.update(&file, &execname);
    return 0;
}
