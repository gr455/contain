#include <linux/netdevice.h>

#define COMM_MAX 16

#define STATE_NEWLINK 0
#define STATE_REGISTERING_SELF 1
#define STATE_REGISTERING_PEER 2

/**
 * 
 * The goal with this BPF program is to find the ifindex of the container's
 * veth peer. This ifindex is used on the userspace program to identify
 * the container that was just created so the BPF filter can be attached to
 * this container's cgroup.
 * 
 * When a new container spawns, a veth pair is created by calling veth_newlink()
 * This routine then goes on to register the devices on either ends of this
 * veth pair with a single call to register_netdevice(). During the entry into
 * register_netdevice(), ifindex is not populated, so we need to hook a
 * kretprobe to the function to read ifindex which is populated by the time
 * register_netdevice() returns. But we don't have access to the device struct
 * in the kretprobe. So we store the reference to the netdevice struct with a
 * kprobe which is then used to read the ifindex when the kretprobe is hooked.
 * 
 * This BPF program hooks do the following
 *  - Traces creation of veth link
 *  - Stores the reference to netdevice struct with kprobe to register_netdevice()
 *  - Reads ifindex from netdevice with kretprobe to register_netdevice()
 * 
 * */

static bool bpf_strcmp_comm(char *s1, char *s2) {
    int MAX_STR_LEN = COMM_MAX;

    int i = 0;
    #pragma clang loop unroll(full)
    while (i < MAX_STR_LEN) {
        if (s1[i] != s2[i]) return false;
        if (s1[i] == '\0') return true;
        i++;
    }

    return true;

}

struct netdevice_ifindex_t {
    struct net_device *dev;
    int ifindex;
    int state;
};

BPF_HASH(pid_to_peer_netdevice_ifindex, __u64, struct netdevice_ifindex_t);

// Initialize netdevice_ifindex struct for pid. Verifies that veth pairs
// were created by dockerd.
static int do_trace__veth_newlink(struct net_device *dev) {
    bpf_trace_printk("[CALL] do_trace__veth_newlink");

    __u64 pid = bpf_get_current_pid_tgid();

    // Verify that veth pairs were created by a dockerd process.
    char comm[COMM_MAX];
    bpf_get_current_comm(comm, COMM_MAX);

    if (!bpf_strcmp_comm(comm, "dockerd\0")) return 0;

    // Initialize the struct. Really only used to verify that
    // veth pairs were created
    struct netdevice_ifindex_t netdevice_ifindex = {
        .dev = NULL,
        .ifindex = 0, // placeholder
        .state = STATE_NEWLINK,
    };

    pid_to_peer_netdevice_ifindex.update(&pid, &netdevice_ifindex);

    return 0;
}

// Since we won't be able to get the netdevice in the kretprobe, we store
// the reference to it in this kprobe
static int do_trace__register_netdevice(struct net_device *dev) {
    bpf_trace_printk("[CALL] do_trace__register_netdevice");

    __u64 pid = bpf_get_current_pid_tgid();

    struct netdevice_ifindex_t *netdevice_ifindex = pid_to_peer_netdevice_ifindex.lookup(&pid);

    if (netdevice_ifindex == NULL) return 0;

    switch (netdevice_ifindex->state) {

    // Veths were newly created, self registration will happen first. This device is SELF
    case STATE_NEWLINK:
        netdevice_ifindex->state = STATE_REGISTERING_SELF;
        netdevice_ifindex->dev = dev;
        break;
    // Self registration has completed for veth pair, peer registration now. This device is PEER
    case STATE_REGISTERING_LINK:
        netdevice_ifindex->state = STATE_REGISTERING_PEER;
        netdevice_ifindex->dev = dev;
        break;
    default:
        return 1;
    }


    return 0;
}


// Before register_netdevice returns, we should have the populated netdevice. Extract the
// ifindex from it.
static int doret_trace__register_netdevice(struct pt_regs *ctx, int ret) {
    bpf_trace_printk("[CALL] doret_trace__register_netdevice");
    // If registration was unsuccessful, fail.
    // if (ret != 0) return 1;

    bpf_trace_printk("[INFO] return ok");

    __u64 pid = bpf_get_current_pid_tgid();

    struct netdevice_ifindex_t *netdevice_ifindex = pid_to_peer_netdevice_ifindex.lookup(&pid);
    if (netdevice_ifindex == NULL) return 1;

    bpf_trace_printk("[INFO] netdevice_ifindex ok");

    // If this registration is not for the peer device, return
    if (netdevice_ifindex->state != STATE_REGISTERING_PEER) return 0;

    if (netdevice_ifindex->dev == NULL) return 1;

    // Set ifindex
    int ifindex = netdevice_ifindex->dev->ifindex;

    bpf_trace_printk("IFINDEX: %d", ifindex);

    return 0;
}


int trace__veth_newlink(struct pt_regs *ctx) {

    struct net_device *dev = (struct net_device *) PT_REGS_PARM2(ctx);
    return do_trace__veth_newlink(dev);
}

int trace__register_netdevice(struct pt_regs *ctx) {
    struct net_device *dev = (struct net_device *)PT_REGS_PARM1(ctx);
    return do_trace__register_netdevice(dev);
}

int traceret__register_netdevice(struct pt_regs *ctx) {

    int ret = PT_REGS_RET(ctx);
    return doret_trace__register_netdevice(ctx, ret);
}