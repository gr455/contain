#include <linux/netdevice.h>
#include <linux/ns_common.h>
#include <net/net_namespace.h>
#include <linux/proc_ns.h>

#define COMM_MAX 16
#define IFIDX_QSIZE 100

#define STATE_NEWLINK 0
#define STATE_REGISTERING_HOST 1
#define STATE_REGISTERING_PEER 2
#define STATE_UNREGING_HOST 3
#define STATE_UNREGING_PEER 4

#define ERR_GENERIC 1
#define ERR_MAP_UPDATE_FAIL 2
#define ERR_MAP_LOOKUP_FAIL 3
#define ERR_ILLEGAL_STATE 4
#define ERR_UNEXPECTED_NULL 5

#define EVENT_STATE_DOWN 0
#define EVENT_STATE_UP 1


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
 *  - Also traces device unregistration and pushes the relevent ifindex to evt queue
 * 
 * 
 * Refer https://github.com/Gui774ume/network-security-probe 
 * 
 * */

struct netdevice_ifindex_t {
    struct net_device *dev;
    int ifindex;
    int state;
};

// Event for adding to eventq. EVENT_STATE_UP says netdevice was registered
// EVENT_STATE_DOWN says the netdevice was unregistered
struct netdevice_event_t {
    int ifindex;
    int event_state;

};

BPF_HASH(pid_to_peer_netdevice_ifindex, __u64, struct netdevice_ifindex_t);

BPF_QUEUE(peer_ifindex_evtq, struct netdevice_event_t, IFIDX_QSIZE);

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

    if (pid_to_peer_netdevice_ifindex.update(&pid, &netdevice_ifindex) != 0) return ERR_MAP_UPDATE_FAIL;

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

    // Veths were newly created, peer registration will happen first. This device is PEER
    case STATE_NEWLINK:
        netdevice_ifindex->state = STATE_REGISTERING_PEER;
        netdevice_ifindex->dev = dev;
        break;
    // Peer registration has completed for veth pair, host registration now. This device is HOST
    case STATE_REGISTERING_PEER:
        netdevice_ifindex->state = STATE_REGISTERING_HOST;
        break;
    default:
        return ERR_ILLEGAL_STATE;
    }


    return 0;
}

// Before register_netdevice returns, we should have the populated netdevice. Extract the
// ifindex from it.
static int doret_trace__register_netdevice(struct pt_regs *ctx, int ret) {
    bpf_trace_printk("[CALL] doret_trace__register_netdevice");
    // If registration was unsuccessful, fail.
    // if (ret != 0) return ERR_GENERIC;

    __u64 pid = bpf_get_current_pid_tgid();

    struct netdevice_ifindex_t *netdevice_ifindex = pid_to_peer_netdevice_ifindex.lookup(&pid);
    if (netdevice_ifindex == NULL) return ERR_MAP_LOOKUP_FAIL;

    // If this registration state is not peer, remove the device from
    // map. (since this is host registration, this device has been
    // taken care of).
    if (netdevice_ifindex->state != STATE_REGISTERING_PEER) {
        pid_to_peer_netdevice_ifindex.delete(&pid);

        return 0;
    }

    bpf_trace_printk("    [INFO] netdevice is PEER");

    if (netdevice_ifindex->dev == NULL) return ERR_UNEXPECTED_NULL;

    // Set ifindex
    int ifindex = netdevice_ifindex->dev->ifindex;

    bpf_trace_printk("    [INFO] IFINDEX: %d", ifindex);

    // push to evtq
    struct netdevice_event_t netdevice_event = {
        .ifindex = ifindex, // placeholder
        .event_state = EVENT_STATE_UP,
    };

    if (peer_ifindex_evtq.push(&netdevice_event, BPF_EXIST) != 0) return ERR_MAP_UPDATE_FAIL;

    return 0;
}


// Add ifindices for devices that get unregistered to evtq
static int do_trace__unregister_netdevice_queue(struct net_device *dev) {
    bpf_trace_printk("[CALL] do_trace__unregister_netdevice_queue");
    // Verify that unregister was called by dockerd
    char comm[COMM_MAX];
    bpf_get_current_comm(comm, COMM_MAX);

    if (!bpf_strcmp_comm(comm, "dockerd\0")) return 0;

    __u64 pid = bpf_get_current_pid_tgid();

    int ifindex = dev->ifindex;

    // Verify state
    struct netdevice_ifindex_t *netdevice_ifindex = pid_to_peer_netdevice_ifindex.lookup(&pid);

    // New device, unregistering peer
    if (netdevice_ifindex == NULL) {
        bpf_trace_printk("    [INFO] : netdevice is PEER");
        struct netdevice_ifindex_t netdevice_ifindex = {
            .dev = dev,
            .ifindex = ifindex,
            .state = STATE_UNREGING_PEER,
        };

        // Push the state
        if (pid_to_peer_netdevice_ifindex.update(&pid, &netdevice_ifindex) != 0) return ERR_MAP_UPDATE_FAIL;

        bpf_trace_printk("    [INFO] IFINDEX: %d", ifindex);
        
        // push to evtq
        struct netdevice_event_t netdevice_event = {
            .ifindex = ifindex, // placeholder
            .event_state = EVENT_STATE_DOWN,
        };

        if (peer_ifindex_evtq.push(&netdevice_event, BPF_EXIST) != 0) return ERR_MAP_UPDATE_FAIL;

    } else if (netdevice_ifindex->state == STATE_UNREGING_HOST) {
        return 0;
    } else {
        return ERR_ILLEGAL_STATE;
    }

    return 0;
}


int trace__veth_newlink(struct pt_regs *ctx) {
    struct net_device *dev = (struct net_device *) PT_REGS_PARM2(ctx);

    return do_trace__veth_newlink(dev);
}

int trace__register_netdevice(struct pt_regs *ctx) {
    struct net_device *dev = (struct net_device *) PT_REGS_PARM1(ctx);

    return do_trace__register_netdevice(dev);
}

int traceret__register_netdevice(struct pt_regs *ctx) {
    int ret = PT_REGS_RET(ctx);

    return doret_trace__register_netdevice(ctx, ret);
}

int trace__unregister_netdevice_queue(struct pt_regs *ctx) {
    struct net_device *dev = (struct net_device *) PT_REGS_PARM1(ctx);

    return do_trace__unregister_netdevice_queue(dev);
}