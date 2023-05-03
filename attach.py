from bcc import BPF, BPFAttachType, lib, BPFProgType
from time import sleep
import bcc
import sys
import os

ATTACH = 1
DETACH = 0

filter_path = "./bpf/cgroup_sock_filter.c"

# attach / detatch CGROUP_SKB program
def sock(b, cgroup2_path, attach=ATTACH):
    def detach_sock(fd, func):
        b.detach_func(func, fd, BPFAttachType.CGROUP_INET_EGRESS)

    def attach_sock(fd, func):
        b.attach_func(func, fd, BPFAttachType.CGROUP_INET_EGRESS)

    func = b.load_func("sock_filter", BPFProgType.CGROUP_SKB)
    fd = os.open(cgroup2_path, os.O_RDONLY)

    if attach: attach_sock(fd, func)
    else: detach_sock(fd, func)

# attach / detatch kprobe
def kprobe(b, attach=ATTACH):
    def detach_kpr():
        b.detach_kretprobe(event="sock_alloc_file", fn_name="kprobe_map_sockfile_pname")
    def attach_kpr():
        b.attach_kretprobe(event="sock_alloc_file", fn_name="kprobe_map_sockfile_pname")

    if attach: attach_kpr()
    else: detach_kpr()

def getBPF():
    program = ""
    with open(filter_path, "r") as filter_file:
        program = filter_file.read()

    b = BPF(text=program)
    return b

if __name__ == '__main__':
    cgroup2_base = "/sys/fs/cgroup/system.slice/"
    containerid = "24503866ce77c6ee88b51f746a07ace1dc7cefc003fbf8125f3c4e36aaf575db"
    cgroup2_path = cgroup2_base + "docker-" + containerid + ".scope"

    b = getBPF()

    # b["blacklist_exec"]

    try:
        kprobe(b)
        sock(b, cgroup2_path)

        b.trace_print()
    except KeyboardInterrupt:
        print("Detaching BPF handlers...")
        sock(b, cgroup2_path, DETACH)
        kprobe(b, DETACH)