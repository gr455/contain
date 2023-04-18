from bcc import BPF, BPFAttachType, lib, BPFProgType
from time import sleep
import bcc
import sys
import os

ATTACH = 1
DETACH = 0

cgroup2_path = "/sys/fs/cgroup/system.slice/docker-24503866ce77c6ee88b51f746a07ace1dc7cefc003fbf8125f3c4e36aaf575db.scope"

def sock(b, attach=ATTACH):
    def detach_sock(fd, func):
        b.detach_func(func, fd, BPFAttachType.CGROUP_INET_EGRESS)

    def attach_sock(fd, func):
        b.attach_func(func, fd, BPFAttachType.CGROUP_INET_EGRESS)

    clone = b.get_syscall_fnname("clone")
    func = b.load_func("sock_filter", BPFProgType.CGROUP_SKB)
    fd = os.open(cgroup2_path, os.O_RDONLY)

    if attach: attach_sock(fd, func)
    else: detach_sock(fd, func)

def kprobe(b, attach=ATTACH):
    def detach_kpr():
        b.detach_kretprobe(event="sock_alloc_file", fn_name="kprobe_map_sockfile_pname")
    def attach_kpr():
        b.attach_kretprobe(event="sock_alloc_file", fn_name="kprobe_map_sockfile_pname")

    if attach: attach_kpr()
    else: detach_kpr()

if __name__ == '__main__':
    program = ""
    with open("ks.c", "r") as kernel_file:
        program = kernel_file.read()

    print("Verifying BPF program...")
    b = BPF(text=program)
    print("Verfication OK")

    # b["blacklist_exec"]

    try:
        kprobe(b)
        sock(b)

        b.trace_print()
    except KeyboardInterrupt:
        print("Detaching BPF handlers...")
        sock(b, DETACH)
        kprobe(b, DETACH)