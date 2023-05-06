from bcc import BPF, BPFAttachType, lib, BPFProgType
from time import sleep
import ipaddress
import sys
import os
import ctypes
import bcc

ATTACH = 1
DETACH = 0

PROC_EXECNAME_MAX = 16
EXECNAMES_COUNT_MAX = 10
IP_COUNT_PER_EXECNAME_MAX = 10
PORT_COUNT_PER_IP_MAX = 5
TOTSIZE = ( EXECNAMES_COUNT_MAX * IP_COUNT_PER_EXECNAME_MAX * PORT_COUNT_PER_IP_MAX )


IP_HASHNAME = "blacklist_ip"
EXEC_ARRAYNAME = "blacklist_execname"
CIDR_ARRAYNAME = "blacklist_cidr_for_ip"
PORT_ARRAYNAME = "blacklist_port_for_ip"

filter_path = "./bpf/cgroup_sock_filter.c"


class ExecName:
    def __init__(self, execname_hi, execname_lo):
        self.execname_hi = execname_hi
        self.execname_lo = execname_lo

# attach / detatch CGROUP_SKB program
def sock(b, cgroup2_path, attach=ATTACH):
    def detach_sock(fd, func):
        b.detach_func(func, fd, BPFAttachType.CGROUP_INET_EGRESS)
        b.detach_func(func, fd, BPFAttachType.CGROUP_INET_INGRESS)

    def attach_sock(fd, func):
        b.attach_func(func, fd, BPFAttachType.CGROUP_INET_EGRESS)
        b.attach_func(func, fd, BPFAttachType.CGROUP_INET_INGRESS)

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

def setDisallowHash(b, policyDict):
    blacklistExecname, blacklistIP, blacklistCIDRForIP, blacklistPortForIP = formatDictToArrays(policyDict)
    blacklistExecname = execnameArrayStringToObject(blacklistExecname, b['blacklist_execname'].Leaf)
    blacklistIP = ipArrayStringToInt(blacklistIP)

    # print(type(b[DISALLOW_IP_HASHNAME]))
    # print(policyDict)
    for i in range(len(blacklistExecname)):
        b[EXEC_ARRAYNAME][i] = blacklistExecname[i]
        b[IP_HASHNAME][i] = blacklistIP[i]
        b[CIDR_ARRAYNAME][i] = blacklistCIDRForIP[i]
        b[PORT_ARRAYNAME][i] = blacklistPortForIP[i]

    

def formatDictToArrays(policyDict):
    blacklistExecname = []
    blacklistIP = []
    blacklistCIDRForIP = []
    blacklistPortForIP = []

    for process in policyDict:
        for ipPolicy in process['disallow']:
            for port in ipPolicy['ports']:
                blacklistExecname.append(process['process'])
                blacklistIP.append(ipPolicy['cidr4'].split('/')[0])
                blacklistCIDRForIP.append(ctypes.c_uint32(int(ipPolicy['cidr4'].split('/')[1])))
                blacklistPortForIP.append(ctypes.c_uint32(port))

    return (blacklistExecname, blacklistIP, blacklistCIDRForIP, blacklistPortForIP)

def ipArrayStringToInt(blacklistIP):
    for i in range(len(blacklistIP)):
        blacklistIP[i] = ctypes.c_uint32(int(ipaddress.IPv4Address(blacklistIP[i])))
    return blacklistIP

def execnameArrayStringToObject(blacklistExecname, ExecNameClass):
    for i in range(len(blacklistExecname)):
        blacklistExecname[i] = execStringToExecName(blacklistExecname[i], ExecNameClass)
    return blacklistExecname

def execStringToExecName(execString, ExecNameClass):
    if len(execString) > 16:
        execString = execString[:16]

    hi = int.from_bytes((bytes(execString, 'utf-8') + b"\0" * (16 - len(execString)))[:8], "little", signed = True)
    lo = int.from_bytes((bytes(execString, 'utf-8') + b"\0" * (16 - len(execString)))[8:], "little", signed = True)

    return ExecNameClass(hi, lo)


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