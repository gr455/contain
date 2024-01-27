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


IP_HASHNAME = "allowlist_ip"
EXEC_ARRAYNAME = "allowlist_execname"
CIDR_ARRAYNAME = "allowlist_cidr_for_ip"
PORT_ARRAYNAME = "allowlist_port_for_ip"

filter_path = "./bpf/cgroup_sock_filter.c"


class ExecName:
    def __init__(self, execname_hi, execname_lo):
        self.execname_hi = execname_hi
        self.execname_lo = execname_lo

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

# Return a BPF object with bpf bytecode compiled from source at filter_path
def getBPF():
    program = ""
    with open(filter_path, "r") as filter_file:
        program = filter_file.read()

    b = BPF(text=program)
    return b

# Set BPF_HASH for dis
def setAllowHash(b, policyDict):
    allowlistExecname, allowlistIP, allowlistCIDRForIP, allowlistPortForIP = formatDictToArrays(policyDict)
    allowlistExecname = execnameArrayStringToObject(allowlistExecname, b['allowlist_execname'].Leaf)
    allowlistIP = ipArrayStringToInt(allowlistIP)

    # print(type(b[DISALLOW_IP_HASHNAME]))
    # print(policyDict)
    for i in range(len(allowlistExecname)):
        b[EXEC_ARRAYNAME][i] = allowlistExecname[i]
        b[IP_HASHNAME][i] = allowlistIP[i]
        b[CIDR_ARRAYNAME][i] = allowlistCIDRForIP[i]
        b[PORT_ARRAYNAME][i] = allowlistPortForIP[i]

    
# Part of formatting from policyDict -> BPF_HASH
def formatDictToArrays(policyDict):
    allowlistExecname = []
    allowlistIP = []
    allowlistCIDRForIP = []
    allowlistPortForIP = []

    for process in policyDict:
        for ipPolicy in process['allow']:
            for port in ipPolicy['ports']:
                allowlistExecname.append(process['process'])
                allowlistIP.append(ipPolicy['cidr4'].split('/')[0])
                allowlistCIDRForIP.append(ctypes.c_uint32(int(ipPolicy['cidr4'].split('/')[1])))
                allowlistPortForIP.append(ctypes.c_uint32(port))

    return (allowlistExecname, allowlistIP, allowlistCIDRForIP, allowlistPortForIP)

def ipArrayStringToInt(allowlistIP):
    for i in range(len(allowlistIP)):
        allowlistIP[i] = ctypes.c_uint32(int(ipaddress.IPv4Address(allowlistIP[i])))
    return allowlistIP

def execnameArrayStringToObject(allowlistExecname, ExecNameClass):
    for i in range(len(allowlistExecname)):
        allowlistExecname[i] = execStringToExecName(allowlistExecname[i], ExecNameClass)
    return allowlistExecname

# Convert from string to ExecNameClass type
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

    # b["allowlist_exec"]

    try:
        kprobe(b)
        sock(b, cgroup2_path)

        b.trace_print()
    except KeyboardInterrupt:
        print("Detaching BPF handlers...")
        sock(b, cgroup2_path, DETACH)
        kprobe(b, DETACH)