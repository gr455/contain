from bcc import BPF, BPFAttachType, lib, BPFProgType
from time import sleep
import ipaddress
import sys
import os
import ctypes
import bcc

ATTACH = 1
DETACH = 0

EXECNAMES_COUNT_PER_IP_MAX = 10

DISALLOW_IP_HASHNAME = "blacklist_ip"
DISALLOW_EXEC_ARRAYNAME = "blacklist_execname"

filter_path = "./bpf/cgroup_sock_filter.c"

class TooManyDisallowedIPsException:
    pass

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

def getBPF():
    program = ""
    with open(filter_path, "r") as filter_file:
        program = filter_file.read()

    b = BPF(text=program)
    return b

def setDisallowHash(b, disallowDict):
    # ExecName = type(b[DISALLOW_HASH_OF_MAPS_NAME][0])
    disallowDict = createInverseDict(disallowDict)
    disallowDict = formatDict(disallowDict)

    deArray = b.get_table(DISALLOW_EXEC_ARRAYNAME)
    disallowDict = makeExecNameStructInDict(deArray.Leaf, disallowDict)

    # print(type(b[DISALLOW_IP_HASHNAME]))
    # print(disallowDict)

    ki = -1
    for k, v in disallowDict.items():
        ki += 1
        if len(v) > EXECNAMES_COUNT_PER_IP_MAX:
            raise TooManyDisallowedIPsException
        b[DISALLOW_IP_HASHNAME][ctypes.c_uint32(k)] = ctypes.c_uint32(ki)
        for vi in range(len(v)):
            idx = ki * EXECNAMES_COUNT_PER_IP_MAX + vi
            b[DISALLOW_EXEC_ARRAYNAME][ctypes.c_uint32(idx)] = v[vi]
    

def createInverseDict(disallowDict):
    inverseDict = {}
    for item in disallowDict:
        for ip in item["disallow_ips"]:
            if ip not in inverseDict.keys():
                inverseDict[ip] = []
            inverseDict[ip].append(item["process"])

    return inverseDict

def formatDict(stringIpDict):
    formattedDict = {}
    for k, v in stringIpDict.items():
        ipInt = int(ipaddress.IPv4Address(k))
        formattedDict[ipInt] = v

    return formattedDict

def makeExecNameStructInDict(ExecNameClass, disallowDict):
    def execStringToExecName(execString):
        if len(execString) > 16:
            execString = execString[:16]

        hi = int.from_bytes((bytes(execString, 'utf-8') + b"\0" * (16 - len(execString)))[:8], "little", signed = True)
        lo = int.from_bytes((bytes(execString, 'utf-8') + b"\0" * (16 - len(execString)))[8:], "little", signed = True)

        return ExecNameClass(hi, lo)

    for k, v in disallowDict.items():
        for i in range(len(disallowDict[k])):
            disallowDict[k][i] = execStringToExecName(disallowDict[k][i])

    return disallowDict

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