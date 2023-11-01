from bcc import BPF, BPFAttachType, lib, BPFProgType
import os

ATTACH = 1
DETACH = 0

filter_path = "./bpf/ifprobe.c"

def getBPF():
	program = ""
	with open(filter_path, "r") as filter_file:
		program = filter_file.read()

	b = BPF(text=program)
	return b

def kprobe(b, attach=ATTACH):
	def detach_kpr():
		b.detach_kprobe(event="veth_newlink", fn_name="trace__veth_newlink")
		b.detach_kprobe(event="register_netdevice", fn_name="trace__register_netdevice")
		b.detach_kretprobe(event="register_netdevice", fn_name="traceret__register_netdevice")
	def attach_kpr():
		b.attach_kprobe(event="veth_newlink", fn_name="trace__veth_newlink")
		b.attach_kprobe(event="register_netdevice", fn_name="trace__register_netdevice")
		b.attach_kretprobe(event="register_netdevice", fn_name="traceret__register_netdevice")


	if attach: attach_kpr()
	else: detach_kpr()


if __name__ == '__main__':
	b = getBPF()

	try:
		kprobe(b)
		print("Attached")
		b.trace_print()

	except KeyboardInterrupt:
		print("Detaching BPF handlers...")
		kprobe(b, DETACH)