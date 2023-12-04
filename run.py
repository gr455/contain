import attach
import attach_monitor_ifprobe
import time
import docker
import subprocess

IFINDEX_EVTQ_NAME = "peer_ifindex_evtq"

IFPROBE_EVENT_STATE_DOWN = 0
IFPROBE_EVENT_STATE_UP = 1

class NonFatalExternalScriptException(Exception):
	"Raised when external script exits with a non-zero exit code non-fatally"
	pass

class CouldNotAttachBPFException(Exception):
	"Raised when there is an error while attaching BPF program"
	pass

# Returns cgroup2 path for docker container with container_id
def get_cgroup2_path(container_id):
	cgroup2_base = "/sys/fs/cgroup/system.slice/"
	cgroup2_path = cgroup2_base + "docker-" + container_id + ".scope"

	return cgroup2_path

glob_cid_to_bpf_obj_map = {}

# Attaches ifprobes to track new containers through ifindexes in upq
def do_attach_monitor_ifprobe(ifprobe_bpf):
	if ifprobe_bpf == None:
		ifprobe_bpf = attach_monitor_ifprobe.getBPF()

	attach_monitor_ifprobe.kprobe(ifprobe_bpf)

	return ifprobe_bpf

# Detatches ifprobes
def do_detach_monitor_ifprobe(ifprobe_bpf):
	if ifprobe_bpf == None: return None

	attach_monitor_ifprobe.kprobe(ifprobe_bpf, attach_monitor_ifprobe.DETACH)
	
	return ifprobe_bpf

def check_ignore_container(container_id):
	return False

def get_ifindex_for_container(container_id):
	# Call shell script to do exactly that
	# print("CID", container_id, type(container_id))
	proc = subprocess.Popen(["./scripts/dockerveth.sh", container_id], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	op, err = proc.communicate()

	if proc.returncode != 0:
		raise NonFatalExternalScriptException(proc.communicate()[1])

	return op

def get_container_id_for_ifindex(ifindex):
	# Get all running containers
	client = docker.from_env()

	container_ids = [container.id for container in client.containers.list(all = True)]

	for cid in container_ids:
		try:
			this_ifindex = int(get_ifindex_for_container(cid))
			if this_ifindex == ifindex:
				return cid
		except NonFatalExternalScriptException:
			pass
		except Exception as e:
			print(f"Exception: {e}")
			continue

	return None

def attach_sock_filter_or_not(ifindex):
	container_id = get_container_id_for_ifindex(ifindex)

	# If container not in the policy, ignore
	if check_ignore_container(container_id):
		return

	
	container_cgroup2_path = get_cgroup2_path(container_id)
	bpf = attach.getBPF()

	glob_cid_to_bpf_obj_map[container_id] = bpf

	try:
		attach.kprobe(bpf)
		attach.sock(bpf, container_cgroup2_path)
	except:
		CouldNotAttachBPFException("could not attach BPF programs")
		return

def detach_sock_filter(ifindex):
	container_id = get_container_id_for_ifindex(ifindex)

	container_cgroup2_path = get_cgroup2_path(container_id)
	bpf = attach.getBPF()

	try:
		attach.sock(bpf, container_cgroup2_path, attach.DETACH)
	except:
		CouldNotAttachBPFException("could not detach sock, maybe sock is not attached for this cgroup2 path")
		return

# Listens for any new entries in the event queue
# For EVENT_STATE_UP, attaches filter to the container
# conditionally. For EVENT_STATE_DOWN detaches filter.
def listenForEvt(ifprobe_bpf):
	while True:
		evt = None
		try:
			evt = ifprobe_bpf[IFINDEX_EVTQ_NAME].pop()
			# print(evt.ifindex, evt.event_state)
		except KeyError:
			# yield cpu
			time.sleep(0.0001)
			continue

		if evt.event_state == IFPROBE_EVENT_STATE_UP:
			attach_sock_filter_or_not(evt.ifindex)

		else:
			detach_sock_filter(evt.ifindex)


if __name__ == '__main__':
	try:
		b = do_attach_monitor_ifprobe(None)
		listenForEvt(b)
	except KeyboardInterrupt:
		print("Detaching ifprobe monitor")
		do_detach_monitor_ifprobe(b)
