import attach.attach as attach
import attach.attach_monitor_ifprobe as attach_monitor_ifprobe
import time
import json
import docker
import subprocess

IFINDEX_EVTQ_NAME = "peer_ifindex_evtq"
DOCKERVETH_SCRIPT_PATH = "./scripts/dockerveth.sh"

IFPROBE_EVENT_STATE_DOWN = 0
IFPROBE_EVENT_STATE_UP = 1

glob_container_name_to_policy_map = {}

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

# Maps container id to bpf object
glob_cid_to_bpf_obj_map = {}
# Maps ifindex to container id, name. Required for detaching since then the container is not running 
# and so, ifindex does not exist in kernel
glob_ifindex_to_cid_map = {}

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

# TODO: smart get policy for k8s, maybe substring?
def get_policy(container_id, container_name):
	if container_name not in glob_container_name_to_policy_map:
		return None

	print(f"SETTING POLICY FOR {container_name} : ", glob_container_name_to_policy_map[container_name])
	return glob_container_name_to_policy_map[container_name]

# Returns ifindex of container's veth's netdevice
def get_ifindex_for_container(container_id):
	# Call shell script to do exactly that
	# print("CID", container_id, type(container_id))
	proc = subprocess.Popen([DOCKERVETH_SCRIPT_PATH, container_id], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	op, err = proc.communicate()

	if proc.returncode != 0:
		raise NonFatalExternalScriptException(proc.communicate()[1])

	return op

# Gets container given ifindex of veth's netdevice
def get_container_id_and_name_for_ifindex(ifindex):
	# If ifindex is cached, return it
	if ifindex in glob_ifindex_to_cid_map.keys():
		return glob_ifindex_to_cid_map[ifindex]

	# Get all running containers
	client = docker.from_env()

	container_names_ids = [(container.id, container.name) for container in client.containers.list(all = True)]

	for cid, cname in container_names_ids:
		try:
			this_ifindex = int(get_ifindex_for_container(cid))
			if this_ifindex == ifindex:
				# Cache and return
				glob_ifindex_to_cid_map[ifindex] = (cid, cname)
				return (cid, cname)
		except NonFatalExternalScriptException:
			pass
		except Exception as e:
			print(f"Exception: {e}")
			continue

	return (None, None)

# Attach socket filter to cgroup of container with veth device ifindex if the container
# policy is available. Else ignore.
def attach_sock_filter_or_not(ifindex):
	container_id, container_name = get_container_id_and_name_for_ifindex(ifindex)

	container_policy = get_policy(container_id, container_name)
	
	# If container does not have any policies, return	
	if container_policy == None:
		return
	
	container_cgroup2_path = get_cgroup2_path(container_id)

	bpf = attach.getBPF()
	attach.setAllowHash(bpf, container_policy)
	glob_cid_to_bpf_obj_map[container_id] = bpf

	print(f"attaching bpf for {container_id}")

	try:
		attach.kprobe(bpf)
		attach.sock(bpf, container_cgroup2_path)
		bpf.trace_print()
	except:
		CouldNotAttachBPFException("could not attach BPF programs")
		return

# Detach socket filter
def detach_sock_filter(ifindex):
	container_id, container_name = get_container_id_and_name_for_ifindex(ifindex)

	# If no bpf was attached to this container, return
	if container_id == None or container_id not in glob_cid_to_bpf_obj_map.keys():
		return

	print(f"detaching bpf for {container_id}")

	container_cgroup2_path = get_cgroup2_path(container_id)
	bpf = glob_cid_to_bpf_obj_map[container_id]

	try:
		attach.sock(bpf, container_cgroup2_path, attach.DETACH)
	except:
		pass
	
	try:
		attach.kprobe(bpf, attach.DETACH)
	except:
		pass

	# The container has stopped, remove the cache entries
	del glob_ifindex_to_cid_map[ifindex]
	del glob_cid_to_bpf_obj_map[container_id]

# Listens for any new entries in the event queue
# For EVENT_STATE_UP, attaches filter to the container
# conditionally. For EVENT_STATE_DOWN detaches filter.
def listen_for_evt(ifprobe_bpf):
	while True:
		evt = None
		try:
			evt = ifprobe_bpf[IFINDEX_EVTQ_NAME].pop()
		except KeyError:
			# yield cpu
			time.sleep(0.0001)
			continue

		if evt.event_state == IFPROBE_EVENT_STATE_UP:
			attach_sock_filter_or_not(evt.ifindex)

		else:
			detach_sock_filter(evt.ifindex)


# Read policy file and return map of container->policy
def read_policy_file(filepath):
	all_policies = None
	policy_map = {}

	with open(filepath, "r") as policy_file:
		all_policies = json.load(policy_file)
	

	for container_policies in all_policies:
		container_name = container_policies["container_name"]
		policy_map[container_name] = container_policies["policy"]

	return policy_map


if __name__ == '__main__':
	b = None
	try:
		b = do_attach_monitor_ifprobe(None)
		glob_container_name_to_policy_map = read_policy_file("allowlist.json")
		print("Attached.")
		listen_for_evt(b)

	except KeyboardInterrupt:
		print("Detaching ifprobe monitor")
		if b != None: do_detach_monitor_ifprobe(b)
