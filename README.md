# Egress Cgroup Socket Filter
BPF based per-process per-container egress filter

## Run
### Docker

Attach BPF handlers
```
python3 docker_filter.py -n <container_name> attach <blacklist.json_location>
```
Detach BPF handlers
```
python3 docker_filter.py -n <container_name> detach <blacklist.json_location>
```

#### Example
The blacklist file
```json
[
	{
		"process": "curl",
		"disallow": [
			{
				"cidr4": "1.1.1.0/24",
				"ports": [80, 443]
			}
		]
	}

]
```

Gives

![Result](images/example.png)

This BPF filter uses `BPF_PROG_TYPE_CGROUP_SKB` and a kretprobe to kernel function `net/socket/sock_alloc_file` for per-process, per-container socket filtering

Tested on Linux 5.19.0-40-generic
