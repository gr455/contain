# Egress Cgroup Socket Filter
BPF based per-process per-container egress filter

## Run
### Docker

Attach BPF handlers
```
python3 docker_filter.py -n <container_name> attach
```
Detach BPF handlers
```
python3 docker_filter.py -n <container_name> detach
```

This BPF filter uses `BPF_PROG_TYPE_CGROUP_SKB` and a kretprobe to kernel function `net/socket.c/sock_alloc_file` for per-process, per-container socket filtering

Tested on Linux 5.19.0-40-generic
