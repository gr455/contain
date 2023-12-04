#!/bin/sh

# Copyright (c) 2017 Micah Culpepper
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Sourced from https://github.com/micahculpepper/dockerveth/blob/master/dockerveth.sh
#

####################
# DEFINE FUNCTIONS #
####################

usage () {
    printf %s \
"dockerveth.sh - Get container ifindex by container id

Usage: dockerveth.sh <container_id> | [-h, --help]

Options:
    -h, --help          Show this help and exit.

Output:
    ifindex of the container with container_id
"
}


get_container_if_index () {
    # Get the index number of a docker container's first veth interface (typically eth0)
    # Input: the container ID
    # Output: The index number, like "42"
    c_pid=$(get_pid "$1")

    if [ $c_pid -eq 0 ]; then
        return 1
    fi

    ip_netns_export "$c_pid"
    ils=$(ip netns exec "ns-${c_pid}" ip link show type veth)
    printf "${ils%%:*}"
}

ip_netns_export () {
    # Make a docker container's networking info available to `ip netns`
    # Input: the container's PID
    # Output: None (besides return code), but performs the set-up so that `ip netns` commands
    # can access this container's namespace.
    if [ ! -d /var/run/netns ]; then
        mkdir -p /var/run/netns
    fi
    ln  -sf "/proc/${1}/ns/net" "/var/run/netns/ns-${1}"
}

get_pid () {
    # Get the PID of a docker container
    # Input: the container ID
    # Output: The PID, like "2499"
    docker inspect --format '{{.State.Pid}}' "$1"
}



######################
# PARSE COMMAND LINE #
######################

case "$1" in
    -h|--help)
    usage
    exit 0
    ;;
    *)
    ;;
esac


##################
# EXECUTE SCRIPT #
##################

set -e
container_ifindex=$(get_container_if_index "$@")

printf "${container_ifindex}"
exit 0