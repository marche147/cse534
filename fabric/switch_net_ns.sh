#!/bin/bash

ifaces="${@:1}"
NSPID=$(docker inspect --format='{{ .State.Pid }}' fabric_p4)

## Attach network interface into docker's network namespace
for iface in $ifaces; do
  ip link set dev $iface promisc on
  ip link set $iface netns $NSPID
  docker exec fabric_p4 ip link set dev $iface up
  docker exec fabric_p4 ip link set dev $iface promisc on
  docker exec fabric_p4 sysctl net.ipv6.conf.${iface}.disable_ipv6=1
done

