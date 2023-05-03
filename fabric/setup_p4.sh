#!/bin/bash

ip_type=$1

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root."
  exit 1
fi

echo Hello, FABRIC. From node `hostname -s`
sudo apt-get update
sudo apt-get install -y docker.io
mkdir -p /workdir/

## We need to configure docker to use host network, so 
## we can setup TAP virtual network.
## N.B. We cannot switch TAP iface namespace after creating them,
## likely because the worker script will no longer has access to the iface.
if [ $ip_type = 'IPv4' ]
then
  git clone https://github.com/marche147/cse534 /workdir/cse534
  docker run -d -v /workdir/cse534:/workdir -it --cap-add=NET_ADMIN --privileged --network host --name fabric_p4 registry.ipv4.docker.com/pruth/fabric-images:0.0.2j
else
  sed -i '/nameserver/d' /etc/resolv.conf 
  echo nameserver 2a00:1098:2c::1 >> /etc/resolv.conf 
  echo nameserver 2a01:4f8:c2c:123f::1 >> /etc/resolv.conf 
  echo nameserver 2a00:1098:2b::1 >> /etc/resolv.conf 
  
  git clone https://github.com/marche147/cse534 /workdir/cse534
  docker run -d -v /workdir/cse534:/workdir -it --cap-add=NET_ADMIN --privileged --network host --name fabric_p4 registry.ipv6.docker.com/pruth/fabric-images:0.0.2j
fi

## Install dependencies and get TAP script
docker exec -w /root fabric_p4 pip3 install python-pytun sh scapy
docker exec -w /root fabric_p4 wget https://gist.githubusercontent.com/marche147/9ab402a694d27f3330ac70b1cecc2067/raw/b90d513e2e2ad263880cb43025f7b9300dd9de47/l2direct.py
