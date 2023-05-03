#!/usr/bin/env python3
import argparse
import os
import sys
import json 
from time import sleep

###################################################################
## Flags
###################################################################

CHECK_ARP = True
MININET = False

if not MININET:
    # Fix for ModuleNotFound problem in docker
    sys.path.insert(0, "/usr/lib/python3/dist-packages")

from p4.v1 import p4runtime_pb2
import grpc

from scapy.all import Ether, ARP, IP, UDP, BOOTP, DHCP
import struct

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

ETHERNET_BROADCAST = "FF:FF:FF:FF:FF:FF"
SW_MAC = "08:00:00:00:01:00"    # MAC of switch
SW_IP  = "10.0.1.1"             # IP of switch
IP_MAC_MAPPING = {}             # DHCP Snooping
SUBNET_TEMPLATE = "10.0.1.{}"
NEXTHOP_SWITCHES = []
BCAST_IDX, PORTS = 0x10, 4                # broadcast to all hosts except the sender
DISCOVERED_ETHERNET = {}

###################################################################
## Util functions
###################################################################

u8 = lambda x: struct.unpack(">B", x)[0]
p8 = lambda x: struct.pack(">B", x)
u16 = lambda x: struct.unpack(">H", x)[0]
p16 = lambda x: struct.pack(">H", x)

def ethernet_str_to_bytes(addr):
    nums = list(map(lambda x: int(x, 16), addr.split(':')))
    assert len(nums) == 6
    return struct.pack("<6B", *nums)

def ethernet_bytes_to_str(bytes):
    assert len(bytes) == 6
    return ':'.join(map(lambda x: "%02X", bytes))

###################################################################
## PacketIn and PacketOut messages are from stream
## Protobuf specification of these messages: https://p4.org/p4-spec/p4runtime/main/P4Runtime-Spec.html#sec-packet-i_o
###################################################################
def packetIn(sw):
    for response in sw.stream_msg_resp:
        return response

def packetOut(sw, packet):
    request = p4runtime_pb2.StreamMessageRequest()
    request.packet.CopyFrom(packet)
    sw.requests_stream.put(request)
    return request

def buildPacketOut(payload, metadata={}):
    packet = p4runtime_pb2.PacketOut()
    packet.payload = payload
    for key in metadata.keys():
        md = packet.metadata.add()
        md.metadata_id = key
        md.value = metadata[key]
    return packet

###################################################################
## Switch table Read/Write helpers
###################################################################

def insert_multicast_entry(sw, p4info_helper, mc_group_id, replicas):
    mc_entry = p4info_helper.buildMulticastGroupEntry(mc_group_id, replicas)
    sw.WritePREEntry(mc_entry)

def insert_ethernet_exact_entry(sw, p4info_helper, match, action, action_param):
    table_entry = p4info_helper.buildTableEntry(
        "MyIngress.ethernet_exact",
        match_fields=match,
        default_action=False,
        action_name=action,
        action_params=action_param,
    )
    sw.WriteTableEntry(table_entry)

def insert_ethernet_exact_default_action(sw, p4info_helper):
    table_entry = p4info_helper.buildTableEntry(
        "MyIngress.ethernet_exact",
        default_action=True,
        action_name="MyIngress.drop",
        action_params={},
    )
    sw.WriteTableEntry(table_entry)

###################################################################
## Control plane packet handlers
###################################################################

def buildDHCPResponse(xid, smac, dmac, sip, dip, options):
    ether = Ether(src=smac, dst=dmac)
    ip = IP(src=sip, dst=dip)
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, xid=xid, chaddr=ethernet_str_to_bytes(dmac), ciaddr=dip, yiaddr=dip, siaddr=sip, giaddr=sip)
    dhcp = DHCP(options=options)
    return ether / ip / udp / bootp / dhcp

# discover is the DHCP discover packet
# sip <- dhcp server & gw
def buildDHCPOffer(discover, smac, dmac, sip, dip):
    options = [
        ('subnet_mask', '255.255.255.0'),
        ('lease_time', 43200),
        ('router', sip),
        ('server_id', sip),
        ('message-type', 'offer'),
        ('end')
        ] 
    return buildDHCPResponse(discover.getlayer(BOOTP).xid, smac, dmac, sip, dip, options)

def buildDHCPAck(request, smac, dmac, sip, dip):
    options = [
        ('subnet_mask', '255.255.255.0'), 
        ('lease_time', 43200),
        ('router', sip),
        ('server_id', sip),
        ('message-type', 'ack'),
        ('end')
    ]
    return buildDHCPResponse(request.getlayer(BOOTP).xid, smac, dmac, sip, dip, options) 

def allocate_subnet():
    for i in range(256):
        if i == 0 or i == 1: continue 
        addr = SUBNET_TEMPLATE.format(i)
        if not addr in IP_MAC_MAPPING:
            return addr
    return None

def register_mapping(addr, mac):
    IP_MAC_MAPPING[addr] = mac.upper()

def send_dhcp_offer(sw, pkt):
    offer_ip = allocate_subnet()
    offer = buildDHCPOffer(pkt, SW_MAC, pkt.src, SW_IP, offer_ip)
    response = buildPacketOut(bytes(offer), {
        1: b'\x00\x00',
        2: b'\x00\x00',
    })
    packetOut(sw, response)
    return offer_ip

def send_dhcp_ack(sw, pkt, requested_ip):
    ack = buildDHCPAck(pkt, SW_MAC, pkt.src, SW_IP, requested_ip)
    response = buildPacketOut(bytes(ack), {
        1: b'\x00\x00',
        2: b'\x00\x00'
    })
    packetOut(sw, response)
    return 

## Handle DHCP discover and request
def handleDHCP(p4info_helper, sw, pkt):
    # check if packet valid, should have UDP source 68, dest 67
    # bootp.op = 1
    udp = pkt.getlayer(UDP)
    if udp.sport != 68 or udp.dport != 67:
        return True
    bootp = pkt.getlayer(BOOTP)
    if bootp.op != 1:
        return True

    dhcp = pkt.getlayer(DHCP)
    hwAddr = pkt.src

    def get_option(options, name):
        for option in options:
            if isinstance(option, tuple):
                if option[0] == name:
                    return option[1]
        return None

    # https://github.com/secdev/scapy/blob/master/scapy/layers/dhcp.py
    message_type = get_option(dhcp.options, 'message-type')
    if message_type == 1:   # DISCOVER
        print("-- DHCP Discover")
        send_dhcp_offer(sw, pkt)
    elif message_type == 3:     # REQUEST
        requested_ip = get_option(dhcp.options, 'requested_addr')
        print("-- DHCP Request: ", requested_ip)
        if not requested_ip in IP_MAC_MAPPING:
            register_mapping(requested_ip, pkt.src)
            send_dhcp_ack(sw, pkt, requested_ip)
        else:
            if IP_MAC_MAPPING[requested_ip] != pkt.src:
                send_dhcp_offer(sw, pkt)
            else:
                send_dhcp_ack(sw, pkt, requested_ip)

    return True

def relay_packet(sw, pkt, ingress_port):
    # need special handling for broadcasting
    mcast_grp = 0
    if pkt.dst.upper() == ETHERNET_BROADCAST:
        mcast_grp = ingress_port + BCAST_IDX

    response = buildPacketOut(bytes(pkt), {
        1: p16(0),
        2: p16(mcast_grp),
    })
    packetOut(sw, response)
    return 

def buildARPReply(request, smac, hwdst):
    ether = Ether(src=smac, dst=request.getlayer(Ether).src)
    arp = ARP(hwtype=1, 
              ptype=2048, 
              op=2, 
              hwsrc=hwdst,
              psrc=request.getlayer(ARP).pdst,
              hwdst=request.getlayer(ARP).hwsrc,
              pdst=request.getlayer(ARP).psrc,
    )
    return ether / arp

## Handle ARP request and reply
def handleARP(p4info_helper, sw, pkt, ingress_port):
    arp = pkt.getlayer(ARP)

    if arp.op == 1:     # ARP who-has
        if arp.pdst == SW_IP:   # query switch HWAddr
            print("-- ARP Request of switch MAC")
            reply = buildARPReply(pkt, SW_MAC, SW_MAC)
            print(reply)
            pb = buildPacketOut(bytes(reply), {
                1: b'\x00\x00',
                2: b'\x00\x00',
            })
            packetOut(sw, pb)
        else:
            relay_packet(sw, pkt, ingress_port)
    else:
        if CHECK_ARP and arp.psrc in IP_MAC_MAPPING:
            mac = IP_MAC_MAPPING[arp.psrc]
            if mac != arp.hwsrc.upper():
                print("!! Invalid IP-to-MAC mapping in ARP reply")
                return True
        relay_packet(sw, pkt, ingress_port)
    return True

def ethernet_discover(sw, p4info_helper, src, inport):
    if not src in DISCOVERED_ETHERNET:
        print("** Discovered new host: %s at port %d" % (src, inport))
        insert_ethernet_exact_entry(sw, p4info_helper, { "hdr.ethernet.dstAddr": src }, "MyIngress.ethernet_forward", { "port": inport, })
        DISCOVERED_ETHERNET[src] = inport 
    return 

# PacketIn handler
def on_PacketIn(p4info_helper, sw, packet):
    pkt = Ether(packet.payload)
    inport = u8(packet.metadata[0].value)

    src = pkt.src.upper()
    ethernet_discover(sw, p4info_helper, src, inport) 

    if DHCP in pkt:      # Ether / IP / UDP / BOOTP / DHCP Discover
        return handleDHCP(p4info_helper, sw, pkt)
    elif ARP in pkt:
        return handleARP(p4info_helper, sw, pkt, inport)
    return True

###################################################################
## P4 Control plane interfaces
###################################################################

# Connect controller to switch 
def connect_switch(name, index, p4info_helper, bmv2_file_path):
    conn = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name=name,
        address="127.0.0.1:%d" % (50051+index),
        device_id=index,
        proto_dump_file="logs/controller.log"
    )
    conn.MasterArbitrationUpdate()  # Set ourself to master controller
    conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
    return conn 

def initialize_ethernet_table(sw, p4info_helper):
    insert_ethernet_exact_default_action(sw, p4info_helper)
    if MININET:
        ethernet_discover(sw, p4info_helper, "08:00:00:00:01:11", 1)
        ethernet_discover(sw, p4info_helper, "08:00:00:00:02:22", 2)
        ethernet_discover(sw, p4info_helper, "08:00:00:00:05:55", 4)
    insert_ethernet_exact_entry(sw, p4info_helper, { "hdr.ethernet.dstAddr": ETHERNET_BROADCAST }, "MyIngress.ethernet_broadcast", {})

def initialize_multicast_table(sw, p4info_helper):
    replicas = [
        { 'egress_port': 1, 'instance': 1 }, 
        { 'egress_port': 2, 'instance': 1 },
        { 'egress_port': 3, 'instance': 1 }, 
        { 'egress_port': 4, 'instance': 1 },
    ]
    insert_multicast_entry(sw, p4info_helper, 1, replicas)  # mcast_grp 1 is broadcast to every port

def initialize_broadcast_table(sw, p4info_helper):
    for i in range(1, PORTS + 1):
        replicas = []
        for j in range(1, PORTS + 1):
            if i == j: continue 
            replicas.append({ 'egress_port': j, 'instance': 1 })
        insert_multicast_entry(sw, p4info_helper, BCAST_IDX + i, replicas)


def initialize_multicast_for_switch(sw, p4info_helper, srcname, topo):
    links = topo['links']
    replicas = []
    for link in links:
        if link[0].startswith(srcname):
            portname = link[0].split('-')[1]
            port = int(portname[1:])
            NEXTHOP_SWITCHES.append(port)
            replicas.append({ 'egress_port': port, 'instance': 1 })
    insert_multicast_entry(sw, p4info_helper, 2, replicas)  # mcast_grp 2 is broadcast to every connected switch

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    topology = json.loads(open("./topo/topology.json").read())

    try:
        conn = connect_switch('s1', 0, p4info_helper, bmv2_file_path)
        initialize_ethernet_table(conn, p4info_helper)
        initialize_multicast_table(conn, p4info_helper)
        initialize_multicast_for_switch(conn, p4info_helper, 's1', topology)
        initialize_broadcast_table(conn, p4info_helper)

        # handle PacketIn from switch
        while True:
            pkt = packetIn(conn)
            if not on_PacketIn(p4info_helper, conn, pkt.packet):
                break
    except KeyboardInterrupt:
        print("- Interrupted.")
    except grpc.RpcError as e:
        printGrpcError(e)

    print("- Shutting down...")
    ShutdownAllSwitchConnections()
    return 0

if __name__ == '__main__':
    p4info_file_path = os.path.join(os.getcwd(), "build/hardened.p4.p4info.txt")
    bmv2_file_path = os.path.join(os.getcwd(), "build/hardened.json")
    sys.exit(main(p4info_file_path, bmv2_file_path))
