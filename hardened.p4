/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CPU_PORT 255
#define BCAST_IDX 0x10

// Ethernet type enum: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;

// IP protocol enum: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const bit<8>    PROTO_UDP   = 17;

// UDP Ports
const bit<16> UDP_DHCP_SERVER = 67;
const bit<16> UDP_DHCP_CLIENT = 68;

// ARP operations
const bit<16>   ARP_REQEUST     = 1;
const bit<16>   ARP_REPLY       = 2;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/



typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    macAddr_t   srcHAddr;
    ip4Addr_t   srcPAddr;
    macAddr_t   tgtHAddr;
    ip4Addr_t   tgtPAddr;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16>  srcPort;
    bit<16>  dstPort;
    bit<16>  len;
    bit<16>  hdrChecksum;
}

// http://www.tcpipguide.com/free/t_BOOTPMessageFormat.htm
header bootp_t {
    bit<8>  op;
    bit<8>  htype;
    bit<8>  hlen;
    bit<8>  hops;
    bit<32> xid;
    bit<16> secs;
    bit<16> flags;
    ip4Addr_t CIAddr;
    ip4Addr_t YIAddr;
    ip4Addr_t SIAddr;
    ip4Addr_t GIAddr;
    bit<128>  CHAddr;
    bit<512>  sname;
    bit<1024> file;
    bit<512>  vend;
}

struct metadata {
    /* empty */
}

@controller_header("packet_in")
header packet_in_metadata_t {
    bit<16> ingress_port;
}

@controller_header("packet_out")
header packet_out_metadata_t {
    bit<16> egress_port;
    bit<16> mcast_grp; 
}

struct headers {
    packet_in_metadata_t packet_in;
    packet_out_metadata_t packet_out;

    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    udp_t        udp;
    bootp_t      bootp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.srcPort) {
            UDP_DHCP_CLIENT: parse_dhcp;
            UDP_DHCP_SERVER: parse_dhcp;
            default: accept;
        }
    }

    state parse_dhcp {
        packet.extract(hdr.bootp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ethernet_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action ipv4_forward(macAddr_t dstHAddr) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstHAddr;
    }

    action ethernet_broadcast() {
        standard_metadata.mcast_grp = (bit<16>)(standard_metadata.ingress_port + BCAST_IDX);    // send to all hosts except itself
    }

    action send_to_cpu() {
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
        standard_metadata.egress_spec = CPU_PORT;
    }

    // Ethernet to Port mapping
    table ethernet_exact {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            ethernet_forward;
            ethernet_broadcast;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // IPv4 to Ethernet mapping
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            // ipv4_broadcast; 
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        // From data plane
        if(standard_metadata.ingress_port != CPU_PORT) {
            if(hdr.bootp.isValid() || hdr.arp.isValid()) {   // DHCP Snooping & ARP Mitigation
                send_to_cpu();
            } else {    // Forward other packets
                if(hdr.ipv4.isValid()) {
                    ipv4_lpm.apply();
                }
                if(hdr.ethernet.isValid()) {
                    ethernet_exact.apply();
                }
            }
        } else {    // From control plane
            if(hdr.packet_out.egress_port == 0 && hdr.packet_out.mcast_grp == 0) {
                if(hdr.ethernet.isValid()) {
                    ethernet_exact.apply();
                }
            } else if(hdr.packet_out.mcast_grp != 0) {
                standard_metadata.mcast_grp = hdr.packet_out.mcast_grp;
            } else if(hdr.packet_out.egress_port != 0) {
                standard_metadata.egress_port = (egressSpec_t)hdr.packet_out.egress_port;
            }
        } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.bootp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
