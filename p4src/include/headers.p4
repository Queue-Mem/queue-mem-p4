#ifndef _HEADERS_
#define _HEADERS_

#include "types.p4"

/* Chunked header sized to contain UDP */
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_0")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_1")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_2")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_3")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_4")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_5")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_6")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_7")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_8")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_9")
@pa_no_overlay("egress", "hdr.hdr_chunks.blk_10")
header hdr_chunk_h {
    bit<32> blk_0;
    bit<32> blk_1;
    bit<32> blk_2;
    bit<32> blk_3;
    bit<32> blk_4;
    bit<32> blk_5;
    bit<32> blk_6;
    bit<32> blk_7;
    bit<32> blk_8;
    bit<32> blk_9;
    bit<16> blk_10;
}

/* Additional chunks for TCP */
@pa_no_overlay("egress", "hdr.hdr_chunks_tcp.blk_11")
@pa_no_overlay("egress", "hdr.hdr_chunks_tcp.blk_12")
@pa_no_overlay("egress", "hdr.hdr_chunks_tcp.blk_13")
@pa_no_overlay("egress", "hdr.hdr_chunks_tcp.blk_14")
header hdr_chunk_tcp_h {
    bit<16> blk_11;
    bit<32> blk_12;
    bit<32> blk_13;
    bit<16> blk_14;
}

@pa_no_overlay("ingress", "meta.queuemem.hdr_idx")
@pa_no_overlay("ingress", "meta.queuemem.pkt_id")
@pa_no_overlay("ingress", "meta.queuemem.flow_ctl")
@pa_no_overlay("ingress", "meta.queuemem.pq_idx")
@pa_no_overlay("ingress", "meta.queuemem.pkt_type")
@pa_no_overlay("ingress", "meta.queuemem.next_hdr")
@pa_no_overlay("egress", "meta.queuemem.hdr_idx")
@pa_no_overlay("egress", "meta.queuemem.pkt_id")
@pa_no_overlay("egress", "meta.queuemem.flow_ctl")
@pa_no_overlay("egress", "meta.queuemem.pq_idx")
@pa_no_overlay("egress", "meta.queuemem.pkt_type")
@pa_no_overlay("egress", "meta.queuemem.next_hdr")
header queuemem_h {
    bit<32> hdr_idx;
    bit<32> pkt_id;
    bit<32> flow_ctl;
    bit<16> pq_idx;
    bit<8> pkt_type;
    queuemem_next_hdr_t next_hdr;
}

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    ipv4_protocol_t protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

@pa_no_overlay("ingress", "hdr.payload.hdr_idx")
@pa_no_overlay("ingress", "hdr.payload.pkt_id")
@pa_no_overlay("ingress", "hdr.payload.total_len")
@pa_no_overlay("ingress", "hdr.payload.pq_idx")
@pa_no_overlay("ingress", "hdr.payload.pkt_type")
@pa_no_overlay("ingress", "hdr.payload.src_mac")
@pa_no_overlay("ingress", "hdr.payload.dst_mac")
@pa_no_overlay("ingress", "hdr.payload.chksum")
@pa_no_overlay("egress", "hdr.payload.hdr_idx")
@pa_no_overlay("egress", "hdr.payload.pkt_id")
@pa_no_overlay("egress", "hdr.payload.total_len")
@pa_no_overlay("egress", "hdr.payload.pq_idx")
@pa_no_overlay("egress", "hdr.payload.pkt_type")
@pa_no_overlay("egress", "hdr.payload.src_mac")
@pa_no_overlay("egress", "hdr.payload.dst_mac")
@pa_no_overlay("egress", "hdr.payload.chksum")
header payload_h {
    bit<32> hdr_idx;
    bit<32> pkt_id;
    bit<16> total_len;
    bit<16> pq_idx;
    bit<8> pkt_type;
    mac_addr_t src_mac;
    mac_addr_t dst_mac;
    bit<16> chksum;
}

@pa_no_overlay("egress", "hdr.header_info.hdr_idx")
@pa_no_overlay("egress", "hdr.header_info.pkt_id")
@pa_no_overlay("egress", "hdr.header_info.pkt_type")
@pa_no_overlay("egress", "hdr.header_info.q_fwd")
header header_info_h {
    bit<32> hdr_idx;
    bit<32> pkt_id;
    bit<8> pkt_type;
    bit<8> q_fwd;
}

struct ingress_headers_t {
    queuemem_h queuemem;
    ethernet_h ethernet;
    payload_h payload;
    hdr_chunk_h hdr_chunks;
    hdr_chunk_tcp_h hdr_chunks_tcp;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    header_info_h header_info;
}

struct egress_headers_t {
    ethernet_h ethernet;
    payload_h payload;
    hdr_chunk_h hdr_chunks;
    hdr_chunk_tcp_h hdr_chunks_tcp;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    header_info_h header_info;
}

#endif /* _HEADERS_ */