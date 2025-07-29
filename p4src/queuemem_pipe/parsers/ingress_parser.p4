#ifndef _INGRESS_PARSER_
#define _INGRESS_PARSER_

#include "../../include/configuration.p4"

parser IngressParser(packet_in pkt, out ingress_headers_t hdr,
                     out ingress_metadata_t meta, out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.first_frag = 0;
        meta.l4_lookup = {0, 0};
        transition select(ig_intr_md.ingress_port) {
            RECIRCULATION_PORT_PIPE2: parse_queuemem;
            RECIRCULATION_PORT_PIPE3: parse_queuemem;
            NF_PORT_PIPE2: check_if_split;
            NF_PORT_PIPE3: check_if_split;
            default: parse_ethernet;
        }
    }

    state parse_queuemem {
        pkt.extract(meta.queuemem);
        transition parse_ethernet;
    }

    state check_if_split {
        bit<96> dst_src_mac = pkt.lookahead<bit<96>>();

        /* Bit 15-0 (of src) is the pq_idx */
        meta.pq_idx = dst_src_mac[15:0];
        /* Bit 7-0 (of dst) == 1 if we split the packet */
        meta.is_split = dst_src_mac[55:48];
        /* Bit 39-8 (of dst) are the adv_flow_ctl */
        meta.flow_ctl = dst_src_mac[87:56];

        /* Split in chunks only if it was originally split */
        transition select(meta.is_split) {
            0x1: parse_chunks;
            default: accept;
        }
    }

    state parse_chunks {
        pkt.extract(hdr.hdr_chunks);
        transition select(hdr.hdr_chunks.blk_5[7:0]) {
            ipv4_protocol_t.UDP: parse_header_info;
            ipv4_protocol_t.TCP: parse_chunks_tcp;
            default: reject;
        }
    }

    state parse_chunks_tcp {
        pkt.extract(hdr.hdr_chunks_tcp);
        transition parse_header_info;
    }

    state parse_header_info {
        pkt.extract(hdr.header_info);
        transition accept;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            (0, ipv4_protocol_t.TCP): parse_tcp;
            (0, ipv4_protocol_t.UDP): parse_udp;
            default: dont_split;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.l4_lookup = {hdr.tcp.src_port, hdr.tcp.dst_port};
        transition parse_first_fragment;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.l4_lookup = {hdr.udp.src_port, hdr.udp.dst_port};
        transition parse_first_fragment;
    }
    
    state parse_first_fragment {
        meta.first_frag = 1;
        transition check_ip_len;
    }

    state check_ip_len {
        transition select(hdr.ipv4.total_len) {
            #if SPLIT==64
                0x003F &&& 0xFFC0: dont_split; // <= 63
                0x0040: dont_split; // == 64
            #elif SPLIT==128
                0x007F &&& 0xFF80: dont_split; // <= 127
                0x0080: dont_split; // == 128
            #elif SPLIT==256
                0x00FF &&& 0xFF00: dont_split; // <= 255
                0x0100: dont_split; // == 256
            #elif SPLIT==512
                0x01FF &&& 0xFE00: dont_split; // <= 511
                0x0200: dont_split; // == 512
            #elif SPLIT==1024
                0x03FF &&& 0xFC00: dont_split; // <= 1023
                0x0400: dont_split; // == 1024
            #endif
            default: split;
        }
    }

    state dont_split {
        meta.to_split = 0x0;
        transition accept;
    }

    state split {
        meta.to_split = 0x1;
        transition accept;
    }
}

control IngressDeparser(packet_out pkt, inout ingress_headers_t hdr,
                        in ingress_metadata_t meta,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Checksum() ipv4_checksum_ig;
    Mirror(TRUNCATE_MIRROR_TYPE) mirror;

    apply {
        if (meta.to_split == 0) {
            hdr.ipv4.hdr_checksum = ipv4_checksum_ig.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        } 

        if (ig_dprsr_md.mirror_type == TRUNCATE_MIRROR_TYPE) {
            mirror.emit<queuemem_h>(meta.mirror_session, {
                meta.queuemem.hdr_idx,
                meta.queuemem.pkt_id,
                meta.queuemem.flow_ctl,
                meta.queuemem.pq_idx,
                meta.queuemem.pkt_type,
                meta.queuemem.next_hdr
            });
        }

        pkt.emit(hdr);
    }
}

#endif /* _INGRESS_PARSER_ */