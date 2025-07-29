#ifndef _EGRESS_PARSER_
#define _EGRESS_PARSER_

#include "../../include/configuration.p4"

parser EgressParser(packet_in pkt, out egress_headers_t hdr, out egress_metadata_t meta,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition select(eg_intr_md.egress_port) {
            NF_PORT_PIPE2: parse_queuemem;
            NF_PORT_PIPE3: parse_queuemem;
            INPUT_PORT_1: check_qid;
            INPUT_PORT_2: check_qid;
            INPUT_PORT_3: check_qid;
            INPUT_PORT_4: check_qid;
            INPUT_PORT_5: check_qid;
            INPUT_PORT_6: check_qid;
            INPUT_PORT_7: check_qid;
            INPUT_PORT_8: check_qid;
            INPUT_PORT_9: check_qid;
            INPUT_PORT_10: check_qid;
            INPUT_PORT_11: check_qid;
            INPUT_PORT_12: check_qid;
            INPUT_PORT_13: check_qid;
            INPUT_PORT_14: check_qid;
            default: parse_ethernet;
        }
    }

    state check_qid {
        transition select(eg_intr_md.egress_qid) {
            MAX_PRIORITY_QUEUE: parse_chunks;
            default: parse_ethernet;
        }
    }

    state parse_queuemem {
        pkt.extract(meta.queuemem);
        transition select(meta.queuemem.next_hdr) {
            queuemem_next_hdr_t.ETHER: parse_ethernet;
            queuemem_next_hdr_t.QUEUEMEM: skip_queuemem;
            default: reject;
        }
    }

    state skip_queuemem {
        pkt.advance(sizeInBits(meta.queuemem));
        transition parse_ethernet;
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
            ether_type_t.PAYLOAD: parse_payload;
            default: reject;
        }
    }

    state parse_payload {
        pkt.extract(hdr.payload);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            ipv4_protocol_t.TCP: parse_tcp;
            ipv4_protocol_t.UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

control EgressDeparser(packet_out pkt, inout egress_headers_t hdr, in egress_metadata_t meta,
                       in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    Checksum() ipv4_checksum_eg;

    apply {
        if (meta.queuemem.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum_eg.update({
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
        
        pkt.emit(hdr);
    }
}

#endif /* _EGRESS_PARSER_ */