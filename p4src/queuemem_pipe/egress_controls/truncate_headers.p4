#ifndef _TRUNCATE_HEADERS_
#define _TRUNCATE_HEADERS_

control TruncateHeaders(inout egress_headers_t hdr, inout egress_metadata_t meta,
                        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    
    action size_udp() {
        hdr.ipv4.total_len = 28 + hdr.header_info.minSizeInBytes(); /* IP (20) + UDP (8B) = 28B + HdrInfo */
        hdr.udp.len = 8 + hdr.header_info.minSizeInBytes(); /* UDP (8B) + HdrInfo */
    }

    action size_tcp() {
        hdr.ipv4.total_len = 40 + hdr.header_info.minSizeInBytes(); /* IP (20) + TCP (20B) = 40B + HdrInfo */
    }

    table truncate_pkt {
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            size_udp;
            size_tcp;
        }
        size = 2;
        const entries = {
            ipv4_protocol_t.TCP: size_tcp();
            ipv4_protocol_t.UDP: size_udp();
        }
    }

    apply {
        /* Store everything in the src_addr since we will only lookahead the first 96bits when the header comes back */
        hdr.ethernet.src_addr[7:0] = 0x1;
        hdr.ethernet.src_addr[39:8] = meta.queuemem.flow_ctl;

        /* This will be in the src_addr after the NF processes it */
        hdr.ethernet.dst_addr[15:0] = meta.queuemem.pq_idx;

        hdr.header_info.setValid();
        hdr.header_info.hdr_idx = meta.queuemem.hdr_idx;
        hdr.header_info.pkt_id = meta.queuemem.pkt_id;
        hdr.header_info.pkt_type = meta.queuemem.pkt_type;
        hdr.header_info.q_fwd = QUEUE_DONT_FORWARD;

        truncate_pkt.apply();
    }
}

#endif /* _TRUNCATE_HEADERS_ */