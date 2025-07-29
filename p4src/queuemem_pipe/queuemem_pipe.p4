/* -*- P4_16 -*- */

#include "../include/defines.p4"
#include "../include/configuration.p4"
#include "../include/headers.p4"
#include "../include/types.p4"
#include "../include/metadata.p4"

#include "ingress_controls/default_switch.p4"
#include "ingress_controls/payload_split.p4"
#include "ingress_controls/forward_header.p4"

#include "egress_controls/truncate_headers.p4"
#include "egress_controls/store_header.p4"
#include "egress_controls/packet_reconstruct.p4"

/* INGRESS */
control Ingress(inout ingress_headers_t hdr, inout ingress_metadata_t meta,
                in ingress_intrinsic_metadata_t ig_intr_md, 
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {                        
    DefaultSwitch() default_switch;
    PayloadSplit() payload_split;
    ForwardHeader() forward_header;

    action send(PortId_t port, QueueId_t qid) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid = qid;
    }

    action send_tag_src(PortId_t port, QueueId_t qid, bit<8> tag) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid = qid;
        hdr.ethernet.src_addr[7:0] = tag;
    }

    action send_swap(PortId_t port, QueueId_t qid, bit<8> tag) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid = qid;

        mac_addr_t src = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = src[47:8] ++ tag;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    table dst_ip_blacklist {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            send;
            send_tag_src;
            send_swap;
            drop;
        }
        size = 32;
    }

    table l4_blacklist {
        key = {
            ig_intr_md.ingress_port: exact;
            hdr.ipv4.protocol: exact;
            hdr.ipv4.total_len: range;
            meta.l4_lookup.src_port: range;
        }
        actions = {
            send;
        }
        size = 16;
    }

    RegisterAction<bit<16>, bit<1>, bit<16>>(n_payloads_per_queue) n_payloads_per_queue_read = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;
        }
    };

    apply {
        if (!dst_ip_blacklist.apply().hit) {
            if (!l4_blacklist.apply().hit) { 
                if (meta.is_split == 0 && meta.to_split == 0) {
                    default_switch.apply(hdr, ig_intr_md, ig_dprsr_md, ig_tm_md);
                } else {
                    bit<16> n_pay_queue = n_payloads_per_queue_read.execute(0);

                    if (hdr.ipv4.isValid() && meta.first_frag == 1) {
                        payload_split.apply(hdr, meta, ig_intr_md, ig_tm_md, ig_prsr_md, ig_dprsr_md, n_pay_queue);
                    } else if (meta.is_split == 1) {
                        forward_header.apply(hdr, meta, ig_intr_md, ig_tm_md, ig_dprsr_md, n_pay_queue);
                    } else {
                        default_switch.apply(hdr, ig_intr_md, ig_dprsr_md, ig_tm_md);
                    }
                }
            } else {
                ig_tm_md.bypass_egress = 0x1;
            }
        } else {
            ig_tm_md.bypass_egress = 0x1;
        }
    }
}

/* EGRESS */
control Egress(inout egress_headers_t hdr, inout egress_metadata_t meta,
               in egress_intrinsic_metadata_t eg_intr_md, in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    TruncateHeaders() truncate_headers;
    StoreHeader() store_header;
    PacketReconstruct() packet_reconstruct;

    #if DEBUG==1
        Register<bit<32>, bit<1>>(1) payload_counter;
        RegisterAction<bit<32>, bit<1>, void>(payload_counter) payload_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) stored_headers_counter;
        RegisterAction<bit<32>, bit<1>, void>(stored_headers_counter) stored_headers_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };
    #endif

    apply {
        if (hdr.payload.isValid()) {
            #if DEBUG==1
                payload_counter_inc.execute(0);
            #endif 

            packet_reconstruct.apply(hdr, eg_dprsr_md);
        } else if (meta.queuemem.isValid()) {
            truncate_headers.apply(hdr, meta, eg_dprsr_md);
        } else if (hdr.hdr_chunks.isValid()) {
            #if DEBUG==1
                stored_headers_counter_inc.execute(0);
            #endif

            store_header.apply(hdr, eg_dprsr_md);

            if (hdr.header_info.q_fwd == QUEUE_FORWARD) {
                /* Tail packet received, flush the queue */
                bit<32> flow_ctl = hdr.hdr_chunks.blk_0[23:0] ++ hdr.hdr_chunks.blk_1[31:24];
                eg_dprsr_md.adv_flow_ctl = flow_ctl + AFC_CREDIT_RESUME;
            }
        }
    }
}