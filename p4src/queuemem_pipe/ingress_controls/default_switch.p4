#ifndef _DEFAULT_SWITCH_
#define _DEFAULT_SWITCH_

#include "../../include/configuration.p4"

control DefaultSwitch(inout ingress_headers_t hdr,
                      in ingress_intrinsic_metadata_t ig_intr_md,
                      inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                      inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    action forward_to_nf_port(PortId_t port) {
        hdr.ethernet.src_addr[7:0] = 0x0;

        ig_tm_md.ucast_egress_port = port;
    }

    bit<1> random_num_nf = 0x0;
    table to_nf {
        key = {
            random_num_nf: exact;
        }
        actions = {
            forward_to_nf_port;
        }
        size = 2;
        const entries = {
            0: forward_to_nf_port(NF_PORT_PIPE2);
            1: forward_to_nf_port(NF_PORT_PIPE3);
        }
    }

    action forward_to_input_port(PortId_t port, QueueId_t qid) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid = qid;
    }

    bit<4> random_num_fwd;
    table random_forwarding {
        key = {
            random_num_fwd: exact;
        }
        actions = {
            forward_to_input_port;
        }
        size = 16;
    }

    Random<bit<4>>() random_gen_fwd;
    Random<bit<1>>() random_gen_nf;
    apply {
        if (ig_intr_md.ingress_port == NF_PORT_PIPE2 || ig_intr_md.ingress_port == NF_PORT_PIPE3) {
            random_num_fwd = random_gen_fwd.get();
            random_forwarding.apply();
        } else {
            random_num_nf = random_gen_nf.get();
            to_nf.apply();
        }

        ig_tm_md.bypass_egress = 0x1;
    }
}

#endif /* _DEFAULT_SWITCH_ */