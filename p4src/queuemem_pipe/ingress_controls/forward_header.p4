#ifndef _FORWARD_HEADER_
#define _FORWARD_HEADER_

#include "../../include/defines.p4"

control ForwardHeader(inout ingress_headers_t hdr, inout ingress_metadata_t meta,
                      in ingress_intrinsic_metadata_t ig_intr_md,
                      inout ingress_intrinsic_metadata_for_tm_t ig_tm_md,
                      inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md, 
                      in bit<16> max_payloads_per_queue) {
    /* Port from the adv_flow_ctl field */
    PortId_t p_id;
    action to_port(PortId_t p) {
        p_id = p;
    }

    table port_from_hdr_flow_ctl {
        key = {
            meta.flow_ctl: exact;
        }
        actions = {
            to_port;
        }
        size = N_OUTPUT_PORTS * N_PORT_QUEUES;
    }

    /* Update the Port Queue State to "Resumed" */
    RegisterAction<queue_state_t, bit<16>, bit<16>>(port_queue_state) port_queue_state_resume = {
        void apply(inout queue_state_t value, out bit<16> read_value) {
            if ((value.n_processed_hdrs + 1) == max_payloads_per_queue) {
                value.state = PQ_STATUS_RESUMED;
                value.n_processed_hdrs = 0;
            } else {
                value.n_processed_hdrs = value.n_processed_hdrs + 1;
            }

            read_value = value.state;
        }
    };

    #if DEBUG==1
        Register<bit<32>, bit<1>>(1) tail_header_ingress_counter;
        RegisterAction<bit<32>, bit<1>, void>(tail_header_ingress_counter) tail_header_ingress_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };
    #endif

    apply {
        port_from_hdr_flow_ctl.apply();

        ig_tm_md.ucast_egress_port = p_id;
        ig_tm_md.qid = MAX_PRIORITY_QUEUE;

        bit<16> q_state = port_queue_state_resume.execute(meta.pq_idx);

        if (q_state == PQ_STATUS_RESUMED) {
            hdr.header_info.q_fwd = QUEUE_FORWARD;
            
            #if DEBUG==1
                tail_header_ingress_counter_inc.execute(0);
            #endif
        }
    }
}


#endif /* _FORWARD_HEADER_ */