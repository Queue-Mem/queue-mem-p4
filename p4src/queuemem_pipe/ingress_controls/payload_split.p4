#ifndef _PAYLOAD_SPLIT_
#define _PAYLOAD_SPLIT_

#include "../../include/defines.p4"
#include "../../include/registers.p4"
#include "../../include/types.p4"
#include "../../include/configuration.p4"

control PayloadSplit(inout ingress_headers_t hdr, inout ingress_metadata_t meta,
                     in ingress_intrinsic_metadata_t ig_intr_md,
                     inout ingress_intrinsic_metadata_for_tm_t ig_tm_md,
                     in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> max_payloads_per_queue) {
    /* Update the header index and read it */
    RegisterAction<bit<32>, bit<1>, bit<32>>(hdr_index) hdr_index_inc = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;

            if (value == (HEADER_REGISTER_SIZE - 1)) {
                value = 0;
            } else {
                value = value + 1;
            }
        }
    };

    /* Update the pktid and read it */
    RegisterAction<bit<32>, bit<1>, bit<32>>(packet_identifier) packet_identifier_inc = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            
            if ((value + 1) == 0) {
                value = 1;
            } else {
                value = value + 1;
            }
        }
    };

    /* Port and qid from the pq_idx field, used for recirculated pkts  */
    action to_port_and_qid(PortId_t p, QueueId_t qid) {
        ig_tm_md.ucast_egress_port = p;
        ig_tm_md.qid = qid;
    }

    table port_queue_from_pq_idx {
        key = {
            meta.queuemem.pq_idx: exact;
        }
        actions = {
            to_port_and_qid;
        }
        size = N_OUTPUT_PORTS * N_PORT_QUEUES;
    }

    bit<2> ig_pipe_id = 0;
    #if PORT_ECMP==1
        /* ECMP Port Selection */
        #if QUEUE_ECMP==1
            bit<32> segment_idx = 0;
            QueueId_t segment_offset = 0;
            bit<16> queues_in_slice = 0;
            action to_port(PortId_t eg_port, bit<32> seg_idx, QueueId_t seg_offset, bit<16> q_in_slice) {
                ig_tm_md.ucast_egress_port = eg_port;
                segment_idx = seg_idx;
                segment_offset = seg_offset;
                queues_in_slice = q_in_slice;
            }
        #else
            bit<32> port_idx = 0;
            action to_port(PortId_t eg_port, bit<32> eg_idx) {
                ig_tm_md.ucast_egress_port = eg_port;
                port_idx = eg_idx;
            }
        #endif
        
        Hash<bit<32>>(HashAlgorithm_t.CRC32) port_ecmp_hash;
        #if QUEUE_ECMP==1
            ActionProfile(size=N_OUTPUT_PORTS * N_QUEUE_SLICES) port_ecmp_profile;
            ActionSelector(
                action_profile = port_ecmp_profile,
                hash = port_ecmp_hash,
                mode = SelectorMode_t.FAIR,
                max_group_size = N_OUTPUT_PORTS * N_QUEUE_SLICES,
                num_groups = 1
            ) port_ecmp_sel;
        #else
            ActionProfile(size=N_OUTPUT_PORTS) port_ecmp_profile;
            ActionSelector(
                action_profile = port_ecmp_profile,
                hash = port_ecmp_hash,
                mode = SelectorMode_t.FAIR,
                max_group_size = N_OUTPUT_PORTS,
                num_groups = 1
            ) port_ecmp_sel;
        #endif

        table port_ecmp {
            key = {
                ig_pipe_id: exact;
                hdr.ipv4.src_addr: selector;
                hdr.ipv4.dst_addr: selector;
                hdr.ipv4.protocol: selector;
                meta.l4_lookup.src_port: selector;
                meta.l4_lookup.dst_port: selector;
            }
            actions = {
                to_port;
            }
            size = 4; /* One per pipe */
            implementation = port_ecmp_sel;
        }
    #else
        #if QUEUE_ECMP==1
            bit<32> segment_idx = 0;
            QueueId_t segment_offset = 0;
            bit<16> queues_in_slice = 0;
            action to_slice(bit<32> seg_idx, QueueId_t seg_offset, bit<16> q_in_slice) {
                segment_idx = seg_idx;
                segment_offset = seg_offset;
                queues_in_slice = q_in_slice;
            }
        
            Hash<bit<32>>(HashAlgorithm_t.CRC32) port_ecmp_hash;
            ActionProfile(size=N_OUTPUT_PORTS * N_QUEUE_SLICES) port_ecmp_profile;
            ActionSelector(
                action_profile = port_ecmp_profile,
                hash = port_ecmp_hash,
                mode = SelectorMode_t.FAIR,
                max_group_size = N_OUTPUT_PORTS * N_QUEUE_SLICES,
                num_groups = 1
            ) port_ecmp_sel;

            table port_ecmp {
                key = {
                    ig_tm_md.ucast_egress_port: exact;
                    hdr.ipv4.src_addr: selector;
                    hdr.ipv4.dst_addr: selector;
                    hdr.ipv4.protocol: selector;
                    meta.l4_lookup.src_port: selector;
                    meta.l4_lookup.dst_port: selector;
                }
                actions = {
                    to_slice;
                }
                size = N_OUTPUT_PORTS;
                implementation = port_ecmp_sel;
            }

            action to_port(PortId_t eg_port) {
                ig_tm_md.ucast_egress_port = eg_port;
            }

            table eg_port_mapping {
                key = {
                    ig_intr_md.ingress_port: exact;
                }
                actions = {
                    to_port;
                }
                size = N_OUTPUT_PORTS;
            }
        #else
            action to_index(bit<32> idx) {
                port_idx = idx;
            }

            table port_idx_mapping {
                key = {
                    ig_intr_md.ingress_port: exact;
                }
                actions = {
                    to_index;
                }
                size = N_OUTPUT_PORTS;
            }
        #endif 
    #endif

    bit<16> n_payload_queues = 0;
    RegisterAction<bit<16>, bit<1>, bit<16>>(n_xoff_queues) n_xoff_queues_read = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;
        }
    };

    /* Port queue selection */
    #if QUEUE_ECMP==1
        RegisterAction2<queue_info_t, bit<32>, bit<16>, QueueId_t>(port_queue_info) get_queue = {
            void apply(inout queue_info_t value, out bit<16> rv, out QueueId_t rv2) {
                if (value.n_pkts == max_payloads_per_queue) {
                    value.n_pkts = 1;
                    if (value.curr_queue == queues_in_slice) {
                        value.curr_queue = 0;
                    } else {
                        value.curr_queue = value.curr_queue + 1;
                    }
                } else {
                    value.n_pkts = value.n_pkts + 1;
                }

                rv = value.n_pkts;
                rv2 = (QueueId_t) value.curr_queue;
            }
        };
    #else
        RegisterAction2<queue_info_t, bit<32>, bit<16>, QueueId_t>(port_queue_info) get_queue = {
            void apply(inout queue_info_t value, out bit<16> rv, out QueueId_t rv2) {
                if (value.n_pkts == max_payloads_per_queue) {
                    value.n_pkts = 1;
                    if (value.curr_queue == n_payload_queues) {
                        value.curr_queue = 0;
                    } else {
                        value.curr_queue = value.curr_queue + 1;
                    }
                } else {
                    value.n_pkts = value.n_pkts + 1;
                }

                rv = value.n_pkts;
                rv2 = (QueueId_t) value.curr_queue;
            }
        };
    #endif

    /* Assign adv_flow_ctl field */
    bit<32> port_queue_flow_ctl = 0;
    action to_flow_ctl(bit<32> flow_ctl) {
        port_queue_flow_ctl = flow_ctl;
    }

    table flow_ctl_from_port_queue {
        key = {
            ig_tm_md.ucast_egress_port: exact;
            ig_tm_md.qid: exact;
        }
        actions = {
            to_flow_ctl;
        }
        size = N_OUTPUT_PORTS * N_PORT_QUEUES;
    }

    /* Assign idx from port and qid */
    bit<16> port_queue_idx = 0;
    action assign_idx(bit<16> idx) {
        port_queue_idx = idx;
    }
    
    table port_qid_to_idx {
        key = {
            ig_tm_md.ucast_egress_port: exact;
            ig_tm_md.qid: exact;
        }
        actions = {
            assign_idx;
        }
        size = N_OUTPUT_PORTS * N_PORT_QUEUES;
    }

    /* Mirror Session */
    bit<2> eg_pipe_id = 0;
    action to_mirror_session(MirrorId_t session) {
        meta.mirror_session = session;
    }
    
    table mirror_select {
        key = {
            eg_pipe_id: exact;
        }
        actions = {
            to_mirror_session;
        }
        size = 4; /* One per pipe */
    }

    /* Port Queue State State-Machine */
    RegisterAction<queue_state_t, bit<16>, bit<16>>(port_queue_state) port_queue_state_transition = {
        void apply(inout queue_state_t value, out bit<16> read_value) {
            /* Read current queue state */
            read_value = value.state;
            if (meta.queuemem.pkt_type == PKT_TYPE_HEAD) {
                /* First packet of the batch */
                /* Reset the processed headers tracker */
                value.n_processed_hdrs = 0;

                if (value.state == PQ_STATUS_RESUMED) {
                    /* Queue was resumed by the tail packet, we will XOFF it here */
                    value.state = PQ_STATUS_PAUSED;
                } else {
                    /* Queue was not resumed by the tail packet, we need to XON it here */
                    value.state = PQ_STATUS_RESUMED;
                }
            } else {
                /* Either a middle or a tail packet */
                if (value.state == PQ_STATUS_RESUMED) {
                    /* Queue was resumed by the previous packet, we need to XOFF it here */
                    value.state = PQ_STATUS_PAUSED;
                }
            }
        }
    };

    #if DEBUG==1
        Register<bit<32>, bit<1>>(1) recirc_pkts;
        RegisterAction<bit<32>, bit<1>, void>(recirc_pkts) recirc_pkts_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };
        Register<bit<32>, bit<1>>(1) not_recirc_pkts;
        RegisterAction<bit<32>, bit<1>, void>(not_recirc_pkts) not_recirc_pkts_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) tail_middle_resume_counter;
        RegisterAction<bit<32>, bit<1>, void>(tail_middle_resume_counter) tail_middle_resume_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) head_packets_counter;
        RegisterAction<bit<32>, bit<1>, void>(head_packets_counter) head_packets_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) tail_packets_counter;
        RegisterAction<bit<32>, bit<1>, void>(tail_packets_counter) tail_packets_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) middle_packets_counter;
        RegisterAction<bit<32>, bit<1>, void>(middle_packets_counter) middle_packets_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) recirculated_head_packets_counter;
        RegisterAction<bit<32>, bit<1>, void>(recirculated_head_packets_counter) recirculated_head_packets_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) recirculated_packets_counter;
        RegisterAction<bit<32>, bit<1>, void>(recirculated_packets_counter) recirculated_packets_counter_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };
    #endif

    apply {
        bit<1> forwarding_state = DONT_FORWARD;

        if (meta.queuemem.isValid()) {
            #if DEBUG==1
                recirculated_packets_counter_inc.execute(0);
            #endif

            if (meta.queuemem.pkt_type == PKT_TYPE_HEAD) {
                port_queue_from_pq_idx.apply();
                meta.queuemem.pkt_type = PKT_TYPE_MIDDLE;

                #if DEBUG==1
                    recirculated_head_packets_counter_inc.execute(0);
                #endif
            }

            forwarding_state = FORWARD;
        } else {
            bit<32> idx = hdr_index_inc.execute(0);
            bit<32> pkt_identifier = packet_identifier_inc.execute(0);
            n_payload_queues = n_xoff_queues_read.execute(0);
            ig_pipe_id = DEVPORT_PIPE(ig_intr_md.ingress_port);
            #if PORT_ECMP==0
                #if QUEUE_ECMP==0
                    ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
                #endif
            #endif

            #if PORT_ECMP==1
                if (port_ecmp.apply().hit) {
            #else
                #if QUEUE_ECMP==1
                    eg_port_mapping.apply();
                    if (port_ecmp.apply().hit) {
                #else
                    if (port_idx_mapping.apply().hit) {
                #endif
            #endif
                /* We selected the port, now we select the queue */
                bit<16> n_enqueued_pkts;
                #if QUEUE_ECMP==1
                    QueueId_t segment_qid;
                    n_enqueued_pkts = get_queue.execute(segment_idx, segment_qid);

                    /* Compute the final qid, it's the offset+segment_qid */
                    ig_tm_md.qid = segment_offset + segment_qid;
                #else
                    QueueId_t selected_qid;
                    n_enqueued_pkts = get_queue.execute(port_idx, selected_qid);

                    /* We explicitly assign the metadata to set the $valid flag, otherwise this is ignored */
                    ig_tm_md.qid = selected_qid;
                #endif

                flow_ctl_from_port_queue.apply();
            
                /* Get idx associated to the port/queue combination */
                if (port_qid_to_idx.apply().hit) {
                    bit<8> pkt_type = PKT_TYPE_MIDDLE;
                    if (n_enqueued_pkts == 1) {
                        pkt_type = PKT_TYPE_HEAD;

                        #if DEBUG==1
                            head_packets_counter_inc.execute(0);
                        #endif
                    } else if (n_enqueued_pkts == max_payloads_per_queue) {
                        pkt_type = PKT_TYPE_TAIL;

                        #if DEBUG==1
                            tail_packets_counter_inc.execute(0);
                        #endif
                    } else {
                        #if DEBUG==1
                            middle_packets_counter_inc.execute(0);
                        #endif
                    }

                    /* Put metadata in place, this will be used for both mirroring and recirculation */
                    meta.queuemem.setValid();
                    meta.queuemem.hdr_idx = idx;
                    meta.queuemem.pkt_id = pkt_identifier;
                    meta.queuemem.flow_ctl = port_queue_flow_ctl;
                    meta.queuemem.pq_idx = port_queue_idx;
                    meta.queuemem.pkt_type = pkt_type;
                    meta.queuemem.next_hdr = queuemem_next_hdr_t.ETHER;

                    forwarding_state = FORWARD;
                }
            }
        }
        
        if (forwarding_state != DONT_FORWARD) {
            bit<1> next_action = ACTION_PREPARE_MIRRORING;

            /* Read the queue state before updating, and update it */
            bit<16> prev_pq_state = port_queue_state_transition.execute(meta.queuemem.pq_idx);

            if (meta.queuemem.pkt_type == PKT_TYPE_HEAD) {
                /* First packet of the batch */
                if (prev_pq_state == PQ_STATUS_RESUMED) {
                    #if DEBUG==1
                        not_recirc_pkts_inc.execute(0);
                    #endif
                    
                    /* Queue was resumed by the tail packet, we will XOFF it here */
                    ig_dprsr_md.adv_flow_ctl = meta.queuemem.flow_ctl + AFC_CREDIT_PAUSE;
                } else {
                    /* Queue was not resumed by the tail packet, we need to XON it here */
                    ig_dprsr_md.adv_flow_ctl = meta.queuemem.flow_ctl + AFC_CREDIT_RESUME;

                    /* If we enqueue the current packet, it will be drained by the queue, we need to recirculate it so to avoid losing it */
                    /* In the meanwhile, the queue will be drained with the previous packets */
                    next_action = ACTION_PREPARE_RECIRCULATION;

                    #if DEBUG==1
                        recirc_pkts_inc.execute(0);
                    #endif
                }
            } else if (prev_pq_state == PQ_STATUS_RESUMED) { /* Either a middle or a tail packet */
                /* Queue was resumed by the previous packet, we need to XOFF it here */
                #if DEBUG==1
                    tail_middle_resume_counter_inc.execute(0);
                #endif

                ig_dprsr_md.adv_flow_ctl = meta.queuemem.flow_ctl + AFC_CREDIT_PAUSE;
            }

            if (next_action == ACTION_PREPARE_MIRRORING) {
                /* Prepare Payload */
                hdr.ipv4.setInvalid();
                hdr.tcp.setInvalid();
                hdr.udp.setInvalid();

                hdr.ethernet.ether_type = ether_type_t.PAYLOAD;

                hdr.payload.setValid();
                hdr.payload.hdr_idx = meta.queuemem.hdr_idx;
                hdr.payload.pkt_id = meta.queuemem.pkt_id;
                hdr.payload.total_len = hdr.ipv4.total_len;
                hdr.payload.pq_idx = meta.queuemem.pq_idx;
                hdr.payload.pkt_type = meta.queuemem.pkt_type;
                hdr.payload.src_mac = hdr.ethernet.src_addr;
                hdr.payload.dst_mac = hdr.ethernet.dst_addr;
                hdr.payload.chksum = hdr.ipv4.hdr_checksum;
                
                /* Prepare Mirroring */
                eg_pipe_id = DEVPORT_PIPE(ig_tm_md.ucast_egress_port);
                mirror_select.apply();
                ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
                ig_dprsr_md.mirror_io_select = 0;
            } else {
                /* Enable recirculation, we assign to hdr.queuemem all the meta.queuemem values so we do not need to read registers again */
                ig_tm_md.ucast_egress_port = RECIRCULATION_PORT_PIPE0;      /* Base port */
                ig_tm_md.ucast_egress_port[8:7] = ig_pipe_id;               /* Change the pipe bits */
                ig_tm_md.bypass_egress = 0x1;

                /* Serialize metadata into a custom header (before Ethernet) */
                hdr.queuemem.setValid();
                hdr.queuemem.hdr_idx = meta.queuemem.hdr_idx;
                hdr.queuemem.pkt_id = meta.queuemem.pkt_id;
                hdr.queuemem.flow_ctl = meta.queuemem.flow_ctl;
                hdr.queuemem.pq_idx = meta.queuemem.pq_idx;
                hdr.queuemem.pkt_type = meta.queuemem.pkt_type;
                hdr.queuemem.next_hdr = queuemem_next_hdr_t.QUEUEMEM;
            }
        }
    }
}

#endif /* _PAYLOAD_SPLIT_ */