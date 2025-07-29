#ifndef _REGISTERS_
#define _REGISTERS_

#include "configuration.p4"
#include "defines.p4"

/* Current index where store headers */
Register<bit<32>, bit<1>>(1) hdr_index;

/* Register to assign an unique packet identifier */
Register<bit<32>, bit<1>>(1, 1) packet_identifier;

/* Registers to temporary store headers */
/* UDP size (336 bits) */
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_0;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_1;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_2;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_3;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_4;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_5;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_6;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_7;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_8;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_9;
Register<bit<16>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_10;
/* Additional registers for TCP (336 bits + 96 bits) = 432 bits */
Register<bit<16>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_11;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_12;
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_13;
Register<bit<16>, bit<32>>(HEADER_REGISTER_SIZE) hdr_block_14;
/* Register to signal that the header is ready */
Register<bit<32>, bit<32>>(HEADER_REGISTER_SIZE) hdr_pkt_id;

/* Register to tweak the number of payloads in each queue */
Register<bit<16>, bit<1>>(1) n_payloads_per_queue;
/* Register to select how many queues dedicate to the QueueMem */
Register<bit<16>, bit<1>>(1) n_xoff_queues;
#if QUEUE_ECMP==1
    /* Register to keep track of the queue to use for a certain port */
    Register<queue_info_t, bit<32>>(N_OUTPUT_PORTS * N_QUEUE_SLICES) port_queue_info;
#else
    /* Register to keep track of the queue to use for a certain port */
    Register<queue_info_t, bit<32>>(N_OUTPUT_PORTS) port_queue_info;
#endif
/* Register that keeps the Port Queue State, all Queues start in "Resumed" */
Register<queue_state_t, bit<16>>(N_OUTPUT_PORTS * N_PORT_QUEUES, {PQ_STATUS_RESUMED, 0}) port_queue_state;

#endif /* _REGISTERS_ */