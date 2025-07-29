#ifndef _TYPES_
#define _TYPES_

/* Protocols Enums */
enum bit<8> queuemem_next_hdr_t {
    ETHER = 0x0001,
    QUEUEMEM = 0x0002
}

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    PAYLOAD = 0xfeed
}

enum bit<8> ipv4_protocol_t {
    TCP = 6,
    UDP = 17
}

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

/* Struct to store L4 ports */
struct l4_lookup_t {
    bit<16> src_port;
    bit<16> dst_port;
}

/* Struct to store information about queue_id and enqueued packets */
struct queue_info_t {
    bit<16> curr_queue;
    bit<16> n_pkts;
}

/* Struct to store information about the queue state */
struct queue_state_t {
    bit<16> state;
    bit<16> n_processed_hdrs;
}

#endif /* _TYPES_ */