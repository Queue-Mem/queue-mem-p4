#ifndef _METADATA_
#define _METADATA_

#include "types.p4"

struct ingress_metadata_t {
    /* Metadata for forwarding logic */
    bit<1> first_frag;
    bit<1> to_split;
    l4_lookup_t l4_lookup;

    /* Metadata read by the processed header */
    bit<8> is_split;
    bit<16> pq_idx;
    bit<32> flow_ctl;

    /* Common metadata for mirroring and recirculation */
    queuemem_h queuemem;
    
    /* Metadata required by mirroring */
    MirrorId_t mirror_session;
}

struct egress_metadata_t {
    /* Logic metadata */
    queuemem_h queuemem;
}

#endif /* _METADATA_ */