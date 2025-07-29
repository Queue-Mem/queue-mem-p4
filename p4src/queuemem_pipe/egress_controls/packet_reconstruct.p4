#ifndef _PACKET_RECONSTRUCT_
#define _PACKET_RECONSTRUCT_

#include "../../include/registers.p4"

#define HDR_READ(i) \
    RegisterAction<bit<32>, bit<32>, bit<32>>(hdr_block_##i) read_hdr_block_##i = { \
        void apply(inout bit<32> value, out bit<32> read_value) { \
            read_value = value; \
        } \
    }; \
    action read_block_##i() { \
        hdr.hdr_chunks.blk_##i = read_hdr_block_##i.execute(idx); \
    }

#define HDR_READ_16(i) \
    RegisterAction<bit<16>, bit<32>, bit<16>>(hdr_block_##i) read_hdr_block_##i = { \
        void apply(inout bit<16> value, out bit<16> read_value) { \
            read_value = value; \
        } \
    }; \
    action read_block_##i() { \
        hdr.hdr_chunks.blk_##i = read_hdr_block_##i.execute(idx); \
    }

#define HDR_READ_TCP(i) \
    RegisterAction<bit<32>, bit<32>, bit<32>>(hdr_block_##i) read_hdr_block_##i = { \
        void apply(inout bit<32> value, out bit<32> read_value) { \
            read_value = value; \
        } \
    }; \
    action read_block_##i() { \
        hdr.hdr_chunks_tcp.blk_##i = read_hdr_block_##i.execute(idx); \
    }

#define HDR_READ_TCP_16(i) \
    RegisterAction<bit<16>, bit<32>, bit<16>>(hdr_block_##i) read_hdr_block_##i = { \
        void apply(inout bit<16> value, out bit<16> read_value) { \
            read_value = value; \  
        } \
    }; \
    action read_block_##i() { \
        hdr.hdr_chunks_tcp.blk_##i = read_hdr_block_##i.execute(idx); \
    }


#define HDR_READ_EXEC(i) \
    read_block_##i();

control PacketReconstruct(inout egress_headers_t hdr,
                          inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    bit<32> idx = hdr.payload.hdr_idx;

    HDR_READ(0)
    HDR_READ(1)
    HDR_READ(2)
    HDR_READ(3)
    HDR_READ(4)
    HDR_READ(5)
    HDR_READ(6)
    HDR_READ(7)
    HDR_READ(8)
    HDR_READ(9)
    HDR_READ_16(10)
    HDR_READ_TCP_16(11)
    HDR_READ_TCP(12)
    HDR_READ_TCP(13)
    HDR_READ_TCP_16(14)

    /* This read action is here just because of compiler bugs */
    RegisterAction<bit<32>, bit<32>, bit<32>>(hdr_pkt_id) hdr_pkt_id_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };

    #if DEBUG==1
        Register<bit<64>, bit<1>>(1) payloads_ok;
        RegisterAction<bit<64>, bit<1>, void>(payloads_ok) payloads_ok_inc = {
            void apply(inout bit<64> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) payloads_dropped;
        RegisterAction<bit<32>, bit<1>, void>(payloads_dropped) payloads_dropped_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) head_payloads_dropped;
        RegisterAction<bit<32>, bit<1>, void>(head_payloads_dropped) head_payloads_dropped_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };

        Register<bit<32>, bit<1>>(1) middle_payloads_dropped;
        RegisterAction<bit<32>, bit<1>, void>(middle_payloads_dropped) middle_payloads_dropped_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };
        
        Register<bit<32>, bit<1>>(1) tail_payloads_dropped;
        RegisterAction<bit<32>, bit<1>, void>(tail_payloads_dropped) tail_payloads_dropped_inc = {
            void apply(inout bit<32> value) {
                value = value + 1;
            }
        };
    #endif

    apply {
        /* Fallthrough */
        /* Set the chunks header valid and read values from registers */
        hdr.hdr_chunks.setValid();
        @stage(2) {
            HDR_READ_EXEC(0)
            HDR_READ_EXEC(1)
        }
        @stage(3) {
            HDR_READ_EXEC(2)
            HDR_READ_EXEC(3)
        }
        @stage(4) {
            HDR_READ_EXEC(4)
            HDR_READ_EXEC(5)
        }
        @stage(5) {
            HDR_READ_EXEC(6)
            HDR_READ_EXEC(7)
        }
        @stage(6) {
            HDR_READ_EXEC(8)
            HDR_READ_EXEC(9)
        }
        @stage(7) {
            HDR_READ_EXEC(10)
        }

        /* Fix IP (and UDP) length with the original size of the packet */
        hdr.hdr_chunks.blk_4[31:16] = hdr.payload.total_len;

        if (hdr.hdr_chunks.blk_5[7:0] == ipv4_protocol_t.UDP) {
            hdr.hdr_chunks.blk_9[15:0] = hdr.hdr_chunks.blk_4[31:16] - hdr.ipv4.minSizeInBytes();
        } else if (hdr.hdr_chunks.blk_5[7:0] == ipv4_protocol_t.TCP) {
            /* Set additional chunks header valid and read values from registers */
            hdr.hdr_chunks_tcp.setValid();
            @stage(7) {
                HDR_READ_EXEC(11)
            }
            @stage(8) {
                HDR_READ_EXEC(12)
                HDR_READ_EXEC(13)
            }
            @stage(9) {
                HDR_READ_EXEC(14)
            }

            /* When using TCP, we are sending to real applications. Therefore, we need to restore MACs and checksum */
            hdr.hdr_chunks.blk_0 = hdr.payload.dst_mac[47:16];
            hdr.hdr_chunks.blk_1 = hdr.payload.dst_mac[15:0] ++ hdr.payload.src_mac[47:32];
            hdr.hdr_chunks.blk_2 = hdr.payload.src_mac[31:0];
            hdr.hdr_chunks.blk_6[31:16] = hdr.payload.chksum;
        }

        /* Even if we read, if the id is the same, we forward the packet, else we drop */
        bit<32> stored_pkt_id;
        @stage(9) {
            stored_pkt_id = hdr_pkt_id_read.execute(idx);
        }

        @stage(10) {
            if (hdr.payload.pkt_id == stored_pkt_id) {
                #if DEBUG==1
                    payloads_ok_inc.execute(0);           
                #endif

                hdr.ethernet.setInvalid();
                hdr.payload.setInvalid();
            } else {
                #if DEBUG==1
                    payloads_dropped_inc.execute(0);

                    if (hdr.payload.pkt_type == PKT_TYPE_HEAD) {
                        head_payloads_dropped_inc.execute(0);
                    } else if (hdr.payload.pkt_type == PKT_TYPE_MIDDLE) {
                        middle_payloads_dropped_inc.execute(0);
                    } else {
                        tail_payloads_dropped_inc.execute(0);
                    }
                #endif

                eg_dprsr_md.drop_ctl = 0x1;
            }
        }
    }
}

#endif /* _PACKET_RECONSTRUCT_ */