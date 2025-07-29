#ifndef _STORE_HEADER_
#define _STORE_HEADER_

#include "../../include/defines.p4"
#include "../../include/registers.p4"

#define HDR_STORE(i) \
    RegisterAction<bit<32>, bit<32>, void>(hdr_block_##i) store_hdr_block_##i = { \
        void apply(inout bit<32> value) { \
            value = hdr.hdr_chunks.blk_##i; \
        } \
    }; \
    action store_block_##i() { \
        store_hdr_block_##i.execute(idx); \
    }

#define HDR_STORE_16(i) \
    RegisterAction<bit<16>, bit<32>, void>(hdr_block_##i) store_hdr_block_##i = { \
        void apply(inout bit<16> value) { \
            value = hdr.hdr_chunks.blk_##i; \
        } \
    }; \
    action store_block_##i() { \
        store_hdr_block_##i.execute(idx); \
    }

#define HDR_STORE_TCP(i) \
    RegisterAction<bit<32>, bit<32>, void>(hdr_block_##i) store_hdr_block_##i = { \
        void apply(inout bit<32> value) { \
            value = hdr.hdr_chunks_tcp.blk_##i; \
        } \
    }; \
    action store_block_##i() { \
        store_hdr_block_##i.execute(idx); \
    }

#define HDR_STORE_TCP_16(i) \
    RegisterAction<bit<16>, bit<32>, void>(hdr_block_##i) store_hdr_block_##i = { \
        void apply(inout bit<16> value) { \
            value = hdr.hdr_chunks_tcp.blk_##i; \
        } \
    }; \
    action store_block_##i() { \
        store_hdr_block_##i.execute(idx); \
    }

#define HDR_STORE_EXEC(i) \
    store_block_##i();

control StoreHeader(inout egress_headers_t hdr,
                    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    bit<32> idx = hdr.header_info.hdr_idx;

    HDR_STORE(0)
    HDR_STORE(1)
    HDR_STORE(2)
    HDR_STORE(3)
    HDR_STORE(4)
    HDR_STORE(5)
    HDR_STORE(6)
    HDR_STORE(7)
    HDR_STORE(8)
    HDR_STORE(9)
    HDR_STORE_16(10)
    HDR_STORE_TCP_16(11)
    HDR_STORE_TCP(12)
    HDR_STORE_TCP(13)
    HDR_STORE_TCP_16(14)

    RegisterAction<bit<32>, bit<32>, void>(hdr_pkt_id) set_hdr_pkt_id = {
        void apply(inout bit<32> value) {
            value = hdr.header_info.pkt_id;
        }
    };

    apply {
       @stage(2) {
            HDR_STORE_EXEC(0)
            HDR_STORE_EXEC(1)
        }
        @stage(3) {
            HDR_STORE_EXEC(2)
            HDR_STORE_EXEC(3)
        }
        @stage(4) {
            HDR_STORE_EXEC(4)
            HDR_STORE_EXEC(5)
        }
        @stage(5) {
            HDR_STORE_EXEC(6)
            HDR_STORE_EXEC(7)
        }
        @stage(6) {
            HDR_STORE_EXEC(8)
            HDR_STORE_EXEC(9)
        }
        @stage(7) {
            HDR_STORE_EXEC(10)
            HDR_STORE_EXEC(11)
        }
        @stage(8) {
            HDR_STORE_EXEC(12)
            HDR_STORE_EXEC(13)
        }
        @stage(9) {
            HDR_STORE_EXEC(14)

            set_hdr_pkt_id.execute(idx);
        }

        eg_dprsr_md.drop_ctl = 0x1;
    }
}

#endif /* _STORE_HEADER_ */