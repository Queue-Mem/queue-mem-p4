import ctypes
import logging
import math
import os
import statistics
import sys
import time

# Experiment flags
BG_TRAFFIC_TPUT = False
BG_TRAFFIC_LAT = False
BG_TRAFFIC_INPUT = BG_TRAFFIC_TPUT or BG_TRAFFIC_LAT

# Enables debugging, the program must be compiled with -DDEBUG=1
DEBUG_STATS = False

# Enables ECMP port forwarding, the program must be compiled with -DPORT_ECMP=1
USE_PORT_ECMP = True

# Enables ECMP queue selection, the program must be compiled with -DQUEUE_ECMP=1
USE_QUEUE_ECMP = True

# Queues per port info
N_PORT_QUEUES = 32
HEADERS_QUEUE = N_PORT_QUEUES - 1
if not BG_TRAFFIC_INPUT:
    payload_queues = list(range(0, N_PORT_QUEUES - 1))
else:
    payload_queues = list(range(0, N_PORT_QUEUES - 2))

queues_per_slice = 0
if USE_QUEUE_ECMP:
    queues_per_slice = 5


# Input Ports (Pipe 2)
INPUT_PORT_1 = 264
INPUT_PORT_2 = 272
INPUT_PORT_3 = 280
INPUT_PORT_4 = 288
INPUT_PORT_5 = 296
INPUT_PORT_6 = 304
INPUT_PORT_7 = 312
# Input Ports (Pipe 3)
INPUT_PORT_8 = 392
INPUT_PORT_9 = 400
INPUT_PORT_10 = 408
INPUT_PORT_11 = 416
INPUT_PORT_12 = 424
INPUT_PORT_13 = 432
INPUT_PORT_14 = 440
# NF Ports (Pipe 2)
NF_PORT_PIPE2 = 320
# NF Ports (Pipe 3)
NF_PORT_PIPE3 = 448

# BG Traffic Port (iperf Server) (Pipe 0)
BG_TRAFFIC_PORT = 24

INPUT_PORTS = [
    INPUT_PORT_1, INPUT_PORT_2, INPUT_PORT_3, INPUT_PORT_4, INPUT_PORT_5, INPUT_PORT_6, INPUT_PORT_7,
    INPUT_PORT_8, INPUT_PORT_9, INPUT_PORT_10, INPUT_PORT_11, INPUT_PORT_12, INPUT_PORT_13, INPUT_PORT_14
]


# Pipes where the program is running (derived from the input/output ports)
def dev_port_pipe(dev_port):
    return dev_port >> 7


PIPE_NUMS = set(map(dev_port_pipe, INPUT_PORTS))
print(f"Program running on pipes={PIPE_NUMS}.")

queuemem_pipe = bfrt.queuemem.queuemem_pipe


#################################
########### PORT SETUP ##########
#################################
# In this section, we setup the ports.
def setup_ports():
    for p in INPUT_PORTS:
        print(f"Setting Input Port @ 100G: {p}")
        pipe_num, pg_id, _ = get_pg_info(p, 0)
        bfrt.tf2.tm.port.group.mod_with_seq(
            pg_id=pg_id, pipe=pipe_num, port_queue_count=[N_PORT_QUEUES, 0, 0, 0, 0, 0, 0, 0]
        )
        bfrt.port.port.add(DEV_PORT=p, SPEED='BF_SPEED_100G', FEC='BF_FEC_TYP_REED_SOLOMON', PORT_ENABLE=True)

    print(f"Setting NF_PORT_PIPE2={NF_PORT_PIPE2} at 100G")
    bfrt.port.port.add(DEV_PORT=NF_PORT_PIPE2, SPEED='BF_SPEED_100G', FEC='BF_FEC_TYP_REED_SOLOMON', PORT_ENABLE=True)

    print(f"Setting NF_PORT_PIPE3={NF_PORT_PIPE3} at 100G")
    bfrt.port.port.add(DEV_PORT=NF_PORT_PIPE3, SPEED='BF_SPEED_100G', FEC='BF_FEC_TYP_REED_SOLOMON', PORT_ENABLE=True)

    if BG_TRAFFIC_TPUT:
        print(f"Setting BG_TRAFFIC_INPUT={BG_TRAFFIC_PORT} at 100G")
        bfrt.port.port.add(DEV_PORT=BG_TRAFFIC_PORT, SPEED='BF_SPEED_100G', FEC='BF_FEC_TYP_REED_SOLOMON', PORT_ENABLE=True)


#################################
########## POOLS SETUP ##########
#################################
# In this section, we enlarge the buffer pools to the maximum available space.
def setup_pools():
    for pool_name in ["IG_APP_POOL_0", "EG_APP_POOL_0"]:
        print(f"Enlarging pool={pool_name}...")
        bfrt.tf2.tm.pool.app.mod_with_color_drop_enable(
            pool=pool_name,
            green_limit_cells=66_000_000 // 176, yellow_limit_cells=66_000_000 // 176, red_limit_cells=66_000_000 // 176
        )


#################################
##### MIRROR SESSIONS TABLE #####
#################################
# In this section, we setup the mirror sessions.
# This is a rough truncation to the maximum possible header, we re-truncate to the proper size
# from the data plane Egress logic (see truncate_headers.p4)
PKT_MAX_LENGTH = 86  # Eth + IP + TCP + QueueMemHdr + QueueMemHdr
HEADER_MIRROR_SESSION_PIPE2 = 100
HEADER_MIRROR_SESSION_PIPE3 = 101
eg_pipe_to_mirror_session = {
    2: HEADER_MIRROR_SESSION_PIPE2,
    3: HEADER_MIRROR_SESSION_PIPE3
}


def setup_mirror_session_table():
    bfrt.mirror.cfg.entry_with_normal(
        sid=HEADER_MIRROR_SESSION_PIPE2,
        direction="BOTH",
        session_enable=True,
        ucast_egress_port=NF_PORT_PIPE2,
        ucast_egress_port_valid=1,
        max_pkt_len=PKT_MAX_LENGTH
    ).push()

    bfrt.mirror.cfg.entry_with_normal(
        sid=HEADER_MIRROR_SESSION_PIPE3,
        direction="BOTH",
        session_enable=True,
        ucast_egress_port=NF_PORT_PIPE3,
        ucast_egress_port_valid=1,
        max_pkt_len=PKT_MAX_LENGTH
    ).push()


# This function setups the entries in the Mirror table, mapping the egress pipe to a certain mirror group.
def setup_mirror_select_table():
    mirror_select = queuemem_pipe.Ingress.payload_split.mirror_select
    mirror_select.clear()

    for eg_pipe_id, session in eg_pipe_to_mirror_session.items():
        print(f"Adding entry for mirror={session}...")
        mirror_select.add_with_to_mirror_session(eg_pipe_id=eg_pipe_id, session=session)


##############################
######### QUEUE SETUP ########
##############################
# In this section, we setup the queue priorities and AFC.
def get_pg_info(dev_port, queue_id):
    pipe_num = dev_port >> 7
    entry = bfrt.tf2.tm.port.cfg.get(dev_port, print_ents=False)
    pg_id = entry.data[b'pg_id']
    pg_queue = entry.data[b'egress_qid_queues'][queue_id]

    return pipe_num, pg_id, pg_queue


def setup_queues_afc():
    for pipe_num in PIPE_NUMS:
        bfrt.tf2.tm.pipe.sched_cfg.set_default(pipe=pipe_num, advanced_flow_control_enable=True)
        print(f"Enabled AFC on pipe={pipe_num}")

    for port in INPUT_PORTS:
        print(f"Set XOFF AFC on port={port} queues={payload_queues}...")
        for queue in payload_queues:
            pipe_num, pg_id, pg_queue = get_pg_info(port, queue)
            bfrt.tf2.tm.queue.sched_cfg.mod(
                pipe=pipe_num, pg_id=pg_id, pg_queue=pg_queue, max_priority="1", advanced_flow_control='XOFF'
            )

        if BG_TRAFFIC_INPUT:
            pipe_num, pg_id, pg_queue = get_pg_info(port, HEADERS_QUEUE - 1)
            bfrt.tf2.tm.queue.sched_cfg.mod(
                pipe=pipe_num, pg_id=pg_id, pg_queue=pg_queue, max_priority="6"
            )

        pipe_num, pg_id, pg_queue = get_pg_info(port, HEADERS_QUEUE)
        bfrt.tf2.tm.queue.sched_cfg.mod(pipe=pipe_num, pg_id=pg_id, pg_queue=pg_queue, max_priority="7")


# This function setups the queue tables to get the adv_flow_ctl value from port/queue and viceversa.
# At also setups the table to assign an index to each port/queue combination (for registers).
class AdvFlowCtl(ctypes.BigEndianStructure):
    # 32-bit adv_flow_ctl format
    # The ig_dprsr_md.adv_flow_ctl value is a 32-bit, that corresponds to the concatenation of these values
    #    bit<1> qfc = set always to 1
    #    bit<2> tm_pipe_id = the pipe ID
    #    bit<4> tm_mac_id = the pg_port number
    #    bit<3> _pad = leave 0
    #    bit<7> tm_mac_qid = the pg_queue number
    #    bit<15> credit = the credit. In XOFF mode, to pause=1, to resume=0
    _fields_ = [
        ("qfc", ctypes.c_uint32, 1),
        ("tm_pipe_id", ctypes.c_uint32, 2),
        ("tm_mac_id", ctypes.c_uint32, 4),
        ("_pad", ctypes.c_uint32, 3),
        ("tm_mac_qid", ctypes.c_uint32, 7),
        ("credit", ctypes.c_uint32, 15)
    ]


def setup_queue_tables():
    import struct

    port_queue_from_pq_idx_table = queuemem_pipe.Ingress.payload_split.port_queue_from_pq_idx
    port_queue_from_pq_idx_table.clear()

    flow_ctl_from_port_queue_table = queuemem_pipe.Ingress.payload_split.flow_ctl_from_port_queue
    flow_ctl_from_port_queue_table.clear()

    port_qid_to_idx_table = queuemem_pipe.Ingress.payload_split.port_qid_to_idx
    port_qid_to_idx_table.clear()

    port_from_hdr_flow_ctl_table = queuemem_pipe.Ingress.forward_header.port_from_hdr_flow_ctl
    port_from_hdr_flow_ctl_table.clear()

    idx = 0

    for port in INPUT_PORTS:
        for queue in payload_queues:
            pipe_num, pg_id, pg_queue = get_pg_info(port, queue)

            adv_flow_ctl = AdvFlowCtl()
            adv_flow_ctl.qfc = 1
            adv_flow_ctl.tm_pipe_id = pipe_num
            adv_flow_ctl.tm_mac_id = pg_id
            adv_flow_ctl.tm_mac_qid = pg_queue
            flow_ctl, = struct.unpack_from("!I", adv_flow_ctl)

            print(f"port={port}, queue={queue} has flow_ctl={hex(flow_ctl)} and idx={idx}...")
            port_queue_from_pq_idx_table.add_with_to_port_and_qid(
                pq_idx=idx, p=port, qid=queue
            )

            flow_ctl_from_port_queue_table.add_with_to_flow_ctl(
                ucast_egress_port=port, qid=queue, flow_ctl=flow_ctl
            )

            port_from_hdr_flow_ctl_table.add_with_to_port(
                flow_ctl=flow_ctl, p=port
            )

            port_qid_to_idx_table.add_with_assign_idx(
                ucast_egress_port=port, qid=queue, idx=idx
            )

            idx += 1


#################################
######## PORT ECMP TABLE ########
#################################
# This function setups the entries in the ECMP port table, mapping the IG pipe and 5-tuple to a certain output port.
def setup_port_ecmp_table():
    port_ecmp_profile = queuemem_pipe.Ingress.payload_split.port_ecmp_profile
    port_ecmp_sel = queuemem_pipe.Ingress.payload_split.port_ecmp_sel
    port_ecmp_table = queuemem_pipe.Ingress.payload_split.port_ecmp

    port_ecmp_profile.clear()
    port_ecmp_sel.clear()
    port_ecmp_table.clear()

    pipe_port_profiles = {}
    idx = 0

    for port in INPUT_PORTS:
        print(f"Adding ECMP entry for port={port}...")
        pipe = dev_port_pipe(port)
        if pipe not in pipe_port_profiles:
            pipe_port_profiles[pipe] = []

        port_ecmp_profile.add_with_to_port(ACTION_MEMBER_ID=idx, eg_port=port, eg_idx=idx)
        pipe_port_profiles[pipe].append(idx)
        idx += 1

    for group_idx, (pipe, port_profiles) in enumerate(pipe_port_profiles.items()):
        n_entries = len(port_profiles)

        port_ecmp_sel.entry(
            SELECTOR_GROUP_ID=group_idx + 1,
            MAX_GROUP_SIZE=n_entries,
            ACTION_MEMBER_ID=port_profiles,
            ACTION_MEMBER_STATUS=[True] * n_entries
        ).push()

        port_ecmp_table.add(ig_pipe_id=pipe, SELECTOR_GROUP_ID=group_idx + 1)


#################################
######## QUEUE ECMP TABLE #######
#################################
# This function setups the entries in the ECMP queue table, mapping the IG pipe and 5-tuple to a certain queue segment.
def setup_queue_ecmp_table():
    port_ecmp_profile = queuemem_pipe.Ingress.payload_split.port_ecmp_profile
    port_ecmp_sel = queuemem_pipe.Ingress.payload_split.port_ecmp_sel
    port_ecmp_table = queuemem_pipe.Ingress.payload_split.port_ecmp

    port_ecmp_profile.clear()
    port_ecmp_sel.clear()
    port_ecmp_table.clear()

    pipe_port_profiles = {}
    idx = 0

    for port in INPUT_PORTS:
        print(f"Adding ECMP entry for port={port}...")
        pipe = dev_port_pipe(port)
        if pipe not in pipe_port_profiles:
            pipe_port_profiles[pipe] = []

        offsets_n_queues = [(off, queues_per_slice - 1) for off in range(0, len(payload_queues), queues_per_slice)]
        remaining_queues = len(payload_queues) % queues_per_slice
        if remaining_queues > 0:
            offsets_n_queues.pop()
            offsets_n_queues[-1] = (offsets_n_queues[-1][0], offsets_n_queues[-1][1] + remaining_queues)

        for segment_offset, q_in_slice in offsets_n_queues:
            print(f"Adding ECMP entry for port={port}, segment_idx={idx} and segment_offset={segment_offset} (queues_in_slice={q_in_slice})...")

            port_ecmp_profile.add_with_to_port(ACTION_MEMBER_ID=idx, eg_port=port, seg_idx=idx, seg_offset=segment_offset, q_in_slice=q_in_slice)
            pipe_port_profiles[pipe].append(idx)

            idx += 1

    for group_idx, (pipe, port_profiles) in enumerate(pipe_port_profiles.items()):
        n_entries = len(port_profiles)

        port_ecmp_sel.entry(
            SELECTOR_GROUP_ID=group_idx + 1,
            MAX_GROUP_SIZE=n_entries,
            ACTION_MEMBER_ID=port_profiles,
            ACTION_MEMBER_STATUS=[True] * n_entries
        ).push()

        port_ecmp_table.add(ig_pipe_id=pipe, SELECTOR_GROUP_ID=group_idx + 1)


#########################################
######## EG PORT QUEUE ECMP TABLE #######
#########################################
# This function setups the entries for static output ports and selects the ECMP queue table, mapping the EG pipe and 5-tuple to a certain queue segment.
def setup_eg_port_queue_ecmp_table():
    eg_port_mapping = queuemem_pipe.Ingress.payload_split.eg_port_mapping
    eg_port_mapping.clear()

    for i, port in enumerate(INPUT_PORTS[:7]):
        eg_port = INPUT_PORTS[i + 7]
        print(f"Adding ig_port={port} to eg_port={eg_port}...")
        eg_port_mapping.add_with_to_port(ingress_port=port, eg_port=eg_port)
    for i, port in enumerate(INPUT_PORTS[7:]):
        eg_port = INPUT_PORTS[i]
        print(f"Adding ig_port={port} to eg_port={eg_port}...")
        eg_port_mapping.add_with_to_port(ingress_port=port, eg_port=eg_port)
    
    port_ecmp_profile = queuemem_pipe.Ingress.payload_split.port_ecmp_profile
    port_ecmp_sel = queuemem_pipe.Ingress.payload_split.port_ecmp_sel
    port_ecmp_table = queuemem_pipe.Ingress.payload_split.port_ecmp

    port_ecmp_profile.clear()
    port_ecmp_sel.clear()
    port_ecmp_table.clear()

    port_profiles = {}
    idx = 0

    for port in INPUT_PORTS:
        print(f"Adding ECMP entry for port={port}...")
        if port not in port_profiles:
            port_profiles[port] = []

        offsets_n_queues = [(off, queues_per_slice - 1) for off in range(0, len(payload_queues), queues_per_slice)]
        remaining_queues = len(payload_queues) % queues_per_slice
        if remaining_queues > 0:
            offsets_n_queues.pop()
            offsets_n_queues[-1] = (offsets_n_queues[-1][0], offsets_n_queues[-1][1] + remaining_queues)

        for segment_offset, q_in_slice in offsets_n_queues:
            print(f"Adding ECMP entry for port={port}, segment_idx={idx} and segment_offset={segment_offset} (queues_in_slice={q_in_slice})...")

            port_ecmp_profile.add_with_to_slice(ACTION_MEMBER_ID=idx, seg_idx=idx, seg_offset=segment_offset, q_in_slice=q_in_slice)
            port_profiles[port].append(idx)

            idx += 1

    for group_idx, (port, port_profiles) in enumerate(port_profiles.items()):
        n_entries = len(port_profiles)

        port_ecmp_sel.entry(
            SELECTOR_GROUP_ID=group_idx + 1,
            MAX_GROUP_SIZE=n_entries,
            ACTION_MEMBER_ID=port_profiles,
            ACTION_MEMBER_STATUS=[True] * n_entries
        ).push()

        port_ecmp_table.add(ucast_egress_port=port, SELECTOR_GROUP_ID=group_idx + 1)


###############################
######## PORT IDX TABLE #######
###############################
# This function setups the entries in the port_idx table, maps ingress port to egress port directly.
def setup_port_idx_mapping():
    port_idx_mapping = queuemem_pipe.Ingress.payload_split.port_idx_mapping
    port_idx_mapping.clear()

    for i, port in enumerate(INPUT_PORTS):
        print(f"Adding PORT INDEX entry for port={port}...")
        port_idx_mapping.add_with_to_index(ingress_port=port, idx=i)


###########################
##### BLACKLIST TABLES #####
###########################
# This function setups the entries in the blacklist tables.
# You can add/edit/remove entries to disable payload splitting on specific traffic classes.
def setup_blacklist_tables():
    from ipaddress import ip_address

    dst_ip_blacklist_table = queuemem_pipe.Ingress.dst_ip_blacklist
    dst_ip_blacklist_table.clear()

    l4_blacklist_table = queuemem_pipe.Ingress.l4_blacklist
    l4_blacklist_table.clear()

    dst_ip_blacklist_table.add_with_drop(dst_addr=ip_address('224.0.0.0'), dst_addr_p_length=16)

    if BG_TRAFFIC_TPUT:
        for idx, port in enumerate(INPUT_PORTS):
            l4_blacklist_table.add_with_send(
                ingress_port=BG_TRAFFIC_PORT, protocol=6, 
                src_port_start=5201 + idx, src_port_end=5201 + idx, 
                total_len_start=0, total_len_end=65535, 
                port=port, qid=HEADERS_QUEUE - 1
            )
            
        dst_ip_blacklist_table.add_with_send(
            dst_addr=ip_address("192.168.4.136"), dst_addr_p_length=32, port=BG_TRAFFIC_PORT, qid=0
        )

    if BG_TRAFFIC_LAT:
        for idx, port in enumerate(INPUT_PORTS):
            ip_str = "10.0.0." + str(idx + 1)
            dst_ip_blacklist_table.add_with_send_swap(
                dst_addr=ip_address(ip_str), dst_addr_p_length=32, port=port, qid=HEADERS_QUEUE - 1, tag=0x02
            )


############################
##### FORWARDING TABLE #####
############################
# This function setups the entries in the default forwarding table.
def setup_default_forwarding_table():
    random_forwarding_table = queuemem_pipe.Ingress.default_switch.random_forwarding
    random_forwarding_table.clear()

    n_ports = len(INPUT_PORTS)

    for i in range(0, 16):
        target_port = i % n_ports
        port = INPUT_PORTS[target_port]

        random_forwarding_table.add_with_forward_to_input_port(
            random_num_fwd=i, port=port, qid=(HEADERS_QUEUE if not BG_TRAFFIC_INPUT else HEADERS_QUEUE - 1)
        )


##############################
##### PAYLOAD PARAMETERS #####
##############################
# This function setups the two registers that tweak the number of payloads in a queue and
# the queue flush timeout
DEFAULT_N_PAYLOADS = 120
if not BG_TRAFFIC_INPUT:
    DEFAULT_PAYLOAD_QUEUES = N_PORT_QUEUES - 2
else:
    DEFAULT_PAYLOAD_QUEUES = N_PORT_QUEUES - 3


def setup_payload_registers():
    print(f"Setting n_payloads_per_queue={DEFAULT_N_PAYLOADS}...")
    n_payloads_per_queue = queuemem_pipe.n_payloads_per_queue
    n_payloads_per_queue.mod(REGISTER_INDEX=0, f1=DEFAULT_N_PAYLOADS)

    print(f"Setting n_xoff_queues={DEFAULT_PAYLOAD_QUEUES}...")
    n_xoff_queues = queuemem_pipe.n_xoff_queues
    n_xoff_queues.mod(REGISTER_INDEX=0, f1=DEFAULT_PAYLOAD_QUEUES)


########################
######### STATS ########
########################
# This section creates a timer that calls a callback to dump and print stats.
PRINT_STATS = True
start_ts = time.time()

previous_nf_output_packets = 0
previous_nf_input_packets = 0
previous_nf_output_bytes = 0
previous_nf_input_bps = 0


def percentile(data, perc):
    global math

    size = len(data)
    return sorted(data)[int(math.ceil((size * perc) / 100)) - 1]


def get_stats():
    global start_ts, stats_time, \
        previous_nf_output_packets, previous_nf_input_packets, previous_nf_output_bytes, previous_nf_input_bps

    port_stats = bfrt.port.port_stat.get(regex=True, print_ents=False, from_hw=True)

    output_port_stats = list(filter(
        lambda x: x.key[b'$DEV_PORT'] in INPUT_PORTS,
        port_stats
    ))

    nf_port_stats = list(filter(
        lambda x: x.key[b'$DEV_PORT'] == NF_PORT_PIPE2 or x.key[b'$DEV_PORT'] == NF_PORT_PIPE3,
        port_stats
    ))

    input_pkts = sum(map(lambda x: x.data[b'$FramesReceivedOK'], output_port_stats))
    output_pkts = sum(map(lambda x: x.data[b'$FramesTransmittedOK'], output_port_stats))

    pipe_stats = {}
    for pipe_num in PIPE_NUMS:
        pipe_stats[pipe_num] = {}

        pipe_stats[pipe_num]['ig_counters'] = bfrt.tf2.tm.counter.ig_port.get(
            regex=True, print_ents=False, pipe=pipe_num, from_hw=True
        )
        pipe_stats[pipe_num]['eg_counters'] = bfrt.tf2.tm.counter.eg_port.get(
            regex=True, print_ents=False, pipe=pipe_num, from_hw=True
        )

    deq_qdepth_pipe = {pipe_num: 0 for pipe_num in PIPE_NUMS}
    for i, port in enumerate(INPUT_PORTS):
        for queue in payload_queues:
            pipe_num, pg_id, pg_queue = get_pg_info(port, queue)
            entry = bfrt.tf2.tm.counter.queue.get(pipe=pipe_num, pg_id=pg_id, pg_queue=pg_queue, print_ents=False)
            deq_qdepth_pipe[pipe_num] += entry.data[b'usage_cells']

    deq_qdepth_avg = statistics.mean(deq_qdepth_pipe.values())
    deq_qdepth_avg_mb = (deq_qdepth_avg * 176.0) / 1000000.0

    if DEBUG_STATS:
        total_payloads_dropped = 0
        for pipe_num in PIPE_NUMS:
            payloads_dropped = queuemem_pipe.payloads_dropped.get(
                REGISTER_INDEX=0, print_ents=False, from_hw=True, pipe=pipe_num
            )
            total_payloads_dropped += payloads_dropped.data[b'payloads_dropped.f1'][0]

    ts = time.time()

    for pipe_num, deq_qdepth_val in deq_qdepth_pipe.items():
        logging.info("QUEUE-%f-RESULT-DEQ_QDEPTH_PIPE%d %d cells" % (ts, pipe_num, deq_qdepth_val))
    logging.info("QUEUE-%f-RESULT-DEQ_QDEPTH_AVG_MB %f MB" % (ts, deq_qdepth_avg_mb))

    current_nf_input_bytes = sum(map(lambda x: x.data[b'$OctetsReceived'], nf_port_stats))
    current_nf_output_bytes = sum(map(lambda x: x.data[b'$OctetsTransmittedTotal'], nf_port_stats))

    current_nf_input_packets = sum(map(lambda x: x.data[b'$FramesReceivedOK'], nf_port_stats))
    current_nf_output_packets = sum(map(lambda x: x.data[b'$FramesTransmittedOK'], nf_port_stats))

    new_stats_time = time.time()
    delta_nf_input_bytes = (current_nf_input_bytes - previous_nf_input_bps) / (new_stats_time - stats_time)
    logging.info("QUEUE-%f-RESULT-NF_INPUT_BPS %d bps" % (ts, delta_nf_input_bytes))
    previous_nf_input_bps = current_nf_input_bytes

    delta_nf_output_bytes = (current_nf_output_bytes - previous_nf_output_bytes) / (new_stats_time - stats_time)
    logging.info("QUEUE-%f-RESULT-NF_OUTPUT_BPS %d bps" % (ts, delta_nf_output_bytes))
    previous_nf_output_bytes = current_nf_output_bytes

    delta_nf_input_packets = (current_nf_input_packets - previous_nf_input_packets) / (new_stats_time - stats_time)
    logging.info("QUEUE-%f-RESULT-NF_INPUT_PPS %d pps" % (ts, delta_nf_input_packets))
    previous_nf_input_packets = current_nf_input_packets

    delta_nf_output_packets = (current_nf_output_packets - previous_nf_output_packets) / (new_stats_time - stats_time)
    logging.info("QUEUE-%f-RESULT-NF_OUTPUT_PPS %d pps" % (ts, delta_nf_output_packets))
    previous_nf_output_packets = current_nf_output_packets

    logging.info("QUEUE-%f-RESULT-INPUT_PKTS %d pkts" % (ts, input_pkts))
    logging.info("QUEUE-%f-RESULT-OUTPUT_PKTS %d pkts" % (ts, output_pkts))
    if DEBUG_STATS:
        logging.info("QUEUE-%f-RESULT-DROPPED_PAYLOADS %d pkts" % (ts, total_payloads_dropped))
    for pipe_num, pipe_stat in pipe_stats.items():
        ig_dropped_pkts = sum(map(lambda x: x.data[b"drop_count_packets"], pipe_stat['ig_counters']))
        eg_dropped_pkts = sum(map(lambda x: x.data[b"drop_count_packets"], pipe_stat['eg_counters']))
        logging.info("QUEUE-%f-RESULT-IG_DROP_PIPE%d %d pkts" % (ts, pipe_num, ig_dropped_pkts))
        logging.info("QUEUE-%f-RESULT-EG_DROP_PIPE%d %d pkts" % (ts, pipe_num, eg_dropped_pkts))
    logging.info("================================================================")

    stats_time = new_stats_time


def stats_timer():
    import threading

    global PRINT_STATS

    if PRINT_STATS:
        get_stats()
    threading.Timer(1, stats_timer).start()


DEBUG_PIPES = [x for x in PIPE_NUMS]


def print_debug_stats():
    payloads_dropped = sum([x for i, x in enumerate(queuemem_pipe.payloads_dropped.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'payloads_dropped.f1']) if i in DEBUG_PIPES])
    head_payloads_dropped = sum([x for i, x in enumerate(queuemem_pipe.Egress.packet_reconstruct.head_payloads_dropped.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Egress.packet_reconstruct.head_payloads_dropped.f1']) if i in DEBUG_PIPES])
    middle_payloads_dropped = sum([x for i, x in enumerate(queuemem_pipe.Egress.packet_reconstruct.middle_payloads_dropped.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Egress.packet_reconstruct.middle_payloads_dropped.f1']) if i in DEBUG_PIPES])
    tail_payloads_dropped = sum([x for i, x in enumerate(queuemem_pipe.Egress.packet_reconstruct.tail_payloads_dropped.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Egress.packet_reconstruct.tail_payloads_dropped.f1']) if i in DEBUG_PIPES])
    payloads_reconstructed = sum([x for i, x in enumerate(queuemem_pipe.payloads_ok.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'payloads_ok.f1']) if i in DEBUG_PIPES])
    dequeued_payload_counter = sum([x for i, x in enumerate(queuemem_pipe.Egress.payload_counter.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Egress.payload_counter.f1']) if i in DEBUG_PIPES])
    stored_headers_counter = sum([x for i, x in enumerate(queuemem_pipe.Egress.stored_headers_counter.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Egress.stored_headers_counter.f1']) if i in DEBUG_PIPES])
    tail_header_counter = sum([x for i, x in enumerate(
        queuemem_pipe.Ingress.forward_header.tail_header_ingress_counter.get(
            REGISTER_INDEX=0, print_ents=False, from_hw=True
        ).data[b'Ingress.forward_header.tail_header_ingress_counter.f1']) if i in DEBUG_PIPES])
    tail_packets_counter = sum([x for i, x in enumerate(queuemem_pipe.Ingress.payload_split.tail_packets_counter.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Ingress.payload_split.tail_packets_counter.f1']) if i in DEBUG_PIPES])
    head_packets_counter = sum([x for i, x in enumerate(queuemem_pipe.Ingress.payload_split.head_packets_counter.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Ingress.payload_split.head_packets_counter.f1']) if i in DEBUG_PIPES])
    middle_packets_counter = sum([x for i, x in enumerate(
        queuemem_pipe.Ingress.payload_split.middle_packets_counter.get(
            REGISTER_INDEX=0, print_ents=False, from_hw=True
        ).data[b'Ingress.payload_split.middle_packets_counter.f1']) if i in DEBUG_PIPES])

    total_packets = head_packets_counter + middle_packets_counter + tail_packets_counter

    head_packets_no_recirc = sum([x for i, x in enumerate(queuemem_pipe.Ingress.payload_split.not_recirc_pkts.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Ingress.payload_split.not_recirc_pkts.f1']) if i in DEBUG_PIPES])
    head_packets_to_recirc = sum([x for i, x in enumerate(queuemem_pipe.Ingress.payload_split.recirc_pkts.get(
        REGISTER_INDEX=0, print_ents=False, from_hw=True
    ).data[b'Ingress.payload_split.recirc_pkts.f1']) if i in DEBUG_PIPES])
    tail_middle_resumes = sum([x for i, x in enumerate(
        queuemem_pipe.Ingress.payload_split.tail_middle_resume_counter.get(
            REGISTER_INDEX=0, print_ents=False, from_hw=True
        ).data[b'Ingress.payload_split.tail_middle_resume_counter.f1']) if i in DEBUG_PIPES])
    head_packets_recirculated = sum([x for i, x in enumerate(
        queuemem_pipe.Ingress.payload_split.recirculated_head_packets_counter.get(
            REGISTER_INDEX=0, print_ents=False, from_hw=True
        ).data[b'Ingress.payload_split.recirculated_head_packets_counter.f1']) if i in DEBUG_PIPES])
    packets_recirculated = sum([x for i, x in enumerate(
        queuemem_pipe.Ingress.payload_split.recirculated_packets_counter.get(
            REGISTER_INDEX=0, print_ents=False, from_hw=True
        ).data[b'Ingress.payload_split.recirculated_packets_counter.f1']) if i in DEBUG_PIPES])

    port_stats = bfrt.port.port_stat.get(regex=True, print_ents=False, from_hw=True)

    input_port_stats = list(filter(lambda x: x.key[b'$DEV_PORT'] in INPUT_PORTS, port_stats))

    nf_port_stats = list(filter(
        lambda x: x.key[b'$DEV_PORT'] == NF_PORT_PIPE2 or x.key[b'$DEV_PORT'] == NF_PORT_PIPE3,
        port_stats
    ))

    input_pkts = sum(map(lambda x: x.data[b'$FramesReceivedOK'], input_port_stats))
    output_pkts = sum(map(lambda x: x.data[b'$FramesTransmittedOK'], input_port_stats))

    headers_received_nf = sum(map(lambda x: x.data[b'$FramesReceivedOK'], nf_port_stats))
    headers_sent_nf = sum(map(lambda x: x.data[b'$FramesTransmittedOK'], nf_port_stats))
    headers_dropped_by_nf = headers_sent_nf - headers_received_nf

    payloads_dropped_in_queues = 0
    payloads_buffered_in_queues = 0
    payloads_buffer_cells = 0

    used_queues = 0
    for i, port in enumerate(INPUT_PORTS):
        for queue in range(0, N_PORT_QUEUES):
            pipe, pg_id, pg_queue = get_pg_info(port, queue)
            entry = bfrt.tf2.tm.counter.queue.get(pipe=pipe, pg_id=pg_id, pg_queue=pg_queue, print_ents=False)
            payloads_dropped_in_queues += entry.data[b'drop_count_packets']
            payloads_buffer_cells += entry.data[b'usage_cells']
            payloads_buffered_in_queues += math.ceil(entry.data[b'usage_cells'] / 9)
            if entry.data[b'watermark_cells'] > 0:
                used_queues += 1

    payloads_dropped_by_queuemem = input_pkts - output_pkts - payloads_buffered_in_queues - headers_dropped_by_nf
    
    print("================================================")
    print("PAYLOADS DROPPED:", payloads_dropped)
    print("HEAD PAYLOADS DROPPED:", head_payloads_dropped)
    print("MIDDLE PAYLOADS DROPPED:", middle_payloads_dropped)
    print("TAIL PAYLOADS DROPPED:", tail_payloads_dropped)
    print("PAYLOADS RECONSTRUCTED:", payloads_reconstructed)
    print("------------------------------------------------")
    print("HEAD PACKETS RECEIVED:", head_packets_counter)
    print("MIDDLE PACKETS RECEIVED:", middle_packets_counter)
    print("TAIL PACKETS RECEIVED:", tail_packets_counter)
    print("TOTAL PACKETS RECEIVED:", total_packets)
    print("------------------------------------------------")
    print("HEAD PACKETS PAUSE:", head_packets_no_recirc)
    print("HEAD PACKETS RESUME to RECIRCULATE:", head_packets_to_recirc)
    print("HEAD PACKETS RESUME RECIRCULATED:", head_packets_recirculated)
    print("TOTAL PACKETS RECIRCULATED:", packets_recirculated)
    print("TOTAL HEADS PACKET:", f"{head_packets_no_recirc + head_packets_to_recirc}/{head_packets_counter}")
    print("TAIL/MIDDLE RESUMES:", tail_middle_resumes)
    print("------------------------------------------------")
    print("TAIL HEADERS RECEIVED:", f"{tail_header_counter}/{tail_packets_counter}")
    print("TOTAL PAYLOADS DEQUEUED:", f"{dequeued_payload_counter}/{total_packets}")
    print("------------------------------------------------")
    print("HEADERS SENT to NF:", headers_sent_nf)
    print("HEADERS RECEIVED from NF:", headers_received_nf)
    print("HEADERS DROPPED by NF:", headers_dropped_by_nf)
    print("STORED HEADERS:", stored_headers_counter)
    print("------------------------------------------------")
    print("TOTAL INPUT PKTS:", input_pkts)
    print("TOTAL OUTPUT PKTS:", output_pkts)
    print("PAYLOADS DROPPED IN QUEUES:", payloads_dropped_in_queues)
    print(
        "PAYLOADS BUFFERED IN QUEUES:",
        f"{payloads_buffered_in_queues} pkts,", f"{payloads_buffer_cells} cells,",
        f"{payloads_buffer_cells * 176} Bytes"
    )
    print("DROPPED PKTS:", input_pkts - output_pkts - payloads_buffered_in_queues)
    print("DROPPED PKTS BY QUEUEMEM:", payloads_dropped_by_queuemem)
    print("DROPPED PKTS BY QUEUEMEM PERC:", (payloads_dropped_by_queuemem / input_pkts) * 100 if input_pkts > 0 else 0)
    print("USED QUEUES:", used_queues)
    print("================================================")


def debug_stats_timer():
    import threading

    global DEBUG_STATS

    if DEBUG_STATS:
        print_debug_stats()
    threading.Timer(5, debug_stats_timer).start()


def reset_port_queue_info(n_payloads=5):
    print(f"Clearing port_queue_info register...")
    queuemem_pipe.port_queue_info.clear()
    n_payloads_per_queue = queuemem_pipe.n_payloads_per_queue
    print(f"Setting n_payloads_per_queue={n_payloads}...")
    n_payloads_per_queue.mod(REGISTER_INDEX=0, f1=n_payloads)


def print_not_empty_queues():
    not_empty_queues = 0
    for i, port in enumerate(INPUT_PORTS):
        for queue in range(0, N_PORT_QUEUES):
            pipe, pg_id, pg_queue = get_pg_info(port, queue)
            entry = bfrt.tf2.tm.counter.queue.get(pipe=pipe, pg_id=pg_id, pg_queue=pg_queue, print_ents=False)
            if entry.data[b'usage_cells'] > 0:
                print(entry)
                not_empty_queues += 1
    print("NOT EMPTY QUEUES:", not_empty_queues)


lab_path = os.path.dirname(__file__)

# Setup Logging
logging.basicConfig(
    format='%(message)s',
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

(year, month, day, hour, minutes, _, _, _, _) = time.localtime(time.time())
log_path = os.path.join(lab_path, "logs")
log_timestamped_name = 'tofino2-log-%d-%s-%s_%s-%s' % (
    year, str(month).zfill(2), str(day).zfill(2), str(hour).zfill(2), str(minutes).zfill(2)
)
os.makedirs(log_path, exist_ok=True)
file_handler = logging.FileHandler(os.path.join(log_path, "%s.log" % log_timestamped_name))
file_handler.setFormatter(logging.Formatter('%(message)s'))
logging.root.addHandler(file_handler)

setup_pools()
setup_ports()
setup_mirror_session_table()
setup_mirror_select_table()
setup_queues_afc()
setup_queue_tables()

if USE_PORT_ECMP:
    if USE_QUEUE_ECMP:
        setup_queue_ecmp_table()
    else:
        setup_port_ecmp_table()
else:
    if USE_QUEUE_ECMP:
        setup_eg_port_queue_ecmp_table()
    else:
        setup_port_idx_mapping()

setup_blacklist_tables()
setup_default_forwarding_table()
setup_payload_registers()

bfrt.complete_operations()

stats_time = time.time()
stats_timer()  # Comment out to disable stats
debug_stats_timer()
