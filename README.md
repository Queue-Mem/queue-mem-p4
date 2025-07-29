# Queue-Mem-P4
This repository contains the P4 implementation of Queue-Mem for Intel Tofino 2. 

This implementation is tested with **SDE 9.11.1**.

## Project Structure

The folder `p4src` contains the P4 code of Queue-Mem:
* The `include` directory contains configuration files. 
* The main file is `queuemem.p4`. It contains the implementation of the entire pipeline. 
* The `queuemem_pipe` folder contains the following modules:
    * The `ingress_controls` directory contains all the controls that Queue-Mem uses in the `Ingress` pipeline. 
    * The `egress_controls` directory contains all the controls that Queue-Mem uses in the `Egress` pipeline. 
    * The `parsers` directory contains both the Ingress Parser/Deparser and Egress Parser/Deparser.

The file `setup.py` contains a `bfrt_python` script that configures ports, mirroring, and other several callbacks for the program.

## How to Build

Example command to build the code, it can vary depending on your SDE installation: 
```bash 
./p4_build.sh -DSPLIT=64 queuemem.p4 # Do not split packets with "length <= SPLIT"
```
You can specify the split threshold modifying the value of `SPLIT`. This parameter sets the threshold under which Queue-Mem does not split the packets. The threshold is expressed in bytes. 

You can add a custom split threshold by editing the `queuemem_pipe/parsers/ingress_parser.p4` file, in the `check_ip_len` state.

## How to Run

Example commands to run Queue-Mem, they can vary depending on your SDE installation.
On a terminal, run `switchd`:
```bash 
$SDE/run_switchd.sh --arch tf2 -p queuemem
```
On another terminal, launch the `setup.py` script using `bfshell`:
```bash 
$SDE/run_bfshell.sh -i -b /absolute/path/to/setup.py
```

## How to Configure Queue-Mem

### Configure the Ports
You can find ports configuration in the `p4src/include/configuration.p4` file. 
Here you can set the ports towards the NF, the traffic generator and the ones used for TX/RX by the pipeline. 
If you make changes, you need to update the ports value in the `setup.py` file accordingly, and also change the various table setups.

The `INPUT_PORT_*` ports specified in the files are used also to send out the traffic after being processed. 

The current implementation supports three ways to return packets from the Tofino:
* Per-queue ECMP
* Per-port ECMP
* Exact mapping

By default, Queue-Mem is configured to use per-queue ECMP.

To enable per-port ECMP, you need to:
1. Compile the P4 with `-DQUEUE_ECMP=0`
2. Set `USE_QUEUE_ECMP = False` in `setup.py`

To enable exact mapping, you need to:
1. Compile the P4 with `-DQUEUE_ECMP=0 -DPORT_ECMP=0`
2. Set `USE_QUEUE_ECMP = False` and `USE_PORT_ECMP = False` in `setup.py`
3. Change the port mapping in the `setup_port_idx_mapping` function in `setup.py`

### Change The Number of Buffer Queues
By default, Queue-Mem uses 31 queues for buffering payloads and one extra queue for header forwarding.

To change the number of queues, you need to:

1. Edit the `p4src/include/defines.p4` file, specifying the new number of desired queues, for example: 
    ```p4
    #define N_PORT_QUEUES 25
    ```
2. Edit the `p4src/include/defines.p4` file, specifying the queue number for the headers (should be set to `N_PORT_QUEUES-1`), for example: 
    ```p4
    #define MAX_PRIORITY_QUEUE 24
    ```
3. Edit the `N_PORT_QUEUES` variable in the `setup.py` file, specifying the new number of desired queues (the header queue is automatically computed):
    ```python
    N_PORT_QUEUES = 25
    ```
4. Recompile the P4 code. 

### Change the Number of Queue Slices
Queue-Mem splits the buffer queues in different slices, that are selected using per-queue ECMP.

To change the number of slices, you have to:

1. Edit the `p4src/include/defines.p4` file, specifying the new number of slices, for example:
    ```p4
    #define N_QUEUE_SLICES 5
    ```
2. Edit the `queues_per_slice` variable in the `setup.py` file, specifying the number of queues per slice. If the slices are 5, then the number of queues per slice is `N_PORT_QUEUES / N_QUEUE_SLICES = 31 / 5 = 6.2 = 6` (the last slice will have 7 queues):
    ```python
    queues_per_slice = 6
    ```
3. Recompile the P4 code.

### Change the Number of Buffered Payloads per Queue
By default, Queue-Mem buffers 120 payloads for each queue batch.

To change the number of buffered payloads, you have to:

1. Edit the `DEFAULT_N_PAYLOADS` variable in the `setup.py` file, specifying the new number of payloads per queue:
    ```python
    DEFAULT_N_PAYLOADS = 20
    ```

### Specify how many bytes should be sent to the NF
You can set the number of bytes to send to the NF. To do so, you have to edit the `setup.py` file, changing the `PKT_MAX_LENGTH` variable: 
```python3
#################################
##### MIRROR SESSIONS TABLE #####
#################################
# In this section, we setup the mirror sessions.
# This is a rough truncation to the maximum possible header, we re-truncate to the proper size
# from the data plane Egress logic (see truncate_headers.p4)
PKT_MAX_LENGTH = 86  # Eth + IP + TCP + QueueMemHdr + QueueMemHdr
```

### Specify traffic classes to not split
You can add entries to the `dst_ip_blacklist` table to disable payload splitting on specific traffic classes selected by IP prefix.
Alternatively, you can add entries to the `l4_blacklist` table to disable payload splitting on specific traffic classes selected by ingress port (exact), IPv4 protocol field (exact), IPv4 total length (range), L4 src port (range). 
You can set up the `dst_ip_blacklist` and `l4_blacklist` tables from the `setup.py` file:
```python3
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
```
