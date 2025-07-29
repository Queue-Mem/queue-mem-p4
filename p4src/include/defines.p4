#ifndef _DEFINES_
#define _DEFINES_

/* Debug define */
#ifndef DEBUG
    #define DEBUG 0
#endif

/* Enables ECMP port forwarding */
#ifndef PORT_ECMP
    #define PORT_ECMP 1
#endif

/* Enables ECMP queue forwarding */
#ifndef QUEUE_ECMP
    #define QUEUE_ECMP 1
#endif

/* Defines for AFC */
#define AFC_CREDIT_PAUSE (1)
#define AFC_CREDIT_RESUME (0)

/* Headers Configurations */
#ifndef HEADER_REGISTER_SIZE
    #define HEADER_REGISTER_SIZE 94000
#endif

/* Number of output ports */
#define N_OUTPUT_PORTS 14

/* Number of queues per port @ 100G (in Tofino 2) */
#define N_PORT_QUEUES 32
/* Number of queue slices */
#define N_QUEUE_SLICES 15
/* Max Priority Queue (to use for headers) */
#define MAX_PRIORITY_QUEUE 31

/* QueueMem Logic defines */
/* Port Queue Statuses */
#define PQ_STATUS_PAUSED 0
#define PQ_STATUS_RESUMED 1
#define PQ_STATUS_UNDEFINED 2

/* Packet Types */
#define PKT_TYPE_HEAD 0xaa
#define PKT_TYPE_MIDDLE 0xbb
#define PKT_TYPE_TAIL 0xcc

/* Forwarding states */
#define DONT_FORWARD 0
#define FORWARD 1

/* Packet Actions */
#define ACTION_PREPARE_MIRRORING 0
#define ACTION_PREPARE_RECIRCULATION 1

/* Queue Forwarding states */
#define QUEUE_DONT_FORWARD 0
#define QUEUE_FORWARD 1

#endif /* _DEFINES_ */