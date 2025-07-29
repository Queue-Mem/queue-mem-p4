/* -*- P4_16 -*- */

#include <core.p4>
#include <t2na.p4>

#include "queuemem_pipe/queuemem_pipe.p4"
#include "queuemem_pipe/parsers/ingress_parser.p4"
#include "queuemem_pipe/parsers/egress_parser.p4"

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) queuemem_pipe;

Switch(queuemem_pipe) main;