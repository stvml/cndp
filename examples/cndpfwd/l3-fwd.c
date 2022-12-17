/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

#include <cne_fib.h>           // For fib_create, fib_add...
#include <cne_inet4.h>         // for inet_mtoh64 and inet_h64tom
#include <net/cne_ether.h>     // for ether_addr

#include "main.h" 

#define IPV4_L3FWD_NUM_FIB_RULES \
    (sizeof(ipv4_l3fwd_fib_rule_array) / sizeof(ipv4_l3fwd_fib_rule_array[0]))

struct ipv4_l3fwd_fib_rule {
    uint32_t ip;
    uint8_t depth;
    struct ether_addr nh;
    uint16_t tx_port;
};

static struct cne_fib *fib;

static int
l3fwd_fib_populate(struct cne_fib *fib)
{
    /* 
     * 198.18.0.0/16 are set aside for RFC2544 benchmarking (RFC5735). 
     * Each FIB rule is IPv4, depth, next hop destination MAC, TX port. 
     */
    struct ipv4_l3fwd_fib_rule ipv4_l3fwd_fib_rule_array[] = {
        {CNE_IPV4(198, 18, 0, 0), 24, {{0x02, 0x00, 0x01, 0x02, 0x03, 0x04}}, 1},
        {CNE_IPV4(198, 18, 1, 0), 24, {{0x06, 0x00, 0x01, 0x02, 0x03, 0x04}}, 0}
    };

    for (uint16_t i = 0; i < IPV4_L3FWD_NUM_FIB_RULES; i++){
        uint32_t ip = ipv4_l3fwd_fib_rule_array[i].ip;
        uint8_t depth = ipv4_l3fwd_fib_rule_array[i].depth;
        uint64_t eaddr = 0;

        inet_mtoh64(&ipv4_l3fwd_fib_rule_array[i].nh, &eaddr);

        /* Store both TX port and destination MAC in FIB's nexthop field. */
        uint64_t nexthop = ((uint64_t)ipv4_l3fwd_fib_rule_array[i].tx_port << 48) | eaddr;

        if(cne_fib_add(fib, ip, depth, nexthop) < 0)
            return -1;
    }

    return 0;
}

int
l3fwd_fib_lookup(uint32_t *ip, struct ether_addr *eaddr, uint16_t *tx_port)
{
    uint64_t nexthop;

    cne_fib_lookup_bulk(fib, ip, &nexthop, 1);
    inet_h64tom(nexthop, eaddr);
    *tx_port = (uint16_t)(nexthop >> 48);

    return 0;
}

int
l3fwd_fib_init(void)
{
    struct cne_fib_conf config;
    config.max_routes = 1 << 16;
    config.default_nh = 0xFFFFFFFFFFFF;
    config.type       = CNE_FIB_DUMMY;

    fib = cne_fib_create("l3fwd_fib", &config);
    if (!fib)
        return -1;

    if (l3fwd_fib_populate(fib) < 0)
        return -1;

    return 0;
}
