/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

#include <cne_fib.h>           // For fib_create, fib_add...
#include <cne_inet4.h>         // for inet_mtoh64 and inet_h64tom
#include <net/cne_ether.h>     // for ether_addr

#include "main.h" 

#define FIB_RULES_IP    0   /**< JSON index for IP address in a single entry */
#define FIB_RULES_MAC   1   /**< JSON index for MAC address in a single entry */
#define FIB_RULES_PORT  2   /**< JSON index for TX port in a single entry */

struct ipv4_l3fwd_fib_rule {
    uint32_t ip;
    uint8_t depth;
    struct ether_addr nh;
    uint16_t tx_port;
};

static struct cne_fib *fib;

static int
l3fwd_fib_populate(struct fwd_info *fwd, struct cne_fib *fib)
{
    for (uint16_t i = 0; i < fwd->fib_size; i++){
        struct ether_addr mac_le;
        char *entry[3];
        char *ip_prefix[4];
        char *address[2];
        char *mac_addr[6];
        int tx_port;
        uint64_t eaddr = 0;

        /* Parse the comma seperated FIB entry */
        entry[0] = strtok(fwd->fib_rules[i], ",");
        for(uint16_t j = 1; j < 3; ++j)
            entry[j] = strtok(NULL, ",");

        /* Parse the IP address and depth */
        address[0] = strtok(entry[FIB_RULES_IP], "/");
        address[1] = strtok(NULL, "/");

        /* Parse the IP address */
        ip_prefix[0] = strtok(address[0], ".");
        for(uint16_t j = 1; j < 4; ++j) {
            ip_prefix[j] = strtok(NULL, ".");
        }

        /* Parse the MAC address */
        mac_addr[0] = strtok(entry[FIB_RULES_MAC], ":");
        for(uint16_t j = 1; j < 6; ++j)
            mac_addr[j] = strtok(NULL, ":");

        tx_port = atoi(entry[FIB_RULES_PORT]);

        jcfg_lport_t *dst = jcfg_lport_by_index(fwd->jinfo, tx_port);

        if (!dst)
            /* Cannot find a local port to match the entry */
            return -1;

        uint32_t ip = CNE_IPV4(atoi(ip_prefix[0]), atoi(ip_prefix[1]),
                                atoi(ip_prefix[2]), atoi(ip_prefix[3]));
        uint8_t depth = (uint8_t) atoi(address[1]);

        for(int j = 0; j < ETHER_ADDR_LEN; ++j){
            mac_le.ether_addr_octet[j] = (uint8_t) strtoul(mac_addr[j], NULL, 16);
        }

        inet_mtoh64(&mac_le, &eaddr);

        /* Store both TX port and destination MAC in FIB's nexthop field. */
        uint64_t nexthop = ((uint64_t)tx_port << 48) | eaddr;

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
l3fwd_fib_init(struct fwd_info *fwd)
{
    struct cne_fib_conf config;
    config.max_routes = 1 << 16;
    config.default_nh = 0xFFFFFFFFFFFF;
    config.type       = CNE_FIB_DUMMY;

    fib = cne_fib_create("l3fwd_fib", &config);
    if (!fib)
        return -1;

    if (l3fwd_fib_populate(fwd, fib) < 0)
        return -1;

    /* Deallocate the entries now that we have the entries populated. */
    for(int i = 0; i < fwd->fib_size; ++i)
        free(fib->fib_rules[i]);
    free(fib->fib_rules);

    return 0;
}
