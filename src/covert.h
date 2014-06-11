/*
 * covert.h
 *
 *  Created on: Jun 4, 2014
 *      Author: root
 */

#ifndef COVERT_H_
#define COVERT_H_

#include "defs.h"

#define PORT_TCP 80
#define PORT_UDP 53

#define IPHDR_LEN 5
#define IP_VER 4
#define TTL 64

/**
 * ip_prep
 *
 * RETURN: iphdr structure
 *
 * NOTES:
 *
 */
struct iphdr ip_prep();

/**
 * tpc_prep
 *
 * RETURN: tcphdr structure
 *
 * NOTES:
 *
 */
struct tcphdr tcp_prep();

/**
 * _send
 *
 * PARAMS:
 * uint32 dest_addr:
 * uint32 data:
 * int chan:
 *
 * RETURN: none
 *
 * NOTES:
 */
void _send(uint32 dest_addr, uint32 data, int chan);

#endif /* COVERT_H_ */
