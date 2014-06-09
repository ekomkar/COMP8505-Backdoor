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
 *
 */
struct iphdr ip_prep();

/**
 *
 */
struct tcphdr tcp_prep();

/**
 *
 */
void _send(uint32 dest_addr, char *data);

#endif /* COVERT_H_ */
