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
 * prep_ip
 *
 * RETURN: iphdr structure
 *
 * NOTES:
 *
 */
struct iphdr prep_ip(uint32 src_addr, uint32 dst_addr);

/**
 * prep_tcp
 *
 * RETURN: tcphdr structure
 *
 * NOTES:
 *
 */
struct tcphdr prep_tcp(int type);

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
void _send(uint32 src, uint32 dest_addr, char data, int chan);

/**
 * chksum
 *
 * PARAMS:
 *
 *
 * RETURN: unsigned short checksum
 *
 * NOTES:
 */
unsigned short chksum(unsigned short *addr, int len);

#endif /* COVERT_H_ */
