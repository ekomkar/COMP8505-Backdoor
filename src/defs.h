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

#define IP_HDR_KEY 5001
//#define SEKRET "Don't panic"
#define SEKRET "Hide my msg"

#define TRUE 1
#define FALSE 0

#define MAX_LEN 4096
#define MASK "/usr/libex/brunner"

#define OPTIONS ":cbhs:d:f:w:x:"

#define PKT_T_FLT "tcp port 80"
#define PKT_U_FLT "udp port 53"

#define FRAM_SZ 8
#define MD5_LEN 4
#define SIZE_TO_SEQ 4

#define CMD_PORT 4096
#define RSP_PORT 4097
#define XFL_PORT 4098
#define DIR_PORT 4099

#define CMD_TYP 0
#define RSP_TYP 1
#define XFL_TYP 2
#define DIR_TYP 3

#define TCP_HDR_SIZ 20
#define UDP_HDR_SIZ 8

#endif /* DEFS_H_ */
