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
#define SLEEP_TIME 50000

#define SVR_NET_DEVICE "wlp2s0"
#define NETWORK_CARD "wlp2s0"

#define TRUE 1
#define FALSE 0

#define MAX_LEN 4096
#define MASK "JBRunner/1.0"

#define DEF_FOLDER "/root/"
#define DEF_SRC "192.168.0.17"
#define DEF_DST "192.168.0.5"
#define CHAN_TCP "tcp"
#define CHAN_UDP "udp"

// command-line options
#define OPTIONS ":cbhs:d:w:x:"

// default PKT Filters
#define PKT_T_FLT "tcp dst port 80 and src host "
#define PKT_U_FLT "udp dst port 80 and src host "

// frame size
#define FRAM_SZ 8

// default sequence number
#define DEF_SEQ 0x2a449b7a

// default IP Identification Field
#define DEF_IP_ID 6363
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

#define IP_HDR_SIZ 20
#define TCP_HDR_SIZ 20
#define UDP_HDR_SIZ 8

#endif /* DEFS_H_ */
