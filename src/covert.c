/*
 * covert.c
 *
 *  Created on: Jun 4, 2014
 *      Author: root
 */
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>


#include "covert.h"
#include "util.h"


struct iphdr ip_prep() {
	struct iphdr ip_hdr;

	return ip_hdr;
}

struct tcphdr tcp_prep() {
	struct tcphdr tcp_hdr;

	return tcp_hdr;
}

void _send(uint32 dest_addr, char *data) {

}

