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

struct _tcp_dgram {
	struct iphdr ip;
	struct tcphdr tcp;
};

struct _pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

struct iphdr ip_prep() {
	struct iphdr ip_hdr;

	return ip_hdr;
}

struct tcphdr tcp_prep() {
	struct tcphdr tcp_hdr;

	return tcp_hdr;
}

void _send(uint32 dest_addr, uint32 data, int chan) {
	struct _tcp_dgram packet;
	struct _pseudo_header pseudo_header;
	struct sockaddr_in sin;
	int sock;
	int one = 1;

	srand(getpid() * time(NULL));

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)
		error("_send(): Unable to open sending socket.");

	// Tell kernel not to help us out
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
		error("_send(): Kernel won't allow IP header override.");

	memset(&packet, 0, sizeof(packet));

}

