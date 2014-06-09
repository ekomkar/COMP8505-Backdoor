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

//typedef u_int32_t uint32;

#include "defs.h"


// Globals
char key = 'A';
char *options[] = { "-dest", "-dest_port", "-source", "-src_port" };
pcap_t *pd;
bool running = true;
FILE *file;
typedef struct _client client;
//typedef struct _packets packets;

struct _client {
	unsigned int source_host;
	unsigned int dest_host;
	unsigned short source_port;
	unsigned short dest_port;
	char srchost[80];
	char desthost[80];
};

static struct _packets {
	struct iphdr ip;
	struct tcphdr tcp;
	//char **data;
	char data[2000];
} packets;

static struct _pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
} pseudo_header;


client *client_new(void);
void packet_new(client *c, char *msg);
unsigned short in_cksum(unsigned short *addr, int len);
void send_packets(client *c, char *input);
void SystemFatal(char *msg);
void *sniffer_thread(void *args);
pcap_t * open_pcap_socket(char *device, const char *filter);
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packet);
void backdoor_client(uint32 ipaddress, char* protocol);
unsigned int host_convert(char *hostname);

#endif /* COMMON_H_ */

