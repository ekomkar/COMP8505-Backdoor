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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>

#include "defs.h"
#include "mask.h"
#include "util.h"

int main(int argc, char *argv[]) {
	extern char* optarg;
	extern int optind, optopt;
	int c;
	bool client = false;
	char host[MAX_LEN];
	char filter[MAX_LEN];
	char folder[MAX_LEN];

	while ((c = getopt(argc, argv, OPTIONS)) != -1) {
		switch (c) {
		case 'c': // client?
			client = true;
			break;
		case 's': // server?
			client = false;
			break;
		case 'i': // remote host
			break;
		case 'f': // filter
			break;
		case 'w': // file watch
			break;
		case 'h': // help
			usage(argv[0]);
			break;
		case 'x': // channel
			break;
		case ':': // Missing operand.
			fprintf(stderr, "-%c requires an operand.\n", optopt);
			usage(argv[0]);
			break;
		}
	}

	// Mask the application name
	mask_prog(argv[0]);

	if (client) { // Controller Client
		// do something
	} else { // Backdoor Server
		//do something
	}

	return EXIT_SUCCESS;
}