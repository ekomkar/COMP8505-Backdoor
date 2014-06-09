/*
 * util.h
 *
 *  Created on: May 16, 2014
 *      Author: root
 */

#ifndef UTIL_H_
#define UTIL_H_

#include "defs.h"

/**
 * FUNCTION: error
 *
 * PARAMS:
 * const char *err: The message to display.
 *
 * RETURN: none.
 *
 * NOTES: Call this function to print a message and quit the program.
 */
void error(const char *err);
/**
 * FUNCTION: usage
 *
 * PARAMS:
 * char* name: The name of the program.
 *
 * RETURN: none.
 *
 * NOTES: Call this function to print usage and exit.
 */
void usage(char *name);

/**
 * FUNCTION: open_file
 *
 * PARAMS:
 * char *fname: The file path to open.
 * uint8 writeMode: True to open in write mode, false for read.
 *
 * RETURN: Pointer to file.
 *
 * NOTES: Call this function to open the specified file with the specified mode.
 */
FILE* open_file(char* fname, uint8 writeMode);

/**
 * FUNCTION: encrypt
 *
 * PARAMS:
 * char *key: The key to encrypt with.
 * char *msg: The message to encrypt.
 * int size: The size of the message.
 *
 * RETURN: None.
 *
 * NOTES: Call this function to encrypt the provided data in place.
 */

void encrypt(char *key, char *msg, int size);
/**
 * FUNCTION: decrypt
 *
 * PARAMS:
 * char *key: The key to decrypt with.
 * char *msg: The message to decrypt.
 * int size: The length of the message.
 *
 * RETURN: none.
 *
 * NOTES: Call this function to decrypt the provided data in place.
 */
void decrypt(char *key, char *msg, int size);

/**
 * FUNCTION: buildTransmission
 *
 * PARAMS:
 * char *data: The data to place in the transmission.
 * int *len: Value result, the length of the data and transmission.
 * char type: The type of transmission.
 *
 * RETURN: Pointer to transmission data.
 *
 * NOTES: Call this function to build a transmission block out of a given
 * set of data; note allocated on heap.
 */
//char* buildTransmission(char *data, int *len, char type);

/**
 * FUNCTION: getTransmission
 *
 * PARAMS:
 * char *data: The packet data to parse.
 * int *len: Value result, the length of the transmission and data.
 * char *type: Result parameter, transmission type.
 *
 * RETURN: Pointer to transmission data.
 *
 * NOTES: Call this function to grab the transmission data out of the specified buffer.
 */
//char* getTransmission(char *packet, int *len, char *type);



#endif /* UTIL_H_ */
