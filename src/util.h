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
 * FUNCTION: randomRange
 *
 * PARAMS:
 * int Minimum number
 * int Maximum number
 *
 * Returns int
 */
int randomRange(int Min, int Max);

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
 * FUNCTION: resolve
 *
 * PARAMS:
 * char *hostname: The hostname to resolve.
 *
 * RETURN: none.
 *
 * NOTES: Call this function to resolve a hostname to an IPV4 address.
 */
unsigned int resolve(char *hostname);

/**
 * FUNCTION: writeToFile
 *
 * PARAMS:
 * char *frame: The string to write to the file
 *
 * RETURN: none.
 *
 * NOTES: Call this function to write a string to a file.
 */
void writeToFile(char * frame);

#endif /* UTIL_H_ */
