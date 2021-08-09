#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "miscs.h"
#include "random_passwd.h"

void random_passwd(char *passwd_new)
{
	FILE *rndh;
	char *curp;
	int idx;

	rndh = fopen("/dev/urandom", "rb");
	if (unlikely(!rndh)) {
		elog("Cannot open /dev/urandom: %s\n", strerror(errno));
		exit(11);
	}
	for (idx = 0, curp = passwd_new; idx < 10; idx++, curp++) {
		do
			fread(curp, 1, 1, rndh);
		while (*curp < 0x21 || *curp > 0x7e || *curp == '\'' ||
				*curp == '"' || *curp == ')' || *curp == '(' ||
				*curp == '<' || *curp == '>' || *curp == '|' ||
				*curp == '&' || *curp == '}' || *curp == '{' ||
				*curp == '#' || *curp == '$' || *curp == ';' ||
				*curp == '[' || *curp == ']' || *curp == ',' ||
				*curp == '\\'|| *curp == '`');

	};
	*curp = 0;
	fclose(rndh);
}
