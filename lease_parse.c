#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "lease_parse.h"

struct dhclient_lease *dhclient_init(unsigned int buflen)
{
	struct dhclient_lease *lebuf;

	buflen = (buflen / 1024 + 1) * 1024;
	lebuf = malloc(buflen);
	if (!lebuf) {
		fprintf(stderr, "Out Of memory.\n");
		return NULL;
	}
	lebuf->recsiz = buflen - sizeof(struct dhclient_lease);
	lebuf->curpos = 0;
	lebuf->rec[0] = 0;
	return lebuf;
}

void dhclient_exit(struct dhclient_lease *lebuf)
{
	free(lebuf);
}

int lease_parse(FILE *fin, struct dhclient_lease *lebuf)
{
	int c, blank, curpos;

	lebuf->curpos = 0;
	lebuf->rec[0] = 0;
	curpos = 0;
	c = getc(fin);
	while (c == ' ' || c == '\t')
		c = getc(fin);
	if (c == '\n')
		return 0;
	else if (c == EOF)
		return -1;

	lebuf->rec[curpos++] = c;
	c = getc(fin);
	while (c != ' ' && c != '\t' && c != '\n' && c != EOF) {
		lebuf->rec[curpos++] = c;
		c = getc(fin);
	}
	if (memcmp(lebuf->rec, "lease", 5) != 0) {
		while (c != '\n' && c != EOF)
			c = getc(fin);
		lebuf->rec[0] = 0;
		if (c == '\n')
			return 0;
		else
			return -1;
	}

	blank = 0;
	while (c != EOF) {
		if (c == ' ' || c == '\t' || c == '\n') {
			if (blank == 0)
				blank = ' ';
			c = getc(fin);
			continue;
		}

		if (blank == ' ') {
			lebuf->rec[curpos++] = blank;
			blank = 0;
		}
		lebuf->rec[curpos++] = c;
		assert(curpos < lebuf->recsiz);
		if (c == '}')
			break;
		c = getc(fin);
	}
	if (c == EOF) {
		fprintf(stderr, "Unexpected end of file.\n");
		return -1;
	}

	lebuf->curpos = curpos;
	lebuf->rec[curpos] = 0;
	return curpos;
}
