#ifndef PIPE_EXECUTION_DSCAO__
#define PIPE_EXECUTION_DSCAO__

int pipe_execute(char *res, int reslen, const char *cmdpath,
		const char *cmdline, const char *input);
int scp_execute(char *res, int reslen, const char *ip, const char *fname,
		int rm);
#endif  /* PIPE_EXECUTION_DSCAO__ */
