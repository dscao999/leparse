#ifndef PIPE_EXECUTION_DSCAO__
#define PIPE_EXECUTION_DSCAO__

int one_execute(char *res, int reslen, const char *cmdline, const char *input);
int pipe_execute(char *res, int reslen, const char *cmdline, const char *input,
		const char *ofname);
int ssh_execute(char *res, int reslen, const char *ip, const char *cmdline,
		const char *input, int rm);
#endif  /* PIPE_EXECUTION_DSCAO__ */
