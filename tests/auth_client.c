/*	$SNOWRABBIT: auth_client.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Run an authentication style the way authenticate(3) runs one, for
 * tests/integration.sh.
 *
 * login_stns cannot be tested by typing at it: the interface is file
 * descriptor 3, and in "response" mode the password arrives there as two NUL
 * terminated strings rather than from a terminal.  There is no shell
 * incantation for that - a here document gives a pipe on standard input, and
 * this needs one descriptor that is both readable and writable - so this sets
 * up the socket pair, hands it over as descriptor 3, and prints whatever the
 * style said.
 *
 * Which makes it the same shape as tests/yp_client.c: a client written here
 * because the stock tools cannot ask the question, and worth having for the
 * same reason - what it exercises is exactly the path login(1) and su(1) take,
 * and nothing else.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static __dead void
usage(void)
{
	(void)fprintf(stderr, "usage: auth_client [-s service] program user [password]\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	const char *service = "response";
	const char *prog, *user, *password = "";
	char reply[256];
	int sv[2];
	pid_t pid;
	ssize_t n;
	int status, ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			service = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2 && argc != 3)
		usage();
	prog = argv[0];
	user = argv[1];
	if (argc == 3)
		password = argv[2];

	/*
	 * A socket pair rather than a pipe, because the back channel is read
	 * and written by the same descriptor at both ends.
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		err(2, "socketpair");

	switch (pid = fork()) {
	case -1:
		err(2, "fork");
	case 0:
		(void)close(sv[0]);
		if (sv[1] != 3) {
			if (dup2(sv[1], 3) == -1)
				err(2, "dup2");
			(void)close(sv[1]);
		}
		execl(prog, "login_stns", "-s", service, user, (char *)NULL);
		err(2, "exec %s", prog);
	default:
		break;
	}
	(void)close(sv[1]);

	/*
	 * The challenge, which is empty, then the response.  Both NUL
	 * terminated, which is the form authenticate(3) sends and the form the
	 * style reads.  Nothing is sent at all for the other services: they
	 * either prompt or answer straight away.
	 */
	if (strcmp(service, "response") == 0) {
		if (write(sv[0], "", 1) != 1 || write(sv[0], password, strlen(password) + 1) !=
		    (ssize_t)strlen(password) + 1)
			err(2, "write to the back channel");
	}

	n = read(sv[0], reply, sizeof(reply) - 1);
	if (n < 0)
		err(2, "read from the back channel");
	reply[n] = '\0';
	reply[strcspn(reply, "\n")] = '\0';
	(void)printf("%s\n", reply);

	(void)close(sv[0]);
	if (waitpid(pid, &status, 0) == -1)
		err(2, "waitpid");

	/*
	 * The exit status is the style's own, so that a test can check the two
	 * separately: a style that says "authorize" and then exits non-zero is
	 * not a style anybody should believe.
	 */
	return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
