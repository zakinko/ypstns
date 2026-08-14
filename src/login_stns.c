/*	$SNOWRABBIT: login_stns.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * login_stns - a BSD authentication style that checks a password against STNS.
 *
 * ypstns answers "who is this and what are they allowed to be"; this answers
 * "is this their password", which on OpenBSD is a separate question asked
 * through a separate mechanism.  login(1), su(1), sshd(8) and everything else
 * that authenticates a person calls authenticate(3), which runs
 * /usr/libexec/auth/login_<style> and believes what it says on file
 * descriptor 3.  So this is that program, and there is nothing else to
 * arrange: it is not a library anybody links, and it works for every caller at
 * once because they all go the same way.
 *
 * It is chosen in login.conf(5), and the order matters:
 *
 *	stns:\
 *		:auth=passwd,stns:\
 *		:tc=default:
 *
 * passwd first, so a local account is answered from master.passwd without the
 * API being asked at all, and the machine stays usable when the API is down -
 * exactly the reasoning behind putting "files" before "stns" in the map order.
 *
 * The password is compared against the hash the directory holds, by
 * stns_crypt_check(), because the two systems this family supports cannot do
 * it themselves: crypt(3) here understands bcrypt and nothing else, and the
 * hashes STNS deployments carry are almost always SHA-512 crypt.  See the
 * comment at the top of src/stns_crypt.c.
 */
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <bsd_auth.h>
#include <err.h>
#include <errno.h>
#include <login_cap.h>
#include <pwd.h>
#include <readpassphrase.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "stns.h"

/*
 * A password long enough that the limit is never the thing anybody meets.
 * readpassphrase(3) truncates at the buffer, so this is also the longest
 * passphrase that can be typed at a prompt.
 */
#define MAX_PASSWORD 1024

enum mode { MODE_LOGIN, MODE_CHALLENGE, MODE_RESPONSE };

static __dead void
usage(void)
{
	(void)fprintf(stderr, "usage: login_stns [-s service] [-v name=value] user [class]\n");
	exit(1);
}

/*
 * Read the challenge and the response from the back channel.
 *
 * In "response" mode the caller has already collected the password and sends
 * it on file descriptor 3 as two NUL terminated strings, the challenge then
 * the response.  The challenge is ours and is always empty, so it is read and
 * discarded; the response is the password.
 */
static int
read_response(char *buf, size_t buflen)
{
	size_t i = 0;
	int nul = 0;

	while (i < buflen - 1) {
		ssize_t n = read(3, buf + i, 1);

		if (n != 1)
			return -1;
		if (buf[i] == '\0' && ++nul == 2)
			break;
		i++;
	}
	buf[i] = '\0';

	if (nul < 2)
		return -1;

	/*
	 * Everything up to the first NUL was the challenge.  Move the response
	 * to the front rather than returning a pointer into the middle, so the
	 * caller has one buffer to wipe.
	 */
	{
		size_t clen = strlen(buf);

		if (clen >= i)
			return -1;
		memmove(buf, buf + clen + 1, i - clen);
	}
	return 0;
}

/*
 * Everything the API client is allowed to touch, and nothing else.
 *
 * unveil(2) before pledge(2), because a process pledged to "stdio" may not
 * call unveil.  What is left is what libcurl opens: a resolver configuration,
 * a trust store, and whatever TLS material stns.conf names.  stns.conf itself
 * has already been read.
 */
static void
restrict_self(const stns_conf_t *sc)
{
	char promises[64];

	if (unveil("/etc/resolv.conf", "r") == -1 || unveil("/etc/hosts", "r") == -1 ||
	    unveil("/etc/services", "r") == -1 || unveil("/etc/ssl", "r") == -1)
		err(1, "unveil");
	if (sc->tls_ca != NULL && unveil(sc->tls_ca, "r") == -1)
		err(1, "unveil %s", sc->tls_ca);
	if (sc->tls_cert != NULL && unveil(sc->tls_cert, "r") == -1)
		err(1, "unveil %s", sc->tls_cert);
	if (sc->tls_key != NULL && unveil(sc->tls_key, "r") == -1)
		err(1, "unveil %s", sc->tls_key);
	if (sc->cached_enable && sc->cached_unix_socket != NULL && unveil(sc->cached_unix_socket, "rw") == -1)
		err(1, "unveil %s", sc->cached_unix_socket);
	if (unveil(NULL, NULL) == -1)
		err(1, "unveil lock");

	/*
	 * "tty" is for the password prompt in login mode; the other two modes
	 * never touch a terminal, but asking for it once is simpler than
	 * pledging differently depending on how we were called, and it grants
	 * nothing a program with a controlling terminal does not already have.
	 */
	(void)strlcpy(promises, "stdio rpath inet dns tty", sizeof(promises));
	if (sc->cached_enable)
		(void)strlcat(promises, " unix", sizeof(promises));
	if (pledge(promises, NULL) == -1)
		err(1, "pledge");
}

int
main(int argc, char *argv[])
{
	char password[MAX_PASSWORD];
	const char *username;
	stns_conf_t sc;
	stns_user_t *u = NULL;
	FILE *back;
	enum mode mode = MODE_LOGIN;
	int authenticated = 0;
	int ch;

	(void)setpriority(PRIO_PROCESS, 0, 0);
	openlog("login_stns", LOG_ODELAY, LOG_AUTH);

	/*
	 * A password must not end up in a core file, and this process holds
	 * one in memory for as long as it takes to hash it.
	 */
	{
		struct rlimit rl = { 0, 0 };

		(void)setrlimit(RLIMIT_CORE, &rl);
	}

	while ((ch = getopt(argc, argv, "ds:v:")) != -1) {
		switch (ch) {
		case 'd':
			/* Accepted and ignored: there is nothing to say. */
			break;
		case 's':
			if (strcmp(optarg, "login") == 0)
				mode = MODE_LOGIN;
			else if (strcmp(optarg, "challenge") == 0)
				mode = MODE_CHALLENGE;
			else if (strcmp(optarg, "response") == 0)
				mode = MODE_RESPONSE;
			else {
				syslog(LOG_ERR, "unknown service \"%s\"", optarg);
				errx(1, "unknown service %s", optarg);
			}
			break;
		case 'v':
			/* Values from login.conf; none of them mean anything here. */
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1 && argc != 2)
		usage();
	username = argv[0];

	/*
	 * File descriptor 3 is the whole interface.  Everything this program
	 * decides is said there, and a caller that did not open it is not a
	 * caller whose question can be answered.
	 */
	if ((back = fdopen(3, "r+")) == NULL) {
		syslog(LOG_ERR, "cannot open the back channel: %m");
		errx(1, "cannot open the back channel");
	}

	/*
	 * There is no challenge to issue.  Saying so with "reject silent"
	 * rather than "reject" is what stops login(1) printing a challenge
	 * prompt of its own for a style that only ever wants a password.
	 */
	if (mode == MODE_CHALLENGE) {
		(void)fprintf(back, "%s\n", BI_SILENT);
		(void)fclose(back);
		return 0;
	}

	/*
	 * A name the API could not hold is refused before anything is read or
	 * asked, which is also what keeps it out of a query string.
	 */
	if (!stns_is_valid_name(username)) {
		syslog(LOG_NOTICE, "refused invalid user name");
		(void)fprintf(back, "%s\n", BI_REJECT);
		(void)fclose(back);
		return 1;
	}

	/*
	 * stns.conf is read before anything is given up, because it may hold an
	 * API token and be readable by root alone - login(1) and su(1) run this
	 * as root, which is the only reason that works.
	 */
	if (stns_load_config(stns_config_path(), &sc) != STNS_OK) {
		syslog(LOG_ERR, "cannot load %s", stns_config_path());
		(void)fprintf(back, "%s\n", BI_REJECT);
		(void)fclose(back);
		return 1;
	}

	/*
	 * The same two settings the fetcher turns off, for the same reasons:
	 * the on-disk cache would need cpath, which this is not going to have,
	 * and query_wrapper would need exec.  Unlike the fetcher this process
	 * has no timer to fall back on - it either answers now or refuses - so
	 * the circuit breaker is left alone: a breaker tripped by an earlier
	 * login is a real answer to whether the API is worth asking.
	 */
	sc.cache = 0;
	if (sc.query_wrapper != NULL) {
		free(sc.query_wrapper);
		sc.query_wrapper = NULL;
	}
	/* But it still must not create the lock file, for want of cpath. */
	sc.request_locktime = 0;

	restrict_self(&sc);

	if (mode == MODE_RESPONSE) {
		if (read_response(password, sizeof(password)) != 0) {
			syslog(LOG_ERR, "cannot read the response");
			(void)fprintf(back, "%s\n", BI_REJECT);
			goto done;
		}
	} else if (readpassphrase("Password:", password, sizeof(password), RPP_ECHO_OFF) == NULL) {
		syslog(LOG_ERR, "cannot read a password");
		(void)fprintf(back, "%s\n", BI_REJECT);
		goto done;
	}

	/*
	 * An empty password is refused here rather than being sent to be
	 * hashed.  A hash of the empty string is a perfectly good hash, and an
	 * account whose stored hash happened to be one would otherwise be
	 * open to anybody who pressed return.
	 */
	if (password[0] == '\0') {
		syslog(LOG_NOTICE, "refused an empty password for \"%s\"", username);
		(void)fprintf(back, "%s\n", BI_REJECT);
		goto done;
	}

	switch (stns_user_by_name(&sc, username, &u)) {
	case STNS_LOOKUP_SUCCESS:
		break;
	case STNS_LOOKUP_NOTFOUND:
		/*
		 * Not an error and not logged as one: this style is listed
		 * after passwd, so every local login on the machine reaches
		 * here for an account the directory has never heard of.
		 */
		(void)fprintf(back, "%s\n", BI_REJECT);
		goto done;
	default:
		syslog(LOG_ERR, "cannot reach the API to authenticate \"%s\"", username);
		(void)fprintf(back, "%s\n", BI_REJECT);
		goto done;
	}

	/*
	 * Two reasons a password can fail, and they are worth separating in
	 * the log even though the answer to the caller is the same.  An
	 * administrator whose users cannot log in wants to know whether the
	 * hashes are wrong or merely of a kind this machine cannot read.
	 */
	if (!stns_crypt_supported(u->password)) {
		syslog(LOG_NOTICE, "no usable password hash for \"%s\"", username);
		(void)fprintf(back, "%s\n", BI_REJECT);
		goto done;
	}

	if (stns_crypt_check(password, u->password) == STNS_OK) {
		authenticated = 1;
		(void)fprintf(back, "%s\n", BI_AUTH);
	} else {
		syslog(LOG_NOTICE, "failed password for \"%s\"", username);
		(void)fprintf(back, "%s\n", BI_REJECT);
	}

done:
	explicit_bzero(password, sizeof(password));
	stns_free_users(u, (u != NULL) ? 1 : 0);
	stns_unload_config(&sc);
	(void)fclose(back);
	closelog();
	return authenticated ? 0 : 1;
}
