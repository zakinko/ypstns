/*	$SNOWRABBIT: ypstns.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * ypstns - serve an STNS directory to OpenBSD as YP.
 *
 * This is the privileged half: it holds the maps and answers the RPC, and it
 * never speaks to the network beyond the machine's own YP clients.  The other
 * half runs as _ypstns behind unveil(2) and pledge(2), does the HTTP, and
 * sends finished map entries back over a pipe.  Neither half can do the
 * other's job, which is the point.
 *
 * The parent keeps root because a YP server has to: master.passwd.byname is
 * served only to a client on a reserved port, and being able to make that
 * distinction at all is the reason /etc/master.passwd has a shadow of its own.
 * What it does not do is parse anything - the RPC decoding is libc's, and the
 * text of the maps is assembled by the child and never taken apart here.
 */
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "ypstns.h"

int debug;
int verbose;

static volatile sig_atomic_t want_quit;
static volatile sig_atomic_t want_reload;
static pid_t client_pid;

void
log_init(int n_debug, int n_verbose)
{
	debug = n_debug;
	verbose = n_verbose;
	/*
	 * LOG_NDELAY opens the socket to syslogd now rather than at the first
	 * message.  It has to be open before pledge(2), because a process
	 * pledged to "stdio" may write to a syslog socket it already has and
	 * may not open a new one.
	 */
	openlog("ypstns", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void
logit(int prio, const char *fmt, ...)
{
	va_list ap;

	if (prio == LOG_DEBUG && !verbose)
		return;

	va_start(ap, fmt);
	vsyslog(prio, fmt, ap);
	va_end(ap);

	if (debug) {
		va_start(ap, fmt);
		(void)fprintf(stderr, "ypstns: ");
		(void)vfprintf(stderr, fmt, ap);
		(void)fputc('\n', stderr);
		va_end(ap);
	}
}

void
log_warn_errno(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	logit(LOG_ERR, "%s: %s", buf, strerror(errno));
}

__dead void
fatal(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	logit(LOG_CRIT, "fatal: %s", buf);
	exit(1);
}

static void
on_quit(int sig)
{
	want_quit = 1;
}

static void
on_reload(int sig)
{
	want_reload = 1;
}

/*
 * The child died.
 *
 * There is nothing useful to do about it in a handler; the main loop notices
 * and exits, and rc.d(8) - or an administrator - starts the whole thing again.
 * Carrying on without a fetcher would mean serving the same maps for ever,
 * which looks exactly like working.
 */
static void
on_child(int sig)
{
	want_quit = 1;
}

static __dead void
usage(void)
{
	extern char *__progname;

	(void)fprintf(stderr, "usage: %s [-dnv] [-D macro=value] [-f file]\n", __progname);
	exit(1);
}

/*
 * Take one entry from the fetcher and put it in the pending maps.
 *
 * Everything in the message came from a process running as an unprivileged
 * user, so the map id is checked against the range before it indexes anything
 * and the two lengths are checked against the size of the message that carried
 * them.  Neither can go wrong with the fetcher this daemon starts; both would
 * be a way in if it were ever replaced by something else.
 */
static int
handle_entry(struct ypstns_maps *pending, const void *data, size_t len)
{
	const struct ypstns_entry_msg *msg = data;
	char key[YPSTNS_MAX_LINE + 1];
	char val[YPSTNS_MAX_LINE + 1];
	size_t head;

	head = offsetof(struct ypstns_entry_msg, data);
	if (len < head)
		return -1;
	if (msg->map >= MAP_COUNT)
		return -1;
	if ((size_t)msg->key_len + msg->val_len != len - head)
		return -1;
	if (msg->key_len > YPSTNS_MAX_LINE || msg->val_len > YPSTNS_MAX_LINE)
		return -1;

	memcpy(key, msg->data, msg->key_len);
	key[msg->key_len] = '\0';
	memcpy(val, msg->data + msg->key_len, msg->val_len);
	val[msg->val_len] = '\0';

	return maps_add(&pending->m[msg->map], key, val);
}

/*
 * Read whatever the fetcher has sent.
 *
 * A refresh is bracketed: entries accumulate in a second set of maps and are
 * only swapped in when the end of the update arrives.  A fetch that fails
 * halfway therefore leaves the previous directory serving, rather than half a
 * directory - and half a passwd map is a machine most of its users cannot log
 * in to.
 *
 * Returns 0 while the fetcher is still there and -1 once it has gone.
 */
static int
dispatch_client(struct imsgbuf *ibuf, struct ypstns_maps *live, struct ypstns_maps *pending, struct ypstns_conf *conf,
    int *serving)
{
	struct imsg imsg;
	ssize_t n;

	if ((n = imsgbuf_read(ibuf)) == -1)
		return -1;
	if (n == 0)
		return -1; /* the fetcher closed the pipe */

	while ((n = imsg_get(ibuf, &imsg)) > 0) {
		size_t len = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_UPDATE_START:
			maps_free(pending);
			break;

		case IMSG_UPDATE_ENTRY:
			if (handle_entry(pending, imsg.data, len) == -1) {
				logit(LOG_ERR, "malformed entry from the fetcher; abandoning the update");
				maps_free(pending);
			}
			break;

		case IMSG_UPDATE_END:
			maps_sort(pending);
			/*
			 * ypservers is this machine and nothing else.  It is
			 * added here rather than sent, because it is a fact
			 * about the server and not about the directory.
			 */
			{
				char host[256];

				if (gethostname(host, sizeof(host)) == 0)
					(void)maps_add(&pending->m[MAP_YPSERVERS], host, host);
			}
			pending->taken = time(NULL);
			pending->ready = 1;

			maps_free(live);
			*live = *pending;
			maps_init(pending);

			logit(LOG_INFO, "maps updated: %lu users, %lu groups",
			    (unsigned long)live->m[MAP_PASSWD_BYNAME].n,
			    (unsigned long)live->m[MAP_GROUP_BYNAME].n);

			/*
			 * Register with portmap only now.  A YP server that
			 * answers YP_NOMAP while it is starting up tells its
			 * clients passwd.byname does not exist, and a client
			 * that believes that is a machine nobody can log in to.
			 */
			if (!*serving) {
				if (yp_init(conf, live) == -1)
					return -1;
				*serving = 1;
			}
			break;

		case IMSG_UPDATE_FAILED:
			logit(LOG_NOTICE, "the fetcher gave up on this update; keeping the previous maps");
			maps_free(pending);
			break;

		default:
			logit(LOG_ERR, "unexpected message %u from the fetcher", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}

	return (n == -1) ? -1 : 0;
}

int
main(int argc, char *argv[])
{
	const char *conffile = YPSTNS_CONF_FILE;
	struct ypstns_conf conf;
	struct ypstns_maps live, pending;
	struct imsgbuf ibuf;
	struct sigaction sa;
	int pair[2];
	int check_only = 0, n_debug = 0, n_verbose = 0;
	int serving = 0, rv = 1, ch;

	while ((ch = getopt(argc, argv, "dD:f:nv")) != -1) {
		switch (ch) {
		case 'd':
			n_debug = 1;
			break;
		case 'D':
			if (cmdline_symset(optarg) < 0)
				errx(1, "could not parse macro definition %s", optarg);
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			check_only = 1;
			break;
		case 'v':
			n_verbose++;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	/*
	 * -n is expected to work as an ordinary user: it is what an
	 * administrator runs on a file before installing it, and refusing
	 * unless invoked as root would make it useless for that.
	 */
	log_init(check_only ? 1 : n_debug, n_verbose);

	if (parse_config(conffile, &conf) == -1)
		exit(1);

	if (check_only) {
		(void)printf("configuration ok\n");
		(void)printf("  domain    %s\n", conf.domain);
		(void)printf("  user      %s\n", conf.user);
		(void)printf("  interval  %d\n", conf.interval);
		(void)printf("  clients   %s\n", conf.local_only ? "this machine, plus any allowed networks" : "any");
		free_config(&conf);
		return 0;
	}

	if (geteuid() != 0)
		errx(1, "need root privileges");

	maps_init(&live);
	maps_init(&pending);

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pair) == -1)
		fatal("socketpair: %s", strerror(errno));

	switch (client_pid = fork()) {
	case -1:
		fatal("fork: %s", strerror(errno));
	case 0:
		(void)close(pair[0]);
		/* Never returns; drops privileges and pledges on the way in. */
		stnsclient(pair[1], &conf);
		/* NOTREACHED */
	default:
		(void)close(pair[1]);
		break;
	}

	if (!debug && daemon(1, 0) == -1)
		fatal("daemon: %s", strerror(errno));

	setproctitle("[priv]");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_quit;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGTERM, &sa, NULL);
	(void)sigaction(SIGINT, &sa, NULL);

	sa.sa_handler = on_reload;
	(void)sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = on_child;
	(void)sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &sa, NULL);

	if (imsgbuf_init(&ibuf, pair[0]) == -1)
		fatal("imsgbuf_init: %s", strerror(errno));

	/*
	 * Everything this process will ever do is now either a socket or a
	 * message on one it already has: RPC transports, a registration with
	 * portmap(8), the pipe to the fetcher, and syslog.  No file is ever
	 * opened again.
	 *
	 * "proc" is there for one system call.  Reloading means passing the
	 * SIGHUP on to the fetcher, and stopping means passing on a SIGTERM,
	 * and kill(2) is not in "stdio" - it wants "proc", which also covers
	 * the wait4(2) that reaps the child afterwards.  Without it the daemon
	 * came up, served, logged that it was asking the fetcher to refresh,
	 * and was killed by the kernel on the very next instruction, which
	 * looks from the outside exactly like a crash on reload.
	 */
	if (pledge("stdio inet proc", NULL) == -1)
		fatal("pledge: %s", strerror(errno));

	logit(LOG_NOTICE, "ypstns %s starting; waiting for the first update", YPSTNS_VERSION);

	while (!want_quit) {
		fd_set rfds, rpcfds;
		int maxfd, n;

		if (want_reload) {
			want_reload = 0;
			logit(LOG_NOTICE, "asking the fetcher to refresh");
			/*
			 * A reload is a refresh and nothing else.  Re-reading
			 * ypstns.conf here would mean re-reading a file this
			 * process has pledged not to open, and the settings
			 * that matter to the fetcher are behind a privilege
			 * boundary it can no longer cross; ypstns.conf(5) says
			 * so, and rcctl restart is the answer.
			 */
			if (client_pid > 0)
				(void)kill(client_pid, SIGHUP);
		}

		FD_ZERO(&rfds);
		FD_SET(ibuf.fd, &rfds);
		maxfd = ibuf.fd;
		yp_fdset(&rfds, &maxfd);

		n = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			log_warn_errno("select");
			break;
		}

		if (FD_ISSET(ibuf.fd, &rfds)) {
			if (dispatch_client(&ibuf, &live, &pending, &conf, &serving) == -1) {
				logit(LOG_ERR, "the fetcher has gone away");
				break;
			}
		}

		/*
		 * svc_getreqset(3) acts on every descriptor set in what it is
		 * given, so the pipe to the fetcher has to be taken out first
		 * or the RPC layer would try to read a request out of it.
		 */
		rpcfds = rfds;
		FD_CLR(ibuf.fd, &rpcfds);
		yp_dispatch(&rpcfds);
	}

	logit(LOG_NOTICE, "exiting");
	rv = 0;

	yp_shutdown();
	if (client_pid > 0) {
		(void)kill(client_pid, SIGTERM);
		(void)waitpid(client_pid, NULL, 0);
	}
	imsgbuf_clear(&ibuf);
	maps_free(&live);
	maps_free(&pending);
	free_config(&conf);
	closelog();
	return rv;
}
