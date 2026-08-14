/*	$SNOWRABBIT: stnsclient.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The fetcher: the half of ypstns that talks to the network.
 *
 * It runs as _ypstns, with the tightest pledge(2) that still lets libcurl
 * work, and it is the only process here that touches the API at all.  What it
 * sends back are finished map entries - a passwd line, a group line, a netid
 * line, each with the name of the map it belongs in - so that the privileged
 * process on the other end of the pipe never has to parse anything, and never
 * has to know what any of the text means.
 *
 * This is the ypldap(8) arrangement, for the ypldap(8) reason: the code that
 * has to speak to the outside world and the code that has to hold root are
 * kept in different processes, and the only thing between them is a pipe
 * carrying messages of a shape both agree on in advance.
 */
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "ypstns.h"

static volatile sig_atomic_t refresh_now;
static volatile sig_atomic_t quit;

static void
on_hup(int sig)
{
	refresh_now = 1;
}

static void
on_quit(int sig)
{
	quit = 1;
}

/*
 * Hand one finished entry to the server.
 *
 * An entry too long for a single imsg is dropped rather than split, and the
 * only thing that can produce one is a group with an implausible number of
 * members.  Half a member list is a group whose membership is silently wrong,
 * which is worse than a group that is visibly absent and named in the log.
 */
static int
send_entry(struct imsgbuf *ibuf, enum ypstns_map_id map, const char *key, const char *val)
{
	struct ypstns_entry_msg *msg;
	size_t klen, vlen, len;
	int rv;

	klen = strlen(key);
	vlen = strlen(val);
	if (klen > UINT16_MAX || vlen > UINT16_MAX || vlen > YPSTNS_MAX_LINE) {
		logit(LOG_NOTICE, "dropping over-long entry \"%s\" from %d", key, (int)map);
		return 0;
	}

	len = offsetof(struct ypstns_entry_msg, data) + klen + vlen;
	if ((msg = malloc(len)) == NULL)
		return -1;

	msg->map = (uint32_t)map;
	msg->key_len = (uint16_t)klen;
	msg->val_len = (uint16_t)vlen;
	memcpy(msg->data, key, klen);
	memcpy(msg->data + klen, val, vlen);

	rv = imsg_compose(ibuf, IMSG_UPDATE_ENTRY, 0, 0, -1, msg, len);
	free(msg);
	return (rv == -1) ? -1 : 0;
}

/*
 * Everything one user contributes to the maps.
 *
 * The passwd maps get the hash masked out and the master.passwd maps get it as
 * the API sent it - which is exactly the split /etc/passwd and
 * /etc/master.passwd make locally, and the reason the privileged maps are
 * marked privileged in maps.c.
 */
static int
send_user(struct imsgbuf *ibuf, const stns_user_t *u)
{
	char key[STNS_MAXBUF];
	char line[YPSTNS_MAX_LINE];

	(void)snprintf(line, sizeof(line), "%s:*:%lu:%lu:%s:%s:%s", u->name, (unsigned long)u->uid,
	    (unsigned long)u->gid, u->gecos, u->directory, u->shell);
	if (send_entry(ibuf, MAP_PASSWD_BYNAME, u->name, line) == -1)
		return -1;

	(void)snprintf(key, sizeof(key), "%lu", (unsigned long)u->uid);
	if (send_entry(ibuf, MAP_PASSWD_BYUID, key, line) == -1)
		return -1;

	/*
	 * The ten fields of a master.passwd line: name, password, uid, gid,
	 * class, change, expire, gecos, home directory and shell.  The class
	 * is left empty so that login.conf's "default" applies, and neither a
	 * password change nor an expiry time is set - STNS has nowhere to
	 * record either, and inventing one would age accounts out.
	 */
	(void)snprintf(line, sizeof(line), "%s:%s:%lu:%lu::0:0:%s:%s:%s", u->name, u->password,
	    (unsigned long)u->uid, (unsigned long)u->gid, u->gecos, u->directory, u->shell);
	if (send_entry(ibuf, MAP_MASTER_PASSWD_BYNAME, u->name, line) == -1)
		return -1;
	if (send_entry(ibuf, MAP_MASTER_PASSWD_BYUID, key, line) == -1)
		return -1;

	return 0;
}

static int
send_group(struct imsgbuf *ibuf, const stns_group_t *g)
{
	char key[STNS_MAXBUF];
	char line[YPSTNS_MAX_LINE];
	size_t i, off;
	int n;

	n = snprintf(line, sizeof(line), "%s:*:%lu:", g->name, (unsigned long)g->gid);
	if (n < 0 || (size_t)n >= sizeof(line))
		return 0;
	off = (size_t)n;

	for (i = 0; i < g->users_size; i++) {
		n = snprintf(line + off, sizeof(line) - off, "%s%s", (i > 0) ? "," : "", g->users[i]);
		if (n < 0 || (size_t)n >= sizeof(line) - off) {
			logit(LOG_NOTICE, "group \"%s\" has too many members for one map entry; "
					   "dropping it",
			    g->name);
			return 0;
		}
		off += (size_t)n;
	}

	if (send_entry(ibuf, MAP_GROUP_BYNAME, g->name, line) == -1)
		return -1;
	(void)snprintf(key, sizeof(key), "%lu", (unsigned long)g->gid);
	return send_entry(ibuf, MAP_GROUP_BYGID, key, line);
}

/*
 * netid.byname, which maps a user to every group id they hold.
 *
 * It is the map getgrouplist(3) would use if it used YP for supplementary
 * groups, and the one Secure RPC reads.  Building it needs both listings at
 * once, which is why it happens here and not alongside the groups.
 *
 * An entry is "unix.<uid>@<domain>" -> "<uid>:<gid>,<gid>,...".  Note what is
 * on each side of the colon: the uid, and then the group list beginning with
 * the primary group.  It is not the gid twice, however much the shape of the
 * key suggests it should be.
 */
static int
send_netid(struct imsgbuf *ibuf, const struct ypstns_conf *conf, const stns_user_t *users, size_t nusers,
    const stns_group_t *groups, size_t ngroups)
{
	char key[STNS_MAXBUF];
	char line[YPSTNS_MAX_LINE];
	size_t i, j, k, off;
	int n;

	for (i = 0; i < nusers; i++) {
		n = snprintf(line, sizeof(line), "%lu:%lu", (unsigned long)users[i].uid,
		    (unsigned long)users[i].gid);
		if (n < 0 || (size_t)n >= sizeof(line))
			continue;
		off = (size_t)n;

		for (j = 0; j < ngroups; j++) {
			if (groups[j].gid == users[i].gid)
				continue; /* already there as the primary */
			for (k = 0; k < groups[j].users_size; k++) {
				if (strcmp(groups[j].users[k], users[i].name) != 0)
					continue;
				n = snprintf(line + off, sizeof(line) - off, ",%lu",
				    (unsigned long)groups[j].gid);
				if (n < 0 || (size_t)n >= sizeof(line) - off)
					break;
				off += (size_t)n;
				break;
			}
		}

		(void)snprintf(key, sizeof(key), "unix.%lu@%s", (unsigned long)users[i].uid, conf->domain);
		if (send_entry(ibuf, MAP_NETID_BYNAME, key, line) == -1)
			return -1;
	}
	return 0;
}

/*
 * One pass: fetch the directory and send it across.
 *
 * A failure anywhere before IMSG_UPDATE_END means the server keeps what it
 * already had.  That is the point of bracketing the update: an API server that
 * is briefly unreachable, or a fetcher that runs out of memory halfway, must
 * not leave the machine with half a directory - or with none, which for a
 * passwd map means nobody in it can log in.
 *
 * The return value is about the pipe and nothing else.  A fetch that failed is
 * an ordinary event to be tried again next interval, and reporting it as fatal
 * here is how an API server going away for ten seconds came to stop the whole
 * daemon: the fetcher exited, the parent saw SIGCHLD, and a machine that would
 * have carried on serving a slightly stale directory served nothing instead.
 */
static int
refresh(struct imsgbuf *ibuf, stns_conf_t *sc, const struct ypstns_conf *conf)
{
	stns_user_t *users = NULL;
	stns_group_t *groups = NULL;
	size_t nusers = 0, ngroups = 0, i;
	int rv = -1;

	if (stns_list_users(sc, &users, &nusers) != STNS_LOOKUP_SUCCESS) {
		logit(LOG_ERR, "cannot list users; keeping the previous maps");
		goto fail;
	}
	if (stns_list_groups(sc, &groups, &ngroups) != STNS_LOOKUP_SUCCESS) {
		logit(LOG_ERR, "cannot list groups; keeping the previous maps");
		goto fail;
	}

	if (imsg_compose(ibuf, IMSG_UPDATE_START, 0, 0, -1, NULL, 0) == -1)
		goto fail;

	for (i = 0; i < nusers; i++) {
		if (send_user(ibuf, &users[i]) == -1)
			goto fail;
	}
	for (i = 0; i < ngroups; i++) {
		if (send_group(ibuf, &groups[i]) == -1)
			goto fail;
	}
	if (send_netid(ibuf, conf, users, nusers, groups, ngroups) == -1)
		goto fail;

	if (imsg_compose(ibuf, IMSG_UPDATE_END, 0, 0, -1, NULL, 0) == -1)
		goto fail;

	logit(LOG_INFO, "sent %lu users and %lu groups", (unsigned long)nusers, (unsigned long)ngroups);
	rv = 0;

fail:
	if (rv != 0)
		(void)imsg_compose(ibuf, IMSG_UPDATE_FAILED, 0, 0, -1, NULL, 0);
	stns_free_users(users, nusers);
	stns_free_groups(groups, ngroups);

	if (imsgbuf_flush(ibuf) == -1) {
		logit(LOG_ERR, "the server has gone away");
		return -1;
	}
	return 0;
}

/*
 * Give up root, and then give up almost everything else.
 *
 * unveil(2) comes before pledge(2) because pledge("stdio") would forbid the
 * unveil call itself.  What is left visible is what libcurl actually opens: a
 * resolver configuration, a trust store, and whatever TLS material stns.conf
 * names.  Everything else on the filesystem, including stns.conf itself, is
 * gone - it was read by the parent while it was still root and is already in
 * memory here.
 */
static void
restrict_self(const struct ypstns_conf *conf, const stns_conf_t *sc)
{
	struct passwd *pw;
	char promises[64];

	if ((pw = getpwnam(conf->user)) == NULL)
		fatal("no such user \"%s\"", conf->user);

	if (setgroups(1, &pw->pw_gid) == -1)
		fatal("setgroups");
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		fatal("setresgid");
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("setresuid");

	if (unveil("/etc/resolv.conf", "r") == -1 || unveil("/etc/hosts", "r") == -1 ||
	    unveil("/etc/services", "r") == -1 || unveil("/etc/ssl", "r") == -1)
		fatal("unveil");
	if (sc->tls_ca != NULL && unveil(sc->tls_ca, "r") == -1)
		fatal("unveil %s", sc->tls_ca);
	if (sc->tls_cert != NULL && unveil(sc->tls_cert, "r") == -1)
		fatal("unveil %s", sc->tls_cert);
	if (sc->tls_key != NULL && unveil(sc->tls_key, "r") == -1)
		fatal("unveil %s", sc->tls_key);
	if (sc->cached_enable && sc->cached_unix_socket != NULL && unveil(sc->cached_unix_socket, "rw") == -1)
		fatal("unveil %s", sc->cached_unix_socket);
	if (unveil(NULL, NULL) == -1)
		fatal("unveil lock");

	/*
	 * "unix" only when talking to cache-stnsd, because otherwise there is
	 * no unix socket to connect to and the promise would be a permission
	 * this process has no use for.
	 */
	(void)strlcpy(promises, "stdio rpath inet dns", sizeof(promises));
	if (sc->cached_enable)
		(void)strlcat(promises, " unix", sizeof(promises));
	if (pledge(promises, NULL) == -1)
		fatal("pledge");
}

__dead void
stnsclient(int fd, const struct ypstns_conf *conf)
{
	struct imsgbuf ibuf;
	struct pollfd pfd;
	struct sigaction sa;
	stns_conf_t sc;
	time_t next;

	setproctitle("stnsclient");

	/*
	 * Read stns.conf here, in the child, but before privileges are given
	 * up: it may hold an API token and be readable by root alone.  It is
	 * never read again - a change to it needs a restart, which is said in
	 * ypstns.conf(5) - so nothing after this point needs to reach it.
	 */
	if (stns_load_config(stns_config_path(), &sc) != STNS_OK)
		fatal("cannot load %s", stns_config_path());

	/*
	 * Turn the library's own on-disk cache off, whatever stns.conf says.
	 *
	 * The daemon already holds the whole directory and refreshes it on its
	 * own interval, so the cache would be a second and staler copy of
	 * something already in memory.  Leaving it on would also mean this
	 * process needed wpath and cpath, which is a great deal to give up for
	 * a copy nothing reads.
	 */
	sc.cache = 0;

	/*
	 * And refuse query_wrapper here, for a harder reason.
	 *
	 * It runs a command with popen(3), and this process is about to pledge
	 * itself without "exec".  Leaving it set would not make the wrapper
	 * fail politely - it would abort the fetcher the first time a refresh
	 * came round, which is a fine way to spend an afternoon working out why
	 * the maps stopped updating.  Saying so once at startup is better.
	 * stns-key-wrapper is a separate program with no pledge and honours it
	 * as it always did.
	 */
	/*
	 * And the circuit breaker, for a harder reason still.
	 *
	 * Tripping it means creating a lock file, and this process is pledged
	 * without cpath - so the first time the API server refused a connection
	 * the kernel would kill the fetcher, the parent would see SIGCHLD, and
	 * a ten second outage at the API would become a YP server that had to
	 * be restarted by hand.  There is nothing for it to protect anybody
	 * from here anyway: the breaker exists because a name lookup happens in
	 * every process on the machine, and this is one process on a timer.
	 */
	sc.request_locktime = 0;

	if (sc.query_wrapper != NULL) {
		logit(LOG_NOTICE, "ignoring query_wrapper: the fetcher is pledged without \"exec\"");
		free(sc.query_wrapper);
		sc.query_wrapper = NULL;
	}

	restrict_self(conf, &sc);

	/*
	 * sigaction(2) rather than signal(3), and without SA_RESTART.
	 *
	 * signal(3) on this system installs a handler with BSD semantics,
	 * which restarts an interrupted system call - and the poll(2) below is
	 * how the interval is waited out.  A restarted poll swallows the
	 * signal entirely: SIGHUP would set the flag and then nothing would
	 * look at it until the interval expired on its own, which with the
	 * default of an hour looks exactly like a reload that does not work.
	 */
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = on_hup;
	(void)sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = on_quit;
	(void)sigaction(SIGTERM, &sa, NULL);
	(void)sigaction(SIGINT, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &sa, NULL);

	if (imsgbuf_init(&ibuf, fd) == -1)
		fatal("imsgbuf_init");

	/* The first pass happens at once; nothing can be served until it does. */
	(void)refresh(&ibuf, &sc, conf);
	next = time(NULL) + conf->interval;

	while (!quit) {
		time_t now;
		int timeout, n;

		if (refresh_now) {
			refresh_now = 0;
			logit(LOG_INFO, "refreshing on SIGHUP");
			if (refresh(&ibuf, &sc, conf) == -1)
				break;
			next = time(NULL) + conf->interval;
		}

		now = time(NULL);
		timeout = (next > now) ? (int)((next - now) * 1000) : 0;

		/*
		 * Nothing is ever read from this socket; it is polled so that
		 * the parent going away shows up as a hangup rather than as a
		 * fetcher that carries on talking to a closed pipe for ever.
		 *
		 * revents is cleared first and only believed when poll(2)
		 * reports something, because poll does not touch it otherwise -
		 * so reading it after an EINTR return means acting on whatever
		 * the last call left behind, or on nothing at all the first
		 * time round.  Which is a fetcher that exits the moment
		 * anybody sends it a SIGHUP.
		 */
		pfd.fd = fd;
		pfd.events = 0;
		pfd.revents = 0;
		n = poll(&pfd, 1, timeout);
		if (n == -1 && errno != EINTR)
			break;
		if (n > 0 && (pfd.revents & (POLLHUP | POLLERR)))
			break;

		if (time(NULL) >= next) {
			(void)refresh(&ibuf, &sc, conf);
			next = time(NULL) + conf->interval;
		}
	}

	imsgbuf_clear(&ibuf);
	stns_unload_config(&sc);
	exit(0);
}
