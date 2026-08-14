/*	$SNOWRABBIT: ypstns.h,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * ypstns - serve an STNS directory to OpenBSD as YP.
 *
 * OpenBSD has no nsswitch(5) and no pluggable directory backend of any other
 * kind.  What it has is YP, which libc has spoken since forever and which
 * getpwnam(3) consults whenever /etc/master.passwd contains a "+" line.  That
 * is the whole reason ypldap(8) is in the base system: it is not that anybody
 * wanted YP, it is that YP is the socket the wall provides.
 *
 * So this is a YP server that answers out of an STNS API server, built the way
 * ypldap(8) is built - a privileged parent that serves the RPC and holds the
 * maps, and an unprivileged child that does the network and hands the entries
 * back over a pipe.
 *
 * The two configuration files are deliberately two.  stns.conf describes the
 * API client, is read by stns-key-wrapper as well, and can be copied verbatim
 * from any other machine running STNS.  ypstns.conf is this daemon's own, and
 * is in the syntax every other OpenBSD daemon uses because it is parsed by the
 * same parse.y that every other one is parsed by.
 */
#ifndef YPSTNS_H
#define YPSTNS_H

#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>

#include <imsg.h>
#include <limits.h>
#include <stdio.h>

#include "stns.h"

#define YPSTNS_VERSION "0.1.0"

#define YPSTNS_USER "_ypstns"
#define YPSTNS_CONF_FILE "/etc/ypstns.conf"
#define YPSTNS_DEFAULT_INTERVAL 60

/*
 * The longest value a map entry can hold, which is not ours to choose.
 *
 * YPMAXRECORD is 1024 and xdr_bytes(3) enforces it: a value longer than that
 * does not get truncated on the way out, it fails to encode, and because
 * YPPROC_ALL is one stream the failure takes the whole map with it.  A group
 * with three hundred members is enough to do it, and the symptom is ypcat(1)
 * reporting "No such map group.byname" for every group on the machine.
 *
 * So an over-long entry is dropped where it is built, with a line in the log
 * naming it.  Losing one group is a poor outcome and losing all of them is a
 * worse one, and truncating a member list would be worse still - that is a
 * group whose membership is quietly wrong rather than visibly absent.
 *
 * It is the limit NIS has always had.  It is also why large groups have always
 * been a problem in NIS, and no amount of care here changes that.
 */
#define YPSTNS_MAX_LINE 1024

/*
 * The messages the fetcher sends the server.
 *
 * A refresh is bracketed by START and END and the server only swaps the new
 * maps in when END arrives, so a fetch that dies halfway through leaves the
 * previous directory in place rather than a partial one.
 */
enum ypstns_imsg_type {
	IMSG_UPDATE_START,
	IMSG_UPDATE_ENTRY,
	IMSG_UPDATE_END,
	IMSG_UPDATE_FAILED
};

/*
 * One map entry, as the fetcher sends it.
 *
 * Everything crosses in this one shape - a passwd line, a group line, a netid
 * line - with the map it belongs in named in the message.  The alternative was
 * a message type per record type, with the server then having to know how a
 * master.passwd line differs from a group line in order to take one apart and
 * put it back together.  This way only the fetcher knows what any of the text
 * means, and the server is a key-value store that happens to speak YP.
 *
 * The strings are packed after the fixed part rather than pointed at, because
 * an imsg is a byte string and a pointer does not survive the trip.  The map
 * id arrives from a process running as an unprivileged user, so the server
 * checks it is in range before indexing anything with it.
 */
struct ypstns_entry_msg {
	uint32_t map; /* enum ypstns_map_id */
	uint16_t key_len;
	uint16_t val_len;
	/* the key, then the value; neither is NUL terminated */
	char data[1];
};

/*
 * One key and value in a map, and a map.
 *
 * Entries are kept sorted by key: YPPROC_MATCH is then a binary search, and
 * YPPROC_FIRST and YPPROC_NEXT are an index walk that visits every entry
 * exactly once.  The YP protocol does not say what order an enumeration comes
 * back in - a real ypserv walks a hash database and produces whatever order
 * that gives - so sorted is as good as anything and rather easier to debug.
 */
struct ypstns_entry {
	char *key;
	char *val;
};

struct ypstns_map {
	const char *name;
	struct ypstns_entry *v;
	size_t n;
	size_t cap;
	/*
	 * Whether the map may only be served to a client on a reserved port.
	 * master.passwd.* is the map with the hashes in it; ypserv(8) makes
	 * the same distinction, and it is the only thing standing between an
	 * unprivileged user on a YP client and every hash in the directory.
	 */
	int privileged;
};

/*
 * Every map served, in one place, so that YPPROC_MAPLIST and the lookup path
 * cannot disagree about which maps exist.
 */
enum ypstns_map_id {
	MAP_PASSWD_BYNAME,
	MAP_PASSWD_BYUID,
	MAP_MASTER_PASSWD_BYNAME,
	MAP_MASTER_PASSWD_BYUID,
	MAP_GROUP_BYNAME,
	MAP_GROUP_BYGID,
	MAP_NETID_BYNAME,
	MAP_YPSERVERS,
	MAP_COUNT
};

struct ypstns_maps {
	struct ypstns_map m[MAP_COUNT];
	time_t taken;
	int ready;
};

/*
 * The daemon's own configuration, as parse.y fills it in.
 */
struct ypstns_conf {
	char domain[HOST_NAME_MAX + 1];
	char *user;
	int interval;
	/*
	 * Whether to answer clients other than this machine.  Off by default:
	 * ypstns is nearly always run beside the ypbind(8) that consumes it,
	 * and a YP server reachable from the network hands the directory to
	 * anybody who can guess the domain name.
	 */
	int local_only;
	/* Networks explicitly allowed, in addition to the loopback. */
	struct ypstns_acl *acl;
	size_t nacl;
};

struct ypstns_acl {
	struct in_addr addr;
	struct in_addr mask;
};

/* parse.y */
int parse_config(const char *filename, struct ypstns_conf *conf);
void free_config(struct ypstns_conf *conf);
int cmdline_symset(char *s);

/* ypstns.c */
extern int debug;
extern int verbose;
void log_init(int, int);
void logit(int, const char *, ...) __attribute__((__format__(printf, 2, 3)));
void log_warn_errno(const char *, ...) __attribute__((__format__(printf, 1, 2)));
__dead void fatal(const char *, ...) __attribute__((__format__(printf, 1, 2)));

/* stnsclient.c */
__dead void stnsclient(int fd, const struct ypstns_conf *conf);

/* maps.c */
void maps_init(struct ypstns_maps *maps);
void maps_free(struct ypstns_maps *maps);
int maps_add(struct ypstns_map *map, const char *key, const char *val);
void maps_sort(struct ypstns_maps *maps);
const struct ypstns_map *maps_find(const struct ypstns_maps *maps, const char *name);
const char *map_match(const struct ypstns_map *map, const char *key);
const struct ypstns_entry *map_first(const struct ypstns_map *map);
const struct ypstns_entry *map_next(const struct ypstns_map *map, const char *key);

/* yp.c */
int yp_init(struct ypstns_conf *conf, struct ypstns_maps *maps);
void yp_shutdown(void);
void yp_fdset(fd_set *set, int *maxfd);
void yp_dispatch(fd_set *set);

#endif /* YPSTNS_H */
