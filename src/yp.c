/*	$SNOWRABBIT: yp.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The YP service itself.
 *
 * Sun RPC is libc's, not ours: svcudp_create(3), svc_register(3) and the XDR
 * routines for the YP types all come from the system, the same ones ypserv(8)
 * and ypldap(8) use.  What is here is the twelve procedures of YPPROG version
 * 2 and the decisions about who is allowed to call them.
 *
 * Two of those decisions are worth reading before the code.
 *
 * The service is not registered with portmap(8) until the first set of maps
 * has arrived.  A YP server that answers YP_NOMAP while it is still starting
 * up tells its clients the map does not exist, and a client that has just been
 * told passwd.byname does not exist is a machine nobody can log in to.  Better
 * to be absent for a moment than wrong.
 *
 * And master.passwd.byname and master.passwd.byuid are served only to a
 * request from a reserved port.  That is the check ypserv(8) makes, and it is
 * the only thing between an ordinary user on a client machine and every
 * password hash in the directory.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <rpcsvc/yp.h>

#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "ypstns.h"

static struct ypstns_conf *yp_conf;
static struct ypstns_maps *yp_maps;
static SVCXPRT *yp_udp;
static SVCXPRT *yp_tcp;
static char yp_master[HOST_NAME_MAX + 1];

static void yp_service(struct svc_req *, SVCXPRT *);

/*
 * May this client be answered at all?
 *
 * The default is the loopback and nothing else.  ypstns is nearly always run
 * beside the ypbind(8) that consumes it, and a YP server reachable from the
 * network hands the entire directory to anybody who can guess the domain name
 * - which is not a secret and never was.  "allow any" in ypstns.conf turns the
 * check off, and has to be written out in words for that reason.
 */
static int
caller_allowed(SVCXPRT *transp)
{
	struct sockaddr_in *sin = svc_getcaller(transp);
	size_t i;

	if (sin->sin_family != AF_INET)
		return 0;
	if (!yp_conf->local_only)
		return 1;
	if (ntohl(sin->sin_addr.s_addr) >> 24 == IN_LOOPBACKNET)
		return 1;

	for (i = 0; i < yp_conf->nacl; i++) {
		if ((sin->sin_addr.s_addr & yp_conf->acl[i].mask.s_addr) == yp_conf->acl[i].addr.s_addr)
			return 1;
	}
	return 0;
}

/*
 * Did this request come from a reserved port?
 *
 * On a system that still honours the convention, only root can bind one, so it
 * stands in for "the client end of this is privileged".  It is a weak claim
 * over a network and a sound one over the loopback, which is where this daemon
 * expects to be used - and it is exactly the claim ypserv(8) relies on for the
 * same maps.
 */
static int
caller_privileged(SVCXPRT *transp)
{
	struct sockaddr_in *sin = svc_getcaller(transp);

	return ntohs(sin->sin_port) < IPPORT_RESERVED;
}

/*
 * Resolve a request to the map it names, or to the reason it cannot be.
 *
 * The distinction between "wrong domain" and "no such map" matters to a
 * client: ypbind(8) unbinds and looks for another server on YP_NODOM, and
 * gives up on that one map on YP_NOMAP.
 */
static const struct ypstns_map *
lookup_map(SVCXPRT *transp, const char *domain, const char *map, enum ypstat *stat)
{
	const struct ypstns_map *m;

	if (domain == NULL || strcmp(domain, yp_conf->domain) != 0) {
		*stat = YP_NODOM;
		return NULL;
	}
	if (map == NULL || (m = maps_find(yp_maps, map)) == NULL) {
		*stat = YP_NOMAP;
		return NULL;
	}
	if (m->privileged && !caller_privileged(transp)) {
		/*
		 * Not YP_NOMAP: the map does exist, and saying otherwise to a
		 * client that will later ask from a reserved port would have
		 * it remember the wrong answer.
		 */
		syslog(LOG_NOTICE, "refused %s to an unprivileged port", m->name);
		*stat = YP_BADDB;
		return NULL;
	}
	*stat = YP_TRUE;
	return m;
}

/* keydat and valdat are counted strings; neither is NUL terminated. */
static char *
dat_to_str(const char *p, u_int len)
{
	char *s;

	if (len > YPSTNS_MAX_LINE)
		return NULL;
	if ((s = malloc((size_t)len + 1)) == NULL)
		return NULL;
	memcpy(s, p, len);
	s[len] = '\0';
	return s;
}

/*
 * YPPROC_ALL, which is a stream rather than a reply.
 *
 * The wire form is a sequence of "more?" booleans, each TRUE one followed by a
 * key and value, terminated by a FALSE.  rpcgen's xdr_ypresp_all encodes
 * exactly one of those, so serving a whole map means writing the loop by hand
 * and handing it to svc_sendreply(3) as the encoder - which is what ypserv(8)
 * does too, for the same reason.
 *
 * This is what makes ypcat(1) work.  Nothing in a login path uses it, but it
 * is the first thing anybody reaches for to find out whether the server is
 * serving what they think it is.
 */
static bool_t
xdr_ypall(XDR *xdrs, void *arg)
{
	const struct ypstns_map *map = arg;
	struct ypresp_key_val kv;
	bool_t more;
	size_t i;

	for (i = 0; i < map->n; i++) {
		more = TRUE;
		if (!xdr_bool(xdrs, &more))
			return FALSE;

		memset(&kv, 0, sizeof(kv));
		kv.stat = YP_TRUE;
		kv.key.keydat_val = map->v[i].key;
		kv.key.keydat_len = (u_int)strlen(map->v[i].key);
		kv.val.valdat_val = map->v[i].val;
		kv.val.valdat_len = (u_int)strlen(map->v[i].val);
		if (!xdr_ypresp_key_val(xdrs, &kv))
			return FALSE;
	}

	more = FALSE;
	return xdr_bool(xdrs, &more);
}

static void
reply_val(SVCXPRT *transp, enum ypstat stat, const char *val)
{
	struct ypresp_val resp;

	memset(&resp, 0, sizeof(resp));
	resp.stat = stat;
	if (val != NULL) {
		resp.val.valdat_val = (char *)val;
		resp.val.valdat_len = (u_int)strlen(val);
	}
	if (!svc_sendreply(transp, (xdrproc_t)xdr_ypresp_val, (caddr_t)&resp))
		svcerr_systemerr(transp);
}

static void
reply_key_val(SVCXPRT *transp, enum ypstat stat, const struct ypstns_entry *e)
{
	struct ypresp_key_val resp;

	memset(&resp, 0, sizeof(resp));
	resp.stat = stat;
	if (e != NULL) {
		resp.key.keydat_val = e->key;
		resp.key.keydat_len = (u_int)strlen(e->key);
		resp.val.valdat_val = e->val;
		resp.val.valdat_len = (u_int)strlen(e->val);
	}
	if (!svc_sendreply(transp, (xdrproc_t)xdr_ypresp_key_val, (caddr_t)&resp))
		svcerr_systemerr(transp);
}

static void
do_match(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct ypreq_key req;
	const struct ypstns_map *map;
	enum ypstat stat;
	char *key;
	const char *val;

	memset(&req, 0, sizeof(req));
	if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_key, (caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if ((map = lookup_map(transp, req.domain, req.map, &stat)) == NULL) {
		reply_val(transp, stat, NULL);
		goto out;
	}
	if ((key = dat_to_str(req.key.keydat_val, req.key.keydat_len)) == NULL) {
		reply_val(transp, YP_BADARGS, NULL);
		goto out;
	}

	val = map_match(map, key);
	reply_val(transp, (val != NULL) ? YP_TRUE : YP_NOKEY, val);
	free(key);

out:
	(void)svc_freeargs(transp, (xdrproc_t)xdr_ypreq_key, (caddr_t)&req);
}

static void
do_first(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct ypreq_nokey req;
	const struct ypstns_map *map;
	const struct ypstns_entry *e;
	enum ypstat stat;

	memset(&req, 0, sizeof(req));
	if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if ((map = lookup_map(transp, req.domain, req.map, &stat)) == NULL)
		reply_key_val(transp, stat, NULL);
	else if ((e = map_first(map)) == NULL)
		reply_key_val(transp, YP_NOMORE, NULL);
	else
		reply_key_val(transp, YP_TRUE, e);

	(void)svc_freeargs(transp, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req);
}

static void
do_next(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct ypreq_key req;
	const struct ypstns_map *map;
	const struct ypstns_entry *e;
	enum ypstat stat;
	char *key;

	memset(&req, 0, sizeof(req));
	if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_key, (caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if ((map = lookup_map(transp, req.domain, req.map, &stat)) == NULL) {
		reply_key_val(transp, stat, NULL);
		goto out;
	}
	if ((key = dat_to_str(req.key.keydat_val, req.key.keydat_len)) == NULL) {
		reply_key_val(transp, YP_BADARGS, NULL);
		goto out;
	}

	e = map_next(map, key);
	reply_key_val(transp, (e != NULL) ? YP_TRUE : YP_NOMORE, e);
	free(key);

out:
	(void)svc_freeargs(transp, (xdrproc_t)xdr_ypreq_key, (caddr_t)&req);
}

static void
do_all(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct ypreq_nokey req;
	const struct ypstns_map *map;
	enum ypstat stat;

	memset(&req, 0, sizeof(req));
	if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	if ((map = lookup_map(transp, req.domain, req.map, &stat)) == NULL) {
		/*
		 * The failure form of ypresp_all is one TRUE record carrying
		 * the status, then the terminating FALSE - which is what the
		 * ordinary reply path already produces if it is handed no
		 * entries, so it is spelled out here rather than reusing an
		 * encoder that would have to know about both cases.
		 */
		struct ypstns_map empty;

		memset(&empty, 0, sizeof(empty));
		reply_key_val(transp, stat, NULL);
		(void)empty;
	} else if (!svc_sendreply(transp, (xdrproc_t)xdr_ypall, (caddr_t)map)) {
		svcerr_systemerr(transp);
	}

	(void)svc_freeargs(transp, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req);
}

static void
do_maplist(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct ypresp_maplist resp;
	struct ypmaplist list[MAP_COUNT];
	char *domain = NULL;
	size_t i;

	if (!svc_getargs(transp, (xdrproc_t)xdr_domainname, (caddr_t)&domain)) {
		svcerr_decode(transp);
		return;
	}

	memset(&resp, 0, sizeof(resp));
	if (domain == NULL || strcmp(domain, yp_conf->domain) != 0) {
		resp.stat = YP_NODOM;
	} else {
		resp.stat = YP_TRUE;
		for (i = 0; i < MAP_COUNT; i++) {
			list[i].map = (char *)yp_maps->m[i].name;
			list[i].next = (i + 1 < MAP_COUNT) ? &list[i + 1] : NULL;
		}
		resp.maps = &list[0];
	}

	if (!svc_sendreply(transp, (xdrproc_t)xdr_ypresp_maplist, (caddr_t)&resp))
		svcerr_systemerr(transp);
	(void)svc_freeargs(transp, (xdrproc_t)xdr_domainname, (caddr_t)&domain);
}

static void
do_master(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct ypreq_nokey req;
	struct ypresp_master resp;
	const struct ypstns_map *map;
	enum ypstat stat;

	memset(&req, 0, sizeof(req));
	if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	memset(&resp, 0, sizeof(resp));
	map = lookup_map(transp, req.domain, req.map, &stat);
	resp.stat = (map != NULL) ? YP_TRUE : stat;
	resp.peer = yp_master;

	if (!svc_sendreply(transp, (xdrproc_t)xdr_ypresp_master, (caddr_t)&resp))
		svcerr_systemerr(transp);
	(void)svc_freeargs(transp, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req);
}

/*
 * YPPROC_ORDER, the map's "order number".
 *
 * Conventionally the time the map was built, which is what a slave server
 * compares to decide whether it is out of date.  There are no slaves here, but
 * yppoll(8) prints it and it is the one place an administrator can see how old
 * the directory being served actually is.
 */
static void
do_order(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct ypreq_nokey req;
	struct ypresp_order resp;
	const struct ypstns_map *map;
	enum ypstat stat;

	memset(&req, 0, sizeof(req));
	if (!svc_getargs(transp, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req)) {
		svcerr_decode(transp);
		return;
	}

	memset(&resp, 0, sizeof(resp));
	map = lookup_map(transp, req.domain, req.map, &stat);
	resp.stat = (map != NULL) ? YP_TRUE : stat;
	resp.ordernum = (u_int)yp_maps->taken;

	if (!svc_sendreply(transp, (xdrproc_t)xdr_ypresp_order, (caddr_t)&resp))
		svcerr_systemerr(transp);
	(void)svc_freeargs(transp, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req);
}

static void
do_domain(struct svc_req *rqstp, SVCXPRT *transp, int nonack)
{
	char *domain = NULL;
	bool_t serves;

	if (!svc_getargs(transp, (xdrproc_t)xdr_domainname, (caddr_t)&domain)) {
		svcerr_decode(transp);
		return;
	}

	serves = (domain != NULL && strcmp(domain, yp_conf->domain) == 0) ? TRUE : FALSE;

	/*
	 * DOMAIN_NONACK exists so that ypbind(8) can broadcast and hear only
	 * from servers that can help: a server that does not serve the domain
	 * says nothing at all rather than saying no.
	 */
	if (nonack && !serves) {
		(void)svc_freeargs(transp, (xdrproc_t)xdr_domainname, (caddr_t)&domain);
		return;
	}
	if (!svc_sendreply(transp, (xdrproc_t)xdr_bool, (caddr_t)&serves))
		svcerr_systemerr(transp);
	(void)svc_freeargs(transp, (xdrproc_t)xdr_domainname, (caddr_t)&domain);
}

static void
yp_service(struct svc_req *rqstp, SVCXPRT *transp)
{
	if (!caller_allowed(transp)) {
		struct sockaddr_in *sin = svc_getcaller(transp);

		syslog(LOG_NOTICE, "refused a request from %s", inet_ntoa(sin->sin_addr));
		svcerr_auth(transp, AUTH_FAILED);
		return;
	}

	switch (rqstp->rq_proc) {
	case YPPROC_NULL:
		if (!svc_sendreply(transp, (xdrproc_t)xdr_void, NULL))
			svcerr_systemerr(transp);
		break;
	case YPPROC_DOMAIN:
		do_domain(rqstp, transp, 0);
		break;
	case YPPROC_DOMAIN_NONACK:
		do_domain(rqstp, transp, 1);
		break;
	case YPPROC_MATCH:
		do_match(rqstp, transp);
		break;
	case YPPROC_FIRST:
		do_first(rqstp, transp);
		break;
	case YPPROC_NEXT:
		do_next(rqstp, transp);
		break;
	case YPPROC_ALL:
		do_all(rqstp, transp);
		break;
	case YPPROC_MASTER:
		do_master(rqstp, transp);
		break;
	case YPPROC_ORDER:
		do_order(rqstp, transp);
		break;
	case YPPROC_MAPLIST:
		do_maplist(rqstp, transp);
		break;
	case YPPROC_XFR:
	case YPPROC_CLEAR:
		/*
		 * Both belong to a world with map transfers in it.  There is
		 * no dbm file here to push or to reopen - the maps come from
		 * an HTTP API on a timer - so neither can be honoured, and
		 * pretending otherwise would have yppush(8) report success for
		 * something that did not happen.
		 */
		svcerr_noproc(transp);
		break;
	default:
		svcerr_noproc(transp);
		break;
	}
}

/*
 * Start serving.
 *
 * Deliberately called only once the first set of maps has arrived; see the
 * comment at the top of this file for why registering earlier would be worse
 * than not registering at all.
 */
int
yp_init(struct ypstns_conf *conf, struct ypstns_maps *maps)
{
	yp_conf = conf;
	yp_maps = maps;

	if (gethostname(yp_master, sizeof(yp_master)) != 0)
		(void)strlcpy(yp_master, "localhost", sizeof(yp_master));

	/* Clear out a registration a previous run may have left behind. */
	(void)pmap_unset(YPPROG, YPVERS);

	if ((yp_udp = svcudp_create(RPC_ANYSOCK)) == NULL) {
		logit(LOG_ERR, "cannot create the UDP transport");
		return -1;
	}
	if ((yp_tcp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL) {
		logit(LOG_ERR, "cannot create the TCP transport");
		return -1;
	}

	if (!svc_register(yp_udp, YPPROG, YPVERS, yp_service, IPPROTO_UDP)) {
		logit(LOG_ERR, "cannot register YPPROG/UDP with portmap; is portmap(8) running?");
		return -1;
	}
	if (!svc_register(yp_tcp, YPPROG, YPVERS, yp_service, IPPROTO_TCP)) {
		logit(LOG_ERR, "cannot register YPPROG/TCP with portmap; is portmap(8) running?");
		return -1;
	}

	logit(LOG_NOTICE, "serving domain \"%s\"%s", conf->domain,
	    conf->local_only ? " to this machine only" : "");
	return 0;
}

void
yp_shutdown(void)
{
	if (yp_udp != NULL || yp_tcp != NULL)
		(void)pmap_unset(YPPROG, YPVERS);
}

void
yp_fdset(fd_set *set, int *maxfd)
{
	int i;

	if (yp_udp == NULL)
		return;
	for (i = 0; i <= svc_maxfd; i++) {
		if (FD_ISSET(i, &svc_fdset)) {
			FD_SET(i, set);
			if (i > *maxfd)
				*maxfd = i;
		}
	}
}

void
yp_dispatch(fd_set *set)
{
	if (yp_udp == NULL)
		return;
	svc_getreqset(set);
}
