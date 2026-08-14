/*	$SNOWRABBIT: yp_client.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * A YP client that talks to the server directly, for tests/integration.sh.
 *
 * ypmatch(1) and ypcat(1) go through ypbind(8), which is the right thing to
 * test and the wrong thing to test *with*: a failure could be ypbind, the
 * binding file, the domain name or the server, and the point of this program
 * is to take all but the last of those out of the picture.  It asks portmap(8)
 * where ypstns is and then speaks YPPROG to it, so what it exercises is the
 * dispatch in yp.c and the encoding in yp_xdr.c and nothing else.
 *
 * It also does the one thing no stock tool will: ask from a port of its own
 * choosing.  master.passwd.byname is served only to a client on a reserved
 * port, and -n is how the test proves that the refusal actually happens rather
 * than merely being written down in yp.c.
 *
 * Output is one line per result, so that a shell script can diff it:
 *
 *	<value>				match
 *	<key> <value>			first, next, all
 *	<name>				maplist
 *	yes | no			domain
 *	stat <n>			anything the server refused
 */
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <rpcsvc/yp.h>

#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct timeval timeout = { 10, 0 };

static void
usage(void)
{
	fprintf(stderr, "usage: yp_client [-n] [-t] [-a address] domain "
			"{match map key | first map | next map key | all map | "
			"maplist | domain | null}\n");
	exit(2);
}

/*
 * A client bound to a port of our choosing.
 *
 * By default a reserved one, because that is what libc's YP client uses and
 * what the privileged maps require; with unpriv set, whatever the kernel
 * hands out, which is what an ordinary user on a YP client would have.
 */
static CLIENT *
make_client(const char *addr, int unpriv, int tcp)
{
	struct sockaddr_in sin;
	CLIENT *cl;
	int sock;
	u_short port;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	/*
	 * The loopback unless told otherwise.  -a exists so that a request can
	 * be made to the machine's own external address instead, which is the
	 * only way to find out whether "allow" in ypstns.conf is doing
	 * anything: from the loopback every configuration answers.
	 */
	if (addr == NULL)
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else if (inet_pton(AF_INET, addr, &sin.sin_addr) != 1)
		errx(1, "\"%s\" is not an IPv4 address", addr);

	port = pmap_getport(&sin, YPPROG, YPVERS, tcp ? IPPROTO_TCP : IPPROTO_UDP);
	if (port == 0)
		errx(1, "YPPROG version %lu is not registered with portmap", (unsigned long)YPVERS);
	sin.sin_port = htons(port);

	/*
	 * The socket is made here rather than left to the RPC layer, for the
	 * one reason this program exists: both clntudp_create(3) and
	 * clnttcp_create(3) call bindresvport(3) on a socket they create
	 * themselves, so asking either for a client and hoping for an
	 * unprivileged port gets a reserved one when run as root - and the
	 * check -n is meant to exercise would pass whether the server
	 * implemented it or not.
	 *
	 * Handing one over means taking on the rest of what they would have
	 * done, and the two do not agree on what that is.  clnttcp_create
	 * expects a socket that is already connected; clntudp_create connects
	 * the one it is given and fails with EISCONN if it is already.  Get it
	 * the wrong way round in either direction and every call comes back
	 * "RPC: Unable to send", which says nothing at all about why.
	 */
	sock = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (sock == -1)
		err(1, "socket");
	if (!unpriv && bindresvport(sock, NULL) == -1)
		err(1, "bindresvport (this test needs to be root)");
	if (tcp && connect(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(1, "connect");

	cl = tcp ? clnttcp_create(&sin, YPPROG, YPVERS, &sock, 0, 0)
		 : clntudp_create(&sin, YPPROG, YPVERS, timeout, &sock);
	if (cl == NULL)
		errx(1, "%s", clnt_spcreateerror("cannot reach ypstns"));

	return cl;
}

static void
print_dat(const char *p, u_int len)
{
	printf("%.*s", (int)len, p);
}

static int
do_match(CLIENT *cl, char *domain, char *map, char *key)
{
	struct ypreq_key req;
	struct ypresp_val resp;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	req.domain = domain;
	req.map = map;
	req.key.keydat_val = key;
	req.key.keydat_len = (u_int)strlen(key);

	if (clnt_call(cl, YPPROC_MATCH, (xdrproc_t)xdr_ypreq_key, (caddr_t)&req, (xdrproc_t)xdr_ypresp_val,
		(caddr_t)&resp, timeout) != RPC_SUCCESS)
		errx(1, "%s", clnt_sperror(cl, "YPPROC_MATCH"));

	if (resp.stat != YP_TRUE) {
		printf("stat %d\n", (int)resp.stat);
		return 1;
	}
	print_dat(resp.val.valdat_val, resp.val.valdat_len);
	printf("\n");
	return 0;
}

static int
do_key_val(CLIENT *cl, u_long proc, char *domain, char *map, char *key)
{
	struct ypresp_key_val resp;

	memset(&resp, 0, sizeof(resp));

	if (proc == YPPROC_FIRST) {
		struct ypreq_nokey req;

		memset(&req, 0, sizeof(req));
		req.domain = domain;
		req.map = map;
		if (clnt_call(cl, proc, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req,
			(xdrproc_t)xdr_ypresp_key_val, (caddr_t)&resp, timeout) != RPC_SUCCESS)
			errx(1, "%s", clnt_sperror(cl, "YPPROC_FIRST"));
	} else {
		struct ypreq_key req;

		memset(&req, 0, sizeof(req));
		req.domain = domain;
		req.map = map;
		req.key.keydat_val = key;
		req.key.keydat_len = (u_int)strlen(key);
		if (clnt_call(cl, proc, (xdrproc_t)xdr_ypreq_key, (caddr_t)&req, (xdrproc_t)xdr_ypresp_key_val,
			(caddr_t)&resp, timeout) != RPC_SUCCESS)
			errx(1, "%s", clnt_sperror(cl, "YPPROC_NEXT"));
	}

	if (resp.stat != YP_TRUE) {
		printf("stat %d\n", (int)resp.stat);
		return 1;
	}
	print_dat(resp.key.keydat_val, resp.key.keydat_len);
	printf(" ");
	print_dat(resp.val.valdat_val, resp.val.valdat_len);
	printf("\n");
	return 0;
}

/*
 * The decoder for YPPROC_ALL, which is the mirror of the encoder in yp.c: a
 * run of "another one?" booleans, each true one followed by a key and a value.
 * Writing it out here rather than calling yp_all(3) is deliberate - yp_all
 * would need ypbind, and this way the two halves of the same stream format sit
 * in the same repository and can be read against each other.
 */
static bool_t
xdr_all_results(XDR *xdrs, void *arg)
{
	int *count = arg;
	bool_t more;

	for (;;) {
		struct ypresp_key_val kv;

		if (!xdr_bool(xdrs, &more))
			return FALSE;
		if (!more)
			break;

		memset(&kv, 0, sizeof(kv));
		if (!xdr_ypresp_key_val(xdrs, &kv))
			return FALSE;
		if (kv.stat != YP_TRUE) {
			printf("stat %d\n", (int)kv.stat);
			xdr_free((xdrproc_t)xdr_ypresp_key_val, (caddr_t)&kv);
			break;
		}
		print_dat(kv.key.keydat_val, kv.key.keydat_len);
		printf(" ");
		print_dat(kv.val.valdat_val, kv.val.valdat_len);
		printf("\n");
		(*count)++;
		xdr_free((xdrproc_t)xdr_ypresp_key_val, (caddr_t)&kv);
	}
	return TRUE;
}

static int
do_all(CLIENT *cl, char *domain, char *map)
{
	struct ypreq_nokey req;
	int count = 0;

	memset(&req, 0, sizeof(req));
	req.domain = domain;
	req.map = map;

	if (clnt_call(cl, YPPROC_ALL, (xdrproc_t)xdr_ypreq_nokey, (caddr_t)&req, (xdrproc_t)xdr_all_results,
		(caddr_t)&count, timeout) != RPC_SUCCESS)
		errx(1, "%s", clnt_sperror(cl, "YPPROC_ALL"));

	return (count > 0) ? 0 : 1;
}

static int
do_maplist(CLIENT *cl, char *domain)
{
	struct ypresp_maplist resp;
	ypmaplist *p;

	memset(&resp, 0, sizeof(resp));

	if (clnt_call(cl, YPPROC_MAPLIST, (xdrproc_t)xdr_domainname, (caddr_t)&domain,
		(xdrproc_t)xdr_ypresp_maplist, (caddr_t)&resp, timeout) != RPC_SUCCESS)
		errx(1, "%s", clnt_sperror(cl, "YPPROC_MAPLIST"));

	if (resp.stat != YP_TRUE) {
		printf("stat %d\n", (int)resp.stat);
		return 1;
	}
	for (p = resp.maps; p != NULL; p = p->next)
		printf("%s\n", p->map);
	return 0;
}

static int
do_domain(CLIENT *cl, char *domain)
{
	bool_t serves = FALSE;

	if (clnt_call(cl, YPPROC_DOMAIN, (xdrproc_t)xdr_domainname, (caddr_t)&domain, (xdrproc_t)xdr_bool,
		(caddr_t)&serves, timeout) != RPC_SUCCESS)
		errx(1, "%s", clnt_sperror(cl, "YPPROC_DOMAIN"));

	printf("%s\n", serves ? "yes" : "no");
	return serves ? 0 : 1;
}

static int
do_null(CLIENT *cl)
{
	if (clnt_call(cl, YPPROC_NULL, (xdrproc_t)xdr_void, NULL, (xdrproc_t)xdr_void, NULL, timeout) !=
	    RPC_SUCCESS)
		errx(1, "%s", clnt_sperror(cl, "YPPROC_NULL"));
	printf("ok\n");
	return 0;
}

int
main(int argc, char *argv[])
{
	CLIENT *cl;
	char *domain, *op;
	const char *addr = NULL;
	int unpriv = 0, tcp = 0, rv, ch;

	while ((ch = getopt(argc, argv, "a:nt")) != -1) {
		switch (ch) {
		case 'a':
			addr = optarg;
			break;
		case 'n':
			unpriv = 1;
			break;
		case 't':
			tcp = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage();
	domain = argv[0];
	op = argv[1];

	/*
	 * A whole map has no business going over UDP - the reply will not fit
	 * in a datagram - so YPPROC_ALL uses TCP whatever was asked for, which
	 * is what libc's yp_all(3) does too.
	 */
	if (strcmp(op, "all") == 0)
		tcp = 1;

	cl = make_client(addr, unpriv, tcp);

	if (strcmp(op, "match") == 0 && argc == 4)
		rv = do_match(cl, domain, argv[2], argv[3]);
	else if (strcmp(op, "first") == 0 && argc == 3)
		rv = do_key_val(cl, YPPROC_FIRST, domain, argv[2], NULL);
	else if (strcmp(op, "next") == 0 && argc == 4)
		rv = do_key_val(cl, YPPROC_NEXT, domain, argv[2], argv[3]);
	else if (strcmp(op, "all") == 0 && argc == 3)
		rv = do_all(cl, domain, argv[2]);
	else if (strcmp(op, "maplist") == 0 && argc == 2)
		rv = do_maplist(cl, domain);
	else if (strcmp(op, "domain") == 0 && argc == 2)
		rv = do_domain(cl, domain);
	else if (strcmp(op, "null") == 0 && argc == 2)
		rv = do_null(cl);
	else {
		usage();
		/* NOTREACHED */
		rv = 2;
	}

	clnt_destroy(cl);
	return rv;
}
