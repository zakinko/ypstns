/*	$SNOWRABBIT: yp_xdr.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * XDR for the YP types.
 *
 * These are not here by choice.  OpenBSD's <rpcsvc/yp.h> declares every one of
 * them, which makes yp.c compile perfectly and then fail to link: libc has the
 * XDR primitives and the RPC machinery, but not the YP protocol's own
 * encoders.  ypserv(8) carries its own copy for the same reason, and so does
 * ypldap(8).
 *
 * The definitions follow Sun's yp.x, and there is exactly one thing about that
 * file worth pointing at.  ypresp_key_val puts the value before the key:
 *
 *	struct ypresp_key_val {
 *		ypstat stat;
 *		valdat val;
 *		keydat key;
 *	};
 *
 * That is not a typo and it is not the order the struct's members appear in on
 * any given system's header - it is the order on the wire, and getting it the
 * other way round produces a server whose YPPROC_FIRST and YPPROC_NEXT replies
 * decode into a key and a value that have swapped places.  Which fails in the
 * least helpful way possible: ypcat(1) prints the map back to front and libc's
 * enumeration walks off into nothing.
 */
#include <sys/types.h>

#include <rpc/rpc.h>
#include <rpcsvc/yp.h>

/*
 * The three name types are all strings with a length limit of their own; the
 * two data types are counted byte strings, because a YP value is not text as
 * far as the protocol is concerned even though everything here puts text in it.
 */
bool_t
xdr_domainname(XDR *xdrs, domainname *objp)
{
	return xdr_string(xdrs, objp, YPMAXDOMAIN);
}

bool_t
xdr_mapname(XDR *xdrs, mapname *objp)
{
	return xdr_string(xdrs, objp, YPMAXMAP);
}

bool_t
xdr_peername(XDR *xdrs, peername *objp)
{
	return xdr_string(xdrs, objp, YPMAXPEER);
}

bool_t
xdr_keydat(XDR *xdrs, keydat *objp)
{
	return xdr_bytes(xdrs, (char **)&objp->keydat_val, (u_int *)&objp->keydat_len, YPMAXRECORD);
}

bool_t
xdr_valdat(XDR *xdrs, valdat *objp)
{
	return xdr_bytes(xdrs, (char **)&objp->valdat_val, (u_int *)&objp->valdat_len, YPMAXRECORD);
}

bool_t
xdr_ypstat(XDR *xdrs, ypstat *objp)
{
	return xdr_enum(xdrs, (enum_t *)objp);
}

bool_t
xdr_ypxfrstat(XDR *xdrs, ypxfrstat *objp)
{
	return xdr_enum(xdrs, (enum_t *)objp);
}

bool_t
xdr_ypreq_key(XDR *xdrs, ypreq_key *objp)
{
	if (!xdr_domainname(xdrs, &objp->domain))
		return FALSE;
	if (!xdr_mapname(xdrs, &objp->map))
		return FALSE;
	return xdr_keydat(xdrs, &objp->key);
}

bool_t
xdr_ypreq_nokey(XDR *xdrs, ypreq_nokey *objp)
{
	if (!xdr_domainname(xdrs, &objp->domain))
		return FALSE;
	return xdr_mapname(xdrs, &objp->map);
}

bool_t
xdr_ypresp_val(XDR *xdrs, ypresp_val *objp)
{
	if (!xdr_ypstat(xdrs, &objp->stat))
		return FALSE;
	return xdr_valdat(xdrs, &objp->val);
}

/* The value comes before the key.  See the comment at the top of this file. */
bool_t
xdr_ypresp_key_val(XDR *xdrs, ypresp_key_val *objp)
{
	if (!xdr_ypstat(xdrs, &objp->stat))
		return FALSE;
	if (!xdr_valdat(xdrs, &objp->val))
		return FALSE;
	return xdr_keydat(xdrs, &objp->key);
}

bool_t
xdr_ypresp_master(XDR *xdrs, ypresp_master *objp)
{
	if (!xdr_ypstat(xdrs, &objp->stat))
		return FALSE;
	return xdr_peername(xdrs, &objp->peer);
}

bool_t
xdr_ypresp_order(XDR *xdrs, ypresp_order *objp)
{
	if (!xdr_ypstat(xdrs, &objp->stat))
		return FALSE;
	return xdr_u_int(xdrs, &objp->ordernum);
}

/*
 * The map list is a linked list on the wire as well as in memory: each element
 * is followed by a boolean saying whether another follows, which is what
 * xdr_pointer encodes.  Hence the recursion.
 */
bool_t
xdr_ypmaplist(XDR *xdrs, ypmaplist *objp)
{
	if (!xdr_mapname(xdrs, &objp->map))
		return FALSE;
	return xdr_pointer(xdrs, (char **)&objp->next, sizeof(ypmaplist), (xdrproc_t)xdr_ypmaplist);
}

bool_t
xdr_ypresp_maplist(XDR *xdrs, ypresp_maplist *objp)
{
	if (!xdr_ypstat(xdrs, &objp->stat))
		return FALSE;
	return xdr_pointer(xdrs, (char **)&objp->maps, sizeof(ypmaplist), (xdrproc_t)xdr_ypmaplist);
}
