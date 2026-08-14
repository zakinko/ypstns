/*	$SNOWRABBIT: maps.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The YP maps: what is in them, and how a lookup finds it.
 *
 * A map is an array of key and value pairs kept sorted by key.  That is not
 * how ypserv(8) does it - it has real dbm files on disk, because it has to
 * survive being restarted and has to be writable by yppush(8) - but neither of
 * those is true here.  These maps are rebuilt from the API every interval and
 * never written to, so an array is the whole of what is needed, and sorting it
 * gives all three operations at once: YPPROC_MATCH is a binary search,
 * YPPROC_FIRST is the first element, and YPPROC_NEXT is the element after the
 * one named.
 *
 * The protocol does not say what order an enumeration comes back in - a real
 * ypserv walks a hash database and produces whatever order that happens to
 * give - so sorted is as good as any other and rather easier to read in a
 * ypcat(1).
 */
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "ypstns.h"

/*
 * Every map served, and whether it may be handed to an unprivileged client.
 *
 * The master.passwd maps are the ones with the password hashes in them.
 * ypserv(8) makes exactly this distinction, and it is the only thing between
 * an ordinary user on a YP client and every hash in the directory; yp.c
 * enforces it by refusing to answer for a privileged map unless the request
 * came from a reserved port.
 */
static const struct {
	const char *name;
	int privileged;
} map_defs[MAP_COUNT] = {
	[MAP_PASSWD_BYNAME] =		{ "passwd.byname",		0 },
	[MAP_PASSWD_BYUID] =		{ "passwd.byuid",		0 },
	[MAP_MASTER_PASSWD_BYNAME] =	{ "master.passwd.byname",	1 },
	[MAP_MASTER_PASSWD_BYUID] =	{ "master.passwd.byuid",	1 },
	[MAP_GROUP_BYNAME] =		{ "group.byname",		0 },
	[MAP_GROUP_BYGID] =		{ "group.bygid",		0 },
	[MAP_NETID_BYNAME] =		{ "netid.byname",		0 },
	[MAP_YPSERVERS] =		{ "ypservers",			0 }
};

void
maps_init(struct ypstns_maps *maps)
{
	size_t i;

	memset(maps, 0, sizeof(*maps));
	for (i = 0; i < MAP_COUNT; i++) {
		maps->m[i].name = map_defs[i].name;
		maps->m[i].privileged = map_defs[i].privileged;
	}
}

void
maps_free(struct ypstns_maps *maps)
{
	size_t i, j;

	for (i = 0; i < MAP_COUNT; i++) {
		for (j = 0; j < maps->m[i].n; j++) {
			free(maps->m[i].v[j].key);
			free(maps->m[i].v[j].val);
		}
		free(maps->m[i].v);
	}
	maps_init(maps);
}

int
maps_add(struct ypstns_map *map, const char *key, const char *val)
{
	struct ypstns_entry *grown;
	char *k, *v;

	if (map->n == map->cap) {
		size_t cap = (map->cap != 0) ? map->cap * 2 : 64;

		if ((grown = reallocarray(map->v, cap, sizeof(*grown))) == NULL)
			return -1;
		map->v = grown;
		map->cap = cap;
	}

	if ((k = strdup(key)) == NULL)
		return -1;
	if ((v = strdup(val)) == NULL) {
		free(k);
		return -1;
	}

	map->v[map->n].key = k;
	map->v[map->n].val = v;
	map->n++;
	return 0;
}

static int
entry_cmp(const void *a, const void *b)
{
	const struct ypstns_entry *ea = a;
	const struct ypstns_entry *eb = b;

	return strcmp(ea->key, eb->key);
}

/*
 * Sort every map, and drop any duplicate keys.
 *
 * A duplicate is not supposed to happen - the API is not meant to hold two
 * users with the same name - but if it does, a map with two entries under one
 * key would answer differently depending on where the binary search landed,
 * and an enumeration would hand the same key out twice.  Keeping the first and
 * saying so is better than either.
 */
void
maps_sort(struct ypstns_maps *maps)
{
	size_t i, j, kept;

	for (i = 0; i < MAP_COUNT; i++) {
		struct ypstns_map *map = &maps->m[i];

		if (map->n == 0)
			continue;
		qsort(map->v, map->n, sizeof(*map->v), entry_cmp);

		for (j = 1, kept = 1; j < map->n; j++) {
			if (strcmp(map->v[j].key, map->v[kept - 1].key) == 0) {
				syslog(LOG_NOTICE, "%s: duplicate key \"%s\", "
				    "keeping the first", map->name,
				    map->v[j].key);
				free(map->v[j].key);
				free(map->v[j].val);
				continue;
			}
			map->v[kept++] = map->v[j];
		}
		map->n = kept;
	}
}

const struct ypstns_map *
maps_find(const struct ypstns_maps *maps, const char *name)
{
	size_t i;

	for (i = 0; i < MAP_COUNT; i++) {
		if (strcmp(maps->m[i].name, name) == 0)
			return &maps->m[i];
	}
	return NULL;
}

const char *
map_match(const struct ypstns_map *map, const char *key)
{
	struct ypstns_entry want;
	const struct ypstns_entry *hit;

	if (map->n == 0)
		return NULL;

	want.key = (char *)key;
	want.val = NULL;
	hit = bsearch(&want, map->v, map->n, sizeof(*map->v), entry_cmp);

	return (hit != NULL) ? hit->val : NULL;
}

const struct ypstns_entry *
map_first(const struct ypstns_map *map)
{
	return (map->n > 0) ? &map->v[0] : NULL;
}

/*
 * The entry after the one named.
 *
 * This looks for the first key strictly greater than the one given, rather
 * than finding that key and stepping past it.  It comes to the same thing when
 * the key is present, which is the only case a well behaved client produces -
 * and when it is not, an enumeration that was interrupted by a refresh
 * continues from the right place instead of failing outright, which is a
 * better answer than the protocol strictly requires.
 */
const struct ypstns_entry *
map_next(const struct ypstns_map *map, const char *key)
{
	size_t lo = 0, hi = map->n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (strcmp(map->v[mid].key, key) <= 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (lo < map->n) ? &map->v[lo] : NULL;
}
