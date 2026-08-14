/*	$SNOWRABBIT: maps_test.c,v $Format:%h %cs %an$ Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Unit tests for the map handling.
 *
 * The daemon itself cannot be run here - it wants root, portmap(8) and a YP
 * domain - but every lookup it will ever answer goes through this file, and
 * this file needs none of those things.  YPPROC_MATCH is map_match(),
 * YPPROC_FIRST and YPPROC_NEXT are map_first() and map_next(), and getting the
 * enumeration wrong means a ypcat(1) that loops for ever or stops early.
 */
#include <stdio.h>
#include <string.h>

#include "ypstns.h"

static int checks;
static int failures;

#define CHECK(cond)                                                                                                    \
	do {                                                                                                           \
		checks++;                                                                                              \
		if (!(cond)) {                                                                                         \
			failures++;                                                                                    \
			(void)printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                   \
		}                                                                                                      \
	} while (0)

#define CHECK_STR(got, want)                                                                                           \
	do {                                                                                                           \
		checks++;                                                                                              \
		if ((got) == NULL || strcmp((got), (want)) != 0) {                                                     \
			failures++;                                                                                    \
			(void)printf("FAIL %s:%d: expected \"%s\", got \"%s\"\n", __FILE__, __LINE__, (want),          \
			    ((got) != NULL) ? (got) : "(null)");                                                       \
		}                                                                                                      \
	} while (0)

/*
 * Every map is present from the start and every one of them knows its own
 * name, because YPPROC_MAPLIST and the lookup path read the same table.  If
 * they ever stopped agreeing, a client could be told a map exists and then be
 * told it does not.
 */
static void
test_map_table(void)
{
	struct ypstns_maps maps;

	maps_init(&maps);

	CHECK(maps_find(&maps, "passwd.byname") == &maps.m[MAP_PASSWD_BYNAME]);
	CHECK(maps_find(&maps, "group.bygid") == &maps.m[MAP_GROUP_BYGID]);
	CHECK(maps_find(&maps, "netid.byname") == &maps.m[MAP_NETID_BYNAME]);
	CHECK(maps_find(&maps, "no.such.map") == NULL);

	/* Only the two maps with hashes in them are privileged. */
	CHECK(maps.m[MAP_MASTER_PASSWD_BYNAME].privileged);
	CHECK(maps.m[MAP_MASTER_PASSWD_BYUID].privileged);
	CHECK(!maps.m[MAP_PASSWD_BYNAME].privileged);
	CHECK(!maps.m[MAP_PASSWD_BYUID].privileged);
	CHECK(!maps.m[MAP_GROUP_BYNAME].privileged);

	maps_free(&maps);
}

static void
test_match(void)
{
	struct ypstns_maps maps;
	struct ypstns_map *m;

	maps_init(&maps);
	m = &maps.m[MAP_PASSWD_BYNAME];

	/* Added out of order on purpose; maps_sort() is what puts them right. */
	CHECK(maps_add(m, "carol", "carol:*:1003:1003:::") == 0);
	CHECK(maps_add(m, "alice", "alice:*:1001:1001:::") == 0);
	CHECK(maps_add(m, "bob", "bob:*:1002:1002:::") == 0);
	maps_sort(&maps);

	CHECK(m->n == 3);
	CHECK_STR(m->v[0].key, "alice");
	CHECK_STR(m->v[2].key, "carol");

	CHECK_STR(map_match(m, "alice"), "alice:*:1001:1001:::");
	CHECK_STR(map_match(m, "carol"), "carol:*:1003:1003:::");
	CHECK(map_match(m, "dave") == NULL);
	/* Keys are bytes, not names: the match is exact. */
	CHECK(map_match(m, "Alice") == NULL);
	CHECK(map_match(m, "") == NULL);

	maps_free(&maps);
}

/* An empty map answers nothing rather than answering wrongly. */
static void
test_empty(void)
{
	struct ypstns_maps maps;

	maps_init(&maps);
	CHECK(map_match(&maps.m[MAP_PASSWD_BYNAME], "alice") == NULL);
	CHECK(map_first(&maps.m[MAP_PASSWD_BYNAME]) == NULL);
	CHECK(map_next(&maps.m[MAP_PASSWD_BYNAME], "alice") == NULL);
	maps_free(&maps);
}

/*
 * A full enumeration, which is what ypcat(1) and a getpwent(3) loop do.
 *
 * Every entry has to come back exactly once and the walk has to end.  Both
 * failures here are the kind that only show up in production: a duplicated key
 * makes a user appear twice, and a walk that never terminates hangs whatever
 * asked.
 */
static void
test_enumeration(void)
{
	static const char *const names[] = { "alice", "bob", "carol", "dave", "eve" };
	struct ypstns_maps maps;
	struct ypstns_map *m;
	const struct ypstns_entry *e;
	size_t i, seen = 0;

	maps_init(&maps);
	m = &maps.m[MAP_GROUP_BYNAME];

	/* Insert backwards, so that a sort that did nothing would be obvious. */
	for (i = sizeof(names) / sizeof(names[0]); i > 0; i--)
		CHECK(maps_add(m, names[i - 1], "value") == 0);
	maps_sort(&maps);

	e = map_first(m);
	while (e != NULL) {
		CHECK(seen < sizeof(names) / sizeof(names[0]));
		if (seen >= sizeof(names) / sizeof(names[0]))
			break;
		CHECK_STR(e->key, names[seen]);
		seen++;
		e = map_next(m, e->key);
	}
	CHECK(seen == sizeof(names) / sizeof(names[0]));

	/* Past the end is the end, not a wrap round to the beginning. */
	CHECK(map_next(m, "zzz") == NULL);

	/*
	 * A key that is not in the map continues from where it would have
	 * been.  A client whose enumeration was interrupted by a refresh
	 * carries on from the right place instead of failing outright.
	 */
	e = map_next(m, "bz");
	CHECK(e != NULL);
	if (e != NULL)
		CHECK_STR(e->key, "carol");

	maps_free(&maps);
}

/*
 * A duplicate key is dropped rather than kept.
 *
 * Two entries under one key would answer differently depending on where the
 * binary search happened to land, and would hand the same key out twice during
 * an enumeration.  It is not supposed to happen; if it does, being consistent
 * about it matters more than which one wins.
 */
static void
test_duplicates(void)
{
	struct ypstns_maps maps;
	struct ypstns_map *m;
	const struct ypstns_entry *e;
	size_t seen = 0;

	maps_init(&maps);
	m = &maps.m[MAP_PASSWD_BYNAME];

	CHECK(maps_add(m, "alice", "first") == 0);
	CHECK(maps_add(m, "alice", "second") == 0);
	CHECK(maps_add(m, "bob", "bob") == 0);
	maps_sort(&maps);

	CHECK(m->n == 2);
	for (e = map_first(m); e != NULL; e = map_next(m, e->key))
		seen++;
	CHECK(seen == 2);

	maps_free(&maps);
}

/* Enough entries that the growth in maps_add() and the binary search both run. */
static void
test_many(void)
{
	struct ypstns_maps maps;
	struct ypstns_map *m;
	const struct ypstns_entry *e;
	char key[32];
	size_t i, seen = 0;

	maps_init(&maps);
	m = &maps.m[MAP_PASSWD_BYUID];

	for (i = 0; i < 1000; i++) {
		(void)snprintf(key, sizeof(key), "%04zu", i);
		CHECK(maps_add(m, key, "x") == 0);
	}
	maps_sort(&maps);
	CHECK(m->n == 1000);

	CHECK(map_match(m, "0000") != NULL);
	CHECK(map_match(m, "0500") != NULL);
	CHECK(map_match(m, "0999") != NULL);
	CHECK(map_match(m, "1000") == NULL);

	for (e = map_first(m); e != NULL; e = map_next(m, e->key))
		seen++;
	CHECK(seen == 1000);

	maps_free(&maps);
}

/* maps_free() leaves a usable, empty set of maps rather than a wrecked one. */
static void
test_free_is_reusable(void)
{
	struct ypstns_maps maps;

	maps_init(&maps);
	CHECK(maps_add(&maps.m[MAP_PASSWD_BYNAME], "alice", "x") == 0);
	maps_free(&maps);

	CHECK(maps.m[MAP_PASSWD_BYNAME].n == 0);
	CHECK(maps_find(&maps, "passwd.byname") != NULL);
	CHECK(maps_add(&maps.m[MAP_PASSWD_BYNAME], "bob", "y") == 0);
	maps_sort(&maps);
	CHECK_STR(map_match(&maps.m[MAP_PASSWD_BYNAME], "bob"), "y");
	maps_free(&maps);
}

int
main(void)
{
	test_map_table();
	test_match();
	test_empty();
	test_enumeration();
	test_duplicates();
	test_many();
	test_free_is_reusable();

	(void)printf("%d checks, %d failures\n", checks, failures);
	return (failures == 0) ? 0 : 1;
}
