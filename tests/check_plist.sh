#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Stage an install and diff it against the port's packing list.
#
# A PLIST that has drifted from what the Makefile installs is not a mistake
# anybody notices while developing: the build works, the tests pass, and the
# package is either missing a file or refuses to build because of one that is
# there and unlisted.  It shows up for the first time in the ports tree, which
# is the worst place to find out.
#
# This runs the real install into a scratch DESTDIR and compares the two.

set -eu

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-/tmp/ypstns_plist}
LOCALBASE=${LOCALBASE:-/usr/local}
PLIST=$SRCDIR/pkg/openbsd/net/ypstns/pkg/PLIST

# shellcheck disable=SC2317  # reached through the trap below
cleanup() {
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

rm -rf "$WORK"
# The staging tree is a directory of its own inside the scratch area, not the
# scratch area itself.  The two logs and the two listings below would otherwise
# be found by the find(1) that walks it and reported as files the packing list
# has forgotten.
DEST=$WORK/dest
mkdir -p "$DEST"

cd "$SRCDIR"
make DESTDIR="$DEST" install >"$WORK/install.log" 2>&1 || {
	cat "$WORK/install.log" >&2
	exit 1
}

# What was actually installed, as absolute paths.
find "$DEST" -type f -o -type l | sed "s,^$DEST,," | sort >"$WORK/staged"

# What the packing list says, with the markers turned back into paths.  A line
# ending in '/' is a directory and is not a file; @newuser and @comment are
# instructions to pkg_add rather than contents.
sed -e '/^@comment/d' \
    -e '/^@newuser/d' \
    -e '/\/$/d' \
    -e "s,^@rcscript \${RCDIR},/etc/rc.d," \
    -e "s,^@bin ,$LOCALBASE/," \
    -e "s,^@man ,$LOCALBASE/," \
    -e "s,^\([^@/]\),$LOCALBASE/\1," \
    "$PLIST" | sort >"$WORK/listed"

if diff -u "$WORK/listed" "$WORK/staged"; then
	echo "ok   - the packing list matches what make install produced"
	exit 0
fi

echo "FAIL - pkg/PLIST and the Makefile disagree" >&2
echo "       '-' is listed but not installed, '+' is installed but not listed" >&2
exit 1
