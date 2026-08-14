#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Feed ypstns.conf files to "ypstns -n" and check what it makes of them.
#
# -n is the only part of the daemon that can be exercised without root, a YP
# domain and a portmap(8) to register with - and it is also the part an
# administrator actually runs, on a file, before restarting anything.  So it is
# worth being sure it accepts what it should and, more importantly, refuses
# what it should: a configuration file that parses into something other than
# what it says is how a directory ends up being served to the whole network.

set -eu

YPSTNS=${1:-./ypstns}
WORK=${WORK:-/tmp/ypstns_parse}

checks=0
failures=0

cleanup() {
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

rm -rf "$WORK"
mkdir -p "$WORK"

# Write a configuration file and run it past the parser.  The file is made
# mode 600 because the parser refuses one anybody else can read, exactly as
# every other daemon on this system does.
try() {
	label=$1
	want=$2
	body=$3

	printf '%s\n' "$body" >"$WORK/test.conf"
	chmod 600 "$WORK/test.conf"

	"$YPSTNS" -n -f "$WORK/test.conf" >"$WORK/out" 2>&1 && got=0 || got=$?
	checks=$((checks + 1))
	if [ "$got" = "$want" ]; then
		echo "ok   - $label"
	else
		failures=$((failures + 1))
		echo "FAIL - $label: exit status $got, expected $want"
		sed 's/^/         /' "$WORK/out"
	fi
}

# Same, but also check something in the output.
try_says() {
	label=$1
	pattern=$2
	body=$3

	printf '%s\n' "$body" >"$WORK/test.conf"
	chmod 600 "$WORK/test.conf"

	"$YPSTNS" -n -f "$WORK/test.conf" >"$WORK/out" 2>&1 || true
	checks=$((checks + 1))
	if grep -q "$pattern" "$WORK/out"; then
		echo "ok   - $label"
	else
		failures=$((failures + 1))
		echo "FAIL - $label: nothing matching '$pattern' in"
		sed 's/^/         /' "$WORK/out"
	fi
}

echo "== configurations that should be accepted =="

try "the smallest useful file" 0 'domain "stns"'
try "every setting at once" 0 'domain "stns"
interval 300
user "_ypstns"
allow 192.0.2.0/24
allow 198.51.100.7'
try "allow any" 0 'domain "stns"
allow any'
try "comments and blank lines" 0 '# a comment

domain "stns"	# and a trailing one

interval 60'
try "a continued line" 0 'domain \
"stns"'
# The single quotes matter in both of these: the $ has to reach the parser as
# a macro reference rather than being expanded by the shell first.
# shellcheck disable=SC2016
try "a macro" 0 'dom = "stns"
domain $dom'

echo "== configurations that should be refused =="

# The domain is the one thing with no default: a server that guessed would
# simply never be asked anything, so it has to be an error rather than a guess.
try "no domain at all" 1 'interval 60'
try_says "and it says so" "no domain" 'interval 60'

try "an interval below the floor" 1 'domain "stns"
interval 1'
try "an interval beyond a day" 1 'domain "stns"
interval 999999'
try "a keyword that does not exist" 1 'domain "stns"
frobnicate 1'
try "a missing argument" 1 'domain'
try "an address that is not one" 1 'domain "stns"
allow 300.1.2.3'
try "a prefix length that is not one" 1 'domain "stns"
allow 192.0.2.0/99'
# shellcheck disable=SC2016
try "an undefined macro" 1 'domain $nosuch'

# "allow any" and a specific network together are contradictory, and the
# contradiction has to be reported rather than resolved by whichever came last.
try "allow any and then a network" 1 'domain "stns"
allow any
allow 192.0.2.0/24'

echo "== what -n reports =="

try_says "the domain" "stns" 'domain "stns"'
try_says "the default interval" "60" 'domain "stns"'
try_says "an interval that was given" "300" 'domain "stns"
interval 300'
try_says "that clients are restricted by default" "this machine" 'domain "stns"'
try_says "that allow any lifted the restriction" "any" 'domain "stns"
allow any'

echo "== file permissions =="

# The parser refuses a configuration file other people can read.  ypstns.conf
# holds no secret of its own, but every other daemon on the system makes this
# check and an administrator who adds one later should not discover that this
# file was the exception.
printf 'domain "stns"\n' >"$WORK/test.conf"
chmod 644 "$WORK/test.conf"
checks=$((checks + 1))
if "$YPSTNS" -n -f "$WORK/test.conf" >"$WORK/out" 2>&1; then
	failures=$((failures + 1))
	echo "FAIL - a world readable configuration file was accepted"
else
	echo "ok   - a world readable configuration file is refused"
fi

checks=$((checks + 1))
if "$YPSTNS" -n -f "$WORK/nonexistent.conf" >/dev/null 2>&1; then
	failures=$((failures + 1))
	echo "FAIL - a missing configuration file was accepted"
else
	echo "ok   - a missing configuration file is refused"
fi

echo
echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
