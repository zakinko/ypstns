#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Run the real daemon and ask it real questions.
#
# The unit tests take maps.c and parse.y apart.  Everything else in this
# repository - the privilege separation, the pipe between the two processes,
# unveil(2) and pledge(2), the portmap registration, the RPC dispatch, and the
# XDR in yp_xdr.c that OpenBSD's libc declines to provide - has no test that
# does not involve starting the daemon.  So this starts it.
#
# It asks in three ways, on purpose, because they fail differently:
#
#   tests/yp_client.c    speaks YPPROG straight to the server.  A failure here
#                        is this repository's, and nothing else's.
#   ypmatch(1), ypcat(1) go through ypbind(8), so they also prove the binding,
#                        the domain and the RPC registration.
#   getent(1), id(1)     go through libc, which is the only thing that proves
#                        the maps are shaped the way a real lookup needs.
#
# This one needs root: it binds reserved ports, starts portmap(8), sets the
# domain name and briefly adds a "+" line to /etc/master.passwd.  It is meant
# for a throwaway machine or the CI virtual machine, and it puts back what it
# changed on the way out.

set -eu

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
STNS_PORT=${STNS_PORT:-11107}
DOMAIN=${DOMAIN:-stnstest}
PYTHON=${PYTHON:-python3}
WORK=${WORK:-/tmp/ypstns_integration}

MOCK=$SRCDIR/tests/mock_stns_server.py
CLIENT=$SRCDIR/yp_client
AUTH=$SRCDIR/auth_client

checks=0
failures=0
stns_pid=
ypstns_pid=
ypbind_started=
saved_domain=
saved_passwd=

# Put /etc back the way it was found.  A "+" line left in master.passwd with no
# YP server able to answer it is a machine that pauses on every name lookup, so
# this is called as soon as the checks that need it are done rather than only
# on the way out.
restore_passwd() {
	if [ -n "$saved_passwd" ] && [ -f "$saved_passwd" ]; then
		cp "$saved_passwd" /etc/master.passwd
		pwd_mkdb /etc/master.passwd
		cp "$saved_passwd.group" /etc/group
		saved_passwd=
	fi
}

stop_ypbind() {
	if [ -n "$ypbind_started" ]; then
		pkill -x ypbind 2>/dev/null || true
		ypbind_started=
	fi
}

cleanup() {
	set +e
	stop_ypbind
	[ -n "$ypstns_pid" ] && kill "$ypstns_pid" 2>/dev/null
	[ -n "$stns_pid" ] && kill "$stns_pid" 2>/dev/null
	restore_passwd
	[ -n "$saved_domain" ] && domainname "$saved_domain"
	rm -rf "$WORK"
	set -e
}
trap cleanup EXIT INT TERM

start_stns() {
	_saddr=127.0.0.1
	_prev=
	for a in "$@"; do
		[ "$_prev" = "--listen" ] && _saddr=$a
		_prev=$a
	done

	$PYTHON "$MOCK" "$STNS_PORT" "$@" >>"$WORK/stns.log" 2>&1 &
	stns_pid=$!

	# create_connection rather than a bare socket, so the family follows the
	# address instead of being decided here.
	i=0
	while [ "$i" -lt 100 ]; do
		$PYTHON -c "import socket, sys
try:
    socket.create_connection(('$_saddr', $STNS_PORT), 0.2).close()
except OSError:
    sys.exit(1)" 2>/dev/null && return 0
		i=$((i + 1))
		sleep 0.1
	done
	echo "the mock server never came up on $_saddr" >&2
	return 1
}

stop_stns() {
	if [ -n "$stns_pid" ]; then
		kill "$stns_pid" 2>/dev/null || true
		wait "$stns_pid" 2>/dev/null || true
		stns_pid=
	fi
}

start_daemon() {
	"$SRCDIR/ypstns" -d -v -f "$WORK/ypstns.conf" >>"$WORK/ypstns.log" 2>&1 &
	ypstns_pid=$!
	i=0
	while [ "$i" -lt 150 ]; do
		rpcinfo -p 127.0.0.1 2>/dev/null | grep -q ' 100004 ' && return 0
		i=$((i + 1))
		sleep 0.2
	done
	return 1
}

stop_daemon() {
	if [ -n "$ypstns_pid" ]; then
		kill "$ypstns_pid" 2>/dev/null || true
		wait "$ypstns_pid" 2>/dev/null || true
		ypstns_pid=
	fi
}

# A self-signed certificate that is also its own CA, so it can be handed to
# tls.ca.  Through a configuration file rather than -addext, which not every
# openssl(1) this runs under agrees about.
make_cert() {
	cat >"$WORK/openssl.cnf" <<-'CNF'
	[req]
	distinguished_name = dn
	x509_extensions = ext
	prompt = no
	[dn]
	CN = localhost
	[ext]
	subjectAltName = DNS:localhost,IP:127.0.0.1
	basicConstraints = critical,CA:TRUE
	CNF
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
		-config "$WORK/openssl.cnf" \
		-keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1
}

stns_requests() {
	$PYTHON -c "
import json, urllib.request
print(len(json.load(urllib.request.urlopen('http://127.0.0.1:$STNS_PORT/v1/_requests'))))"
}

check() {
	label=$1
	shift
	expected=$(cat)
	actual=$("$@" 2>&1 || true)
	checks=$((checks + 1))
	if [ "$actual" = "$expected" ]; then
		echo "ok   - $label"
	else
		failures=$((failures + 1))
		echo "FAIL - $label"
		echo "       expected: $expected"
		echo "       got:      $actual"
	fi
}

ok() {
	checks=$((checks + 1))
	echo "ok   - $1"
}

# For a command whose exit status is the thing under test.
check_status() {
	label=$1
	want=$2
	shift 2
	"$@" >/dev/null 2>&1 && got=0 || got=$?
	checks=$((checks + 1))
	if [ "$got" = "$want" ]; then
		echo "ok   - $label"
	else
		failures=$((failures + 1))
		echo "FAIL - $label: exit status $got, expected $want"
	fi
}

fail() {
	checks=$((checks + 1))
	failures=$((failures + 1))
	echo "FAIL - $1"
}

[ "$(id -u)" = "0" ] || {
	echo "skip - this one needs root" >&2
	exit 0
}
[ "$(uname -s)" = "OpenBSD" ] || {
	echo "skip - OpenBSD only" >&2
	exit 0
}

rm -rf "$WORK"
mkdir -p "$WORK"

echo "== preparing =="

# The account the fetcher drops to.  A package would have made it through
# @newuser in the packing list; nothing has installed a package here.
if ! id _ypstns >/dev/null 2>&1; then
	groupadd -g 783 _ypstns
	useradd -u 783 -g _ypstns -d /nonexistent -s /sbin/nologin \
		-c "ypstns account" _ypstns
	echo "     created _ypstns"
fi

make -C "$SRCDIR" >"$WORK/build.log" 2>&1 || { cat "$WORK/build.log" >&2; exit 1; }
make -C "$SRCDIR" yp_client >>"$WORK/build.log" 2>&1 || { cat "$WORK/build.log" >&2; exit 1; }
make -C "$SRCDIR" auth_client >>"$WORK/build.log" 2>&1 || { cat "$WORK/build.log" >&2; exit 1; }

mkdir -p /etc/stns/client
cat >/etc/stns/client/stns.conf <<EOF
api_endpoint = "http://127.0.0.1:$STNS_PORT/v1"
cache = false
EOF
chmod 600 /etc/stns/client/stns.conf

cat >"$WORK/ypstns.conf" <<EOF
domain "$DOMAIN"
interval 3600
EOF
chmod 600 "$WORK/ypstns.conf"

saved_domain=$(domainname)
domainname "$DOMAIN"

# portmap(8) has to be there before the daemon can register with it.
if ! rcctl check portmap >/dev/null 2>&1; then
	rcctl -f start portmap >/dev/null
	echo "     started portmap"
fi

start_stns

echo "== starting the daemon =="

# It registers with portmap only after the first fetch has succeeded, so the
# registration appearing is also the proof that the fetcher got through
# unveil(2) and pledge(2) and back over the pipe with a whole directory.
start_daemon || true
if rpcinfo -p 127.0.0.1 2>/dev/null | grep -q ' 100004 '; then
	ok "the daemon fetched the directory and registered with portmap"
else
	fail "nothing registered as YPPROG within 30 seconds"
	echo "--- ypstns.log"
	cat "$WORK/ypstns.log"
	echo "--- stns.log"
	cat "$WORK/stns.log"
	exit 1
fi

# Both transports, because libc uses UDP for a lookup and TCP for a whole map.
for proto in udp tcp; do
	if rpcinfo -p 127.0.0.1 | grep ' 100004 ' | grep -q "$proto"; then
		ok "registered on $proto"
	else
		fail "not registered on $proto"
	fi
done

echo "== the protocol, spoken directly =="

check "YPPROC_NULL" "$CLIENT" "$DOMAIN" null <<'EOF'
ok
EOF

check "YPPROC_DOMAIN for the domain served" "$CLIENT" "$DOMAIN" domain <<'EOF'
yes
EOF

check "and for one that is not" "$CLIENT" nosuchdomain domain <<'EOF'
no
EOF

check "a user by name" "$CLIENT" "$DOMAIN" match passwd.byname stnsuser <<'EOF'
stnsuser:*:1001:1001:STNS test user:/home/stnsuser:/bin/sh
EOF

check "a user by uid" "$CLIENT" "$DOMAIN" match passwd.byuid 1001 <<'EOF'
stnsuser:*:1001:1001:STNS test user:/home/stnsuser:/bin/sh
EOF

# The empty shell and directory the mock server sends have to have come back
# as the defaults, and the empty password field as a locked "*".
check "the defaults were applied" "$CLIENT" "$DOMAIN" match passwd.byname stnsdefault <<'EOF'
stnsdefault:*:1002:1001::/home/stnsdefault:/bin/sh
EOF

check "a group, with its members" "$CLIENT" "$DOMAIN" match group.byname stnsgroup <<'EOF'
stnsgroup:*:1001:stnsuser,stnsdefault
EOF

check "a group by gid" "$CLIENT" "$DOMAIN" match group.bygid 1002 <<'EOF'
stnsops:*:1002:stnsuser
EOF

# uid on the left of the colon, then the primary group and every other group
# the user is in.  stnsgroup is the primary and so is not repeated.
check "netid" "$CLIENT" "$DOMAIN" match netid.byname "unix.1001@$DOMAIN" <<'EOF'
1001:1001,1002,1005
EOF

echo "== the privileged maps =="

# Root, so yp_client binds a reserved port and is allowed the hash.
check "master.passwd from a reserved port" "$CLIENT" "$DOMAIN" match master.passwd.byname stnshash <<'EOF'
stnshash:$6$stnssalt$OIMtoFferfvDRURYFOfno07xGCvtuODAKpR8zK4wOUL0oRwqKXqB6kv96hFKeeb9UCZTR40OaUBzAMP.QqIgi1:1004:1001::0:0::/home/stnshash:/bin/sh
EOF

# -5 is YP_BADDB.  Deliberately not YP_NOMAP: the map does exist, and telling a
# client it does not would have it remember that and stop asking.
check "and refused from an unprivileged one" "$CLIENT" -n "$DOMAIN" match master.passwd.byname stnshash <<'EOF'
stat -5
EOF

check "while the ordinary map is not" "$CLIENT" -n "$DOMAIN" match passwd.byname stnsuser <<'EOF'
stnsuser:*:1001:1001:STNS test user:/home/stnsuser:/bin/sh
EOF

echo "== the failures a client has to be able to tell apart =="

# -2 YP_NODOM, -1 YP_NOMAP, -3 YP_NOKEY.  ypbind unbinds and looks for another
# server on the first, gives up on one map on the second, and simply reports
# "not found" on the third.
check "the wrong domain" "$CLIENT" nosuchdomain match passwd.byname stnsuser <<'EOF'
stat -2
EOF

check "a map that does not exist" "$CLIENT" "$DOMAIN" match no.such.map stnsuser <<'EOF'
stat -1
EOF

check "a key that does not exist" "$CLIENT" "$DOMAIN" match passwd.byname nobodyhere <<'EOF'
stat -3
EOF

echo "== enumeration =="

# Sorted, so the first is predictable.
check "YPPROC_FIRST" "$CLIENT" "$DOMAIN" first passwd.byname <<'EOF'
stnsdefault stnsdefault:*:1002:1001::/home/stnsdefault:/bin/sh
EOF

check "YPPROC_NEXT" "$CLIENT" "$DOMAIN" next passwd.byname stnsdefault <<'EOF'
stnshash stnshash:*:1004:1001::/home/stnshash:/bin/sh
EOF

check "and the end of the map" "$CLIENT" "$DOMAIN" next passwd.byname stnsuser <<'EOF'
stat 2
EOF

# YPPROC_ALL is a stream of its own and the encoder for it is hand written, so
# the count is worth checking rather than assuming.
"$CLIENT" "$DOMAIN" all passwd.byname >"$WORK/all.out" 2>"$WORK/all.err" || true
n=$(wc -l <"$WORK/all.out" | tr -d ' ')
checks=$((checks + 1))
if [ "$n" = "4" ]; then
	echo "ok   - YPPROC_ALL returned all four users"
else
	failures=$((failures + 1))
	echo "FAIL - YPPROC_ALL returned $n entries, expected 4"
	sed 's/^/       /' "$WORK/all.err"
fi

check "YPPROC_MAPLIST" "$CLIENT" "$DOMAIN" maplist <<'EOF'
passwd.byname
passwd.byuid
master.passwd.byname
master.passwd.byuid
group.byname
group.bygid
netid.byname
ypservers
EOF

echo "== through ypbind, and then through libc =="

# -ypsetme allows ypset(8) from this machine, which is how the binding is
# pointed at the server without waiting on a broadcast that has nowhere to go.
ypbind -ypsetme >>"$WORK/ypstns.log" 2>&1 &
ypbind_started=yes
sleep 2
ypset 127.0.0.1 >/dev/null 2>&1 || true

i=0
while [ "$i" -lt 50 ]; do
	ypwhich >/dev/null 2>&1 && break
	ypset 127.0.0.1 >/dev/null 2>&1 || true
	i=$((i + 1))
	sleep 0.4
done

if ypwhich >/dev/null 2>&1; then
	ok "ypbind bound to the server"

	check "ypmatch" ypmatch stnsuser passwd <<'EOF'
stnsuser:*:1001:1001:STNS test user:/home/stnsuser:/bin/sh
EOF

	# Four of the five.  The fixture's stnsbig has three hundred members and
	# so is over YPMAXRECORD; it is dropped where it is built, and the point
	# of this check is that dropping it costs one group rather than the map
	# - a value that fails to encode inside YPPROC_ALL takes the whole
	# stream with it, and ypcat then reports every group as missing.
	#
	# stderr is kept: when ypcat returns nothing, what it says about why is
	# the whole of the information.
	ypcat group >"$WORK/ypcat.out" 2>"$WORK/ypcat.err" || true
	n=$(wc -l <"$WORK/ypcat.out" | tr -d ' ')
	checks=$((checks + 1))
	if [ "$n" = "4" ]; then
		echo "ok   - ypcat listed the four groups that fit"
	else
		failures=$((failures + 1))
		echo "FAIL - ypcat listed $n groups, expected 4"
		sed 's/^/       /' "$WORK/ypcat.err"
	fi

	checks=$((checks + 1))
	if grep -q 'stnsbig' "$WORK/ypstns.log"; then
		echo "ok   - and the one that did not fit is named in the log"
	else
		failures=$((failures + 1))
		echo "FAIL - the dropped group was not reported"
	fi

	# And now the whole point of the exercise: libc, resolving a name it
	# has never heard of, through the "+" line.
	saved_passwd=$WORK/master.passwd.orig
	cp /etc/master.passwd "$saved_passwd"
	cp /etc/group "$saved_passwd.group"
	echo '+:*::::::::' >>/etc/master.passwd
	echo '+:*::' >>/etc/group
	pwd_mkdb /etc/master.passwd

	check "getent passwd" getent passwd stnsuser <<'EOF'
stnsuser:*:1001:1001:STNS test user:/home/stnsuser:/bin/sh
EOF

	check "id, which needs the group maps as well" id -G stnsuser <<'EOF'
1001 1002 1005
EOF
else
	fail "ypbind never bound; the checks through libc did not run"
	echo "--- ypstns.log"
	tail -20 "$WORK/ypstns.log"
fi

echo "== reloading =="

# SIGHUP asks the fetcher for the directory again.  The daemon has pledged
# "stdio inet" by now, so this also checks that nothing in the reload path
# reaches for a file and gets the process killed for it.
before=$(grep -c 'maps updated' "$WORK/ypstns.log" || true)
kill -HUP "$ypstns_pid"
sleep 3
after=$(grep -c 'maps updated' "$WORK/ypstns.log" || true)
checks=$((checks + 1))
if [ "$after" -gt "$before" ]; then
	echo "ok   - SIGHUP fetched the directory again"
else
	failures=$((failures + 1))
	echo "FAIL - SIGHUP produced no new update ($before -> $after)"
	tail -10 "$WORK/ypstns.log"
fi

checks=$((checks + 1))
if kill -0 "$ypstns_pid" 2>/dev/null; then
	echo "ok   - and the daemon is still running"
else
	failures=$((failures + 1))
	echo "FAIL - the daemon died during the reload"
	tail -20 "$WORK/ypstns.log"
fi

echo "== login_stns =="

# The other half of the answer to "who is this": ypstns says what a user is,
# and this says whether a password is theirs.  It is a separate program on a
# separate mechanism, so it gets its own phase - and auth_client runs it the
# way authenticate(3) does, over file descriptor 3, which is the only path
# login(1) and su(1) ever take.
#
# The fixture's stnshash carries a real SHA-512 crypt hash of the password
# below.  The comparison is src/stns_crypt.c, whose own tests check the hashing
# against published vectors; what is being checked here is the program around
# it - the back channel, the confinement, and every way of saying no.
check "the right password is authorized" \
	"$AUTH" "$SRCDIR/login_stns" stnshash "correct horse battery staple" <<'EOF'
authorize
EOF
check_status "and it exits zero" 0 \
	"$AUTH" "$SRCDIR/login_stns" stnshash "correct horse battery staple"

check "the wrong one is rejected" \
	"$AUTH" "$SRCDIR/login_stns" stnshash "incorrect horse battery staple" <<'EOF'
reject
EOF
check_status "and it exits non-zero" 1 \
	"$AUTH" "$SRCDIR/login_stns" stnshash "incorrect horse battery staple"

# An empty password is refused before it is hashed.  The hash of an empty
# string is a perfectly good hash, and an account holding one must not be
# open to anybody who presses return.
check "an empty password is rejected" "$AUTH" "$SRCDIR/login_stns" stnshash "" <<'EOF'
reject
EOF

# stnsuser's password field is empty, so the library stored "*".  A locked
# account must not be opened by anything, including by typing the lock.
check "a locked account is rejected" "$AUTH" "$SRCDIR/login_stns" stnsuser "anything" <<'EOF'
reject
EOF
check "and not by its own lock string either" "$AUTH" "$SRCDIR/login_stns" stnsuser "*" <<'EOF'
reject
EOF

# Reached for every local login on the machine, since the style is listed
# after passwd - so it has to be quiet and quick about it rather than an error.
check "a user the directory does not hold is rejected" \
	"$AUTH" "$SRCDIR/login_stns" nosuchuser "anything" <<'EOF'
reject
EOF

check "a name outside the character set is rejected" \
	"$AUTH" "$SRCDIR/login_stns" "bad name" "anything" <<'EOF'
reject
EOF

# There is no challenge to issue, and saying so silently is what stops login(1)
# printing a prompt of its own for a style that only wants a password.
check "the challenge service is silent" \
	"$AUTH" -s challenge "$SRCDIR/login_stns" stnshash <<'EOF'
reject silent
EOF

echo "== login_stns when the API is unreachable =="

# It must refuse rather than fall back to anything, and it must not hang.  The
# machine keeps working because login.conf lists passwd first; this style has
# nothing to offer when the directory cannot be reached and says so.
stop_stns
check "an unreachable API is a rejection" \
	"$AUTH" "$SRCDIR/login_stns" stnshash "correct horse battery staple" <<'EOF'
reject
EOF
start_stns

# The "+" line and ypbind have done their job.  Everything below restarts the
# daemon, which changes the port it is registered on, and a bound ypbind with a
# stale port in front of a "+" line is how a machine comes to pause on every
# name lookup.
restore_passwd
stop_ypbind

echo "== fetching over TLS =="

# This is what the unveil(2) list in stnsclient.c exists for.  Everything above
# talks plain HTTP to 127.0.0.1, which never opens a trust store and never
# performs a handshake - so a mistake in that list would not appear until
# somebody pointed the fetcher at a real https:// endpoint on a real machine,
# where it would be killed by pledge or fail to find a CA, and nothing in any
# test would have said a word.
stop_daemon
stop_stns
make_cert
start_stns --tls "$WORK/cert.pem,$WORK/key.pem"

# localhost rather than an address, so the name in the certificate is checked
# and the resolver is used - which is another thing unveil has to have left
# reachable.
cat >/etc/stns/client/stns.conf <<EOF
api_endpoint = "https://localhost:$STNS_PORT/v1"
cache = false
ssl_verify = true
[tls]
ca = "$WORK/cert.pem"
EOF
chmod 600 /etc/stns/client/stns.conf

if start_daemon; then
	ok "the fetcher reached an https endpoint from inside unveil and pledge"
	check "and what it brought back is intact" \
		"$CLIENT" "$DOMAIN" match passwd.byname stnsuser <<'EOF'
stnsuser:*:1001:1001:STNS test user:/home/stnsuser:/bin/sh
EOF
else
	fail "nothing registered after the endpoint moved to https"
	tail -30 "$WORK/ypstns.log"
fi

stop_daemon

# Untrusted, and so the first fetch cannot succeed.  The daemon must not
# register at all: a YP server answering YP_NOMAP tells its clients the map
# does not exist, which is worse than one that is simply not there.
cat >/etc/stns/client/stns.conf <<EOF
api_endpoint = "https://localhost:$STNS_PORT/v1"
cache = false
ssl_verify = true
EOF
chmod 600 /etc/stns/client/stns.conf

if start_daemon; then
	fail "it registered with portmap without ever fetching anything"
else
	ok "an untrusted certificate leaves it unregistered rather than empty"
fi
stop_daemon

echo "== an API reached over IPv6 =="

# YP itself is IPv4 and always will be - Sun RPC over anything else is not a
# thing libc's client will ask for - but the API the fetcher talks to is an
# ordinary HTTP endpoint and may well be v6 only.  Worth its own phase because
# the URL has brackets in it, which nothing else here produces, and because
# pledge(2)'s "inet" has to cover AF_INET6 as well; if it did not, this is the
# one arrangement that would find out.
stop_daemon
stop_stns
start_stns --listen ::1

cat >/etc/stns/client/stns.conf <<EOF
api_endpoint = "http://[::1]:$STNS_PORT/v1"
cache = false
EOF
chmod 600 /etc/stns/client/stns.conf

cat >"$WORK/ypstns.conf" <<EOF
domain "$DOMAIN"
interval 3600
EOF
chmod 600 "$WORK/ypstns.conf"

if start_daemon; then
	ok "the fetcher reached an IPv6 endpoint"
	check "and the maps it built are right" \
		"$CLIENT" "$DOMAIN" match passwd.byname stnsuser <<'EOF'
stnsuser:*:1001:1001:STNS test user:/home/stnsuser:/bin/sh
EOF
else
	fail "nothing registered with the endpoint at [::1]"
	tail -20 "$WORK/ypstns.log"
fi

stop_daemon
stop_stns
start_stns

cat >/etc/stns/client/stns.conf <<EOF
api_endpoint = "http://127.0.0.1:$STNS_PORT/v1"
cache = false
EOF
chmod 600 /etc/stns/client/stns.conf

echo "== the refresh timer =="

stop_stns
start_stns

cat >/etc/stns/client/stns.conf <<EOF
api_endpoint = "http://127.0.0.1:$STNS_PORT/v1"
cache = false
EOF
chmod 600 /etc/stns/client/stns.conf

# Ten seconds is the floor the grammar allows, and the shortest honest way to
# watch the timer fire.  Every phase above sets an hour and relies on the fetch
# that happens at startup, so until now nothing has ever tested the interval.
cat >"$WORK/ypstns.conf" <<EOF
domain "$DOMAIN"
interval 10
EOF
chmod 600 "$WORK/ypstns.conf"

if start_daemon; then
	before=$(stns_requests)
	sleep 13
	after=$(stns_requests)
	checks=$((checks + 1))
	if [ "$after" -gt "$before" ]; then
		echo "ok   - the directory was fetched again on the interval"
	else
		failures=$((failures + 1))
		echo "FAIL - no refresh in thirteen seconds ($before -> $after)"
	fi
else
	fail "the daemon did not come back for the interval check"
fi

echo "== when the API goes away =="

# Several failed refreshes in a row, at ten seconds each.  The maps have to
# stay exactly as they were: an API server that is briefly unreachable must not
# empty the directory out from under everybody logged in.
stop_stns
sleep 13

check "a lookup still works from the last good maps" \
	"$CLIENT" "$DOMAIN" match passwd.byname stnsuser <<'EOF'
stnsuser:*:1001:1001:STNS test user:/home/stnsuser:/bin/sh
EOF

checks=$((checks + 1))
if kill -0 "$ypstns_pid" 2>/dev/null; then
	echo "ok   - and the daemon is still running"
else
	failures=$((failures + 1))
	echo "FAIL - the daemon exited when the API went away"
	tail -20 "$WORK/ypstns.log"
fi

start_stns

echo "== who may ask =="

# From the loopback every configuration answers, so the access list has never
# been tested by anything above.  This asks the machine its own question from
# its own external address, which is a different source address and therefore
# a different answer.
EXTADDR=$(ifconfig 2>/dev/null | awk '/^[[:space:]]*inet / && $2 != "127.0.0.1" { print $2; exit }')

if [ -z "$EXTADDR" ]; then
	echo "     skip - no non-loopback address on this machine"
else
	echo "     using $EXTADDR"
	check_status "a request from a non-loopback address is refused" 1 \
		"$CLIENT" -a "$EXTADDR" "$DOMAIN" match passwd.byname stnsuser

	# And the same request, once the configuration says it is allowed.
	stop_daemon
	cat >"$WORK/ypstns.conf" <<EOF
domain "$DOMAIN"
interval 3600
allow any
EOF
	chmod 600 "$WORK/ypstns.conf"

	if start_daemon; then
		check_status "and allowed once allow any is given" 0 \
			"$CLIENT" -a "$EXTADDR" "$DOMAIN" match passwd.byname stnsuser
		check_status "the loopback still works too" 0 \
			"$CLIENT" "$DOMAIN" match passwd.byname stnsuser
	else
		fail "the daemon did not come back for the access list check"
	fi
fi

echo
echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
